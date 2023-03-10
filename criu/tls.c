#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/limits.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>

#include "imgset.h"
#include "images/cipher.pb-c.h"
#include "protobuf.h"
#include "cr_options.h"
#include "xmalloc.h"

/* Compatibility with GnuTLS version < 3.5 */
#ifndef GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR
#define GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR GNUTLS_E_CERTIFICATE_ERROR
#endif

#undef LOG_PREFIX
#define LOG_PREFIX "tls: "

#define CRIU_PKI_DIR SYSCONFDIR "/pki"
#define CRIU_CACERT  CRIU_PKI_DIR "/CA/cacert.pem"
#define CRIU_CACRL   CRIU_PKI_DIR "/CA/cacrl.pem"
#define CRIU_CERT    CRIU_PKI_DIR "/criu/cert.pem"
#define CRIU_KEY     CRIU_PKI_DIR "/criu/private/key.pem"

#define SPLICE_BUF_SZ_MAX (PIPE_BUF * 100)

#define tls_perror(msg, ret) pr_err("%s: %s\n", msg, gnutls_strerror(ret))

static gnutls_session_t session;
static gnutls_certificate_credentials_t x509_cred;
static gnutls_pubkey_t pubkey;
static int tls_sk = -1;
static int tls_sk_flags = 0;

/* 256-bits key for ChaCha20-Poly1305 */
static uint8_t token[32];
static const int algo = GNUTLS_CIPHER_CHACHA20_POLY1305;

void tls_terminate_session(bool async)
{
	int ret;

	if (!opts.tls)
		return;

	if (session) {
		do {
			/*
			 * Initiate a connection shutdown but don't
			 * wait for peer to close connection.
			 */
			ret = gnutls_bye(session, async ? GNUTLS_SHUT_WR : GNUTLS_SHUT_RDWR);
		} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
		/* Free the session object */
		gnutls_deinit(session);
	}

	tls_sk = -1;

	/* Free the credentials object */
	if (x509_cred)
		gnutls_certificate_free_credentials(x509_cred);
}

ssize_t tls_send(const void *buf, size_t len, int flags)
{
	ssize_t ret;

	tls_sk_flags = flags;
	ret = gnutls_record_send(session, buf, len);
	tls_sk_flags = 0;

	if (ret < 0) {
		switch (ret) {
		case GNUTLS_E_AGAIN:
			errno = EAGAIN;
			break;
		case GNUTLS_E_INTERRUPTED:
			errno = EINTR;
			break;
		case GNUTLS_E_UNEXPECTED_PACKET_LENGTH:
			errno = ENOMSG;
			break;
		default:
			tls_perror("Failed to send data", ret);
			errno = EIO;
			break;
		}
	}

	return ret;
}

/*
 * Read data from a file descriptor, then encrypt and send it with GnuTLS.
 * This function is used for cases when we would otherwise use splice()
 * to transfer data from PIPE to TCP socket.
 */
int tls_send_data_from_fd(int fd, unsigned long len)
{
	ssize_t copied;
	unsigned long buf_size = min(len, (unsigned long)SPLICE_BUF_SZ_MAX);
	void *buf = xmalloc(buf_size);

	if (!buf)
		return -1;

	while (len > 0) {
		ssize_t ret, sent;

		copied = read(fd, buf, min(len, buf_size));
		if (copied <= 0) {
			pr_perror("Can't read from pipe");
			goto err;
		}

		for (sent = 0; sent < copied; sent += ret) {
			ret = tls_send((buf + sent), (copied - sent), 0);
			if (ret < 0) {
				tls_perror("Failed sending data", ret);
				goto err;
			}
		}
		len -= copied;
	}
err:
	xfree(buf);
	return (len > 0);
}

ssize_t tls_recv(void *buf, size_t len, int flags)
{
	ssize_t ret;

	tls_sk_flags = flags;
	ret = gnutls_record_recv(session, buf, len);
	tls_sk_flags = 0;

	/* Check if there are any data to receive in the gnutls buffers. */
	if (flags == MSG_DONTWAIT && (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)) {
		size_t pending = gnutls_record_check_pending(session);
		if (pending > 0) {
			pr_debug("Receiving pending data (%zu bytes)\n", pending);
			ret = gnutls_record_recv(session, buf, len);
		}
	}

	if (ret < 0) {
		switch (ret) {
		case GNUTLS_E_AGAIN:
			errno = EAGAIN;
			break;
		case GNUTLS_E_INTERRUPTED:
			errno = EINTR;
			break;
		default:
			tls_perror("Failed receiving data", ret);
			errno = EIO;
			break;
		}
		ret = -1;
	}

	return ret;
}

/*
 * Read and decrypt data with GnuTLS, then write it to a file descriptor.
 * This function is used for cases when we would otherwise use splice()
 * to transfer data from a TCP socket to a PIPE.
 */
int tls_recv_data_to_fd(int fd, unsigned long len)
{
	gnutls_packet_t packet;

	while (len > 0) {
		ssize_t ret, w;
		gnutls_datum_t pdata;

		ret = gnutls_record_recv_packet(session, &packet);
		if (ret == 0) {
			pr_info("Connection closed by peer\n");
			break;
		} else if (ret < 0) {
			tls_perror("Received corrupted data", ret);
			break;
		}

		gnutls_packet_get(packet, &pdata, NULL);
		for (w = 0; w < pdata.size; w += ret) {
			ret = write(fd, (pdata.data + w), (pdata.size - w));
			if (ret < 0) {
				pr_perror("Failed writing to fd");
				goto err;
			}
		}
		len -= pdata.size;
	}
err:
	gnutls_packet_deinit(packet);
	return (len > 0);
}

static inline void tls_handshake_verification_status_print(int ret, unsigned status)
{
	gnutls_datum_t out;
	int type = gnutls_certificate_type_get(session);

	if (!gnutls_certificate_verification_status_print(status, type, &out, 0))
		pr_err("%s\n", out.data);

	gnutls_free(out.data);
}

static int tls_x509_verify_peer_cert(void)
{
	int ret;
	unsigned status;
	const char *hostname = NULL;

	if (!opts.tls_no_cn_verify)
		hostname = opts.addr;

	ret = gnutls_certificate_verify_peers3(session, hostname, &status);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Unable to verify TLS peer", ret);
		return -1;
	}

	if (status != 0) {
		pr_err("Invalid certificate\n");
		tls_handshake_verification_status_print(GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR, status);
		return -1;
	}

	return 0;
}

static int tls_handshake(void)
{
	int ret = -1;
	while (ret != GNUTLS_E_SUCCESS) {
		/* Establish TLS session */
		ret = gnutls_handshake(session);
		if (gnutls_error_is_fatal(ret)) {
			tls_perror("TLS handshake failed", ret);
			return -1;
		}
	}
	pr_info("TLS handshake completed\n");
	return 0;
}

static int tls_x509_setup_creds(void)
{
	int ret;
	char *cacert = CRIU_CACERT;
	char *cacrl = CRIU_CACRL;
	char *cert = CRIU_CERT;
	char *key = CRIU_KEY;
	gnutls_x509_crt_fmt_t pem = GNUTLS_X509_FMT_PEM;

	if (opts.tls_cacert)
		cacert = opts.tls_cacert;
	if (opts.tls_cacrl)
		cacrl = opts.tls_cacrl;
	if (opts.tls_cert)
		cert = opts.tls_cert;
	if (opts.tls_key)
		key = opts.tls_key;

	/* Load the trusted CA certificates */
	ret = gnutls_certificate_allocate_credentials(&x509_cred);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Failed to allocate x509 credentials", ret);
		return -1;
	}

	if (!opts.tls_cacert) {
		ret = gnutls_certificate_set_x509_system_trust(x509_cred);
		if (ret < 0) {
			tls_perror("Failed to load default trusted CAs", ret);
			return -1;
		}
	}

	ret = gnutls_certificate_set_x509_trust_file(x509_cred, cacert, pem);
	if (ret == 0) {
		pr_info("No trusted CA certificates added (%s)\n", cacert);
		if (opts.tls_cacert)
			return -1;
	}

	if (!access(cacrl, R_OK)) {
		ret = gnutls_certificate_set_x509_crl_file(x509_cred, cacrl, pem);
		if (ret < 0) {
			tls_perror("Can't set certificate revocation list", ret);
			return -1;
		}
	} else if (opts.tls_cacrl) {
		pr_perror("Can't read certificate revocation list %s", cacrl);
		return -1;
	}

	ret = gnutls_certificate_set_x509_key_file(x509_cred, cert, key, pem);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Failed to set certificate/private key pair", ret);
		return -1;
	}

	return 0;
}

/**
 * A function used by gnutls to send data. It returns a positive
 * number indicating the bytes sent, and -1 on error.
 */
static ssize_t _tls_push_cb(void *p, const void *data, size_t sz)
{
	int fd = *(int *)(p);
	ssize_t ret = send(fd, data, sz, tls_sk_flags);
	if (ret < 0 && errno != EAGAIN) {
		int _errno = errno;
		pr_perror("Push callback send failed");
		errno = _errno;
	}
	return ret;
}

/**
 * A callback function used by gnutls to receive data.
 * It returns 0 on connection termination, a positive number
 * indicating the number of bytes received, and -1 on error.
 */
static ssize_t _tls_pull_cb(void *p, void *data, size_t sz)
{
	int fd = *(int *)(p);
	ssize_t ret = recv(fd, data, sz, tls_sk_flags);
	if (ret < 0 && errno != EAGAIN) {
		int _errno = errno;
		pr_perror("Pull callback recv failed");
		errno = _errno;
	}
	return ret;
}

static int tls_x509_setup_session(unsigned int flags)
{
	int ret;

	/* Create the session object */
	ret = gnutls_init(&session, flags);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Failed to initialize session", ret);
		return -1;
	}

	/* Install the trusted certificates */
	ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Failed to set session credentials", ret);
		return -1;
	}

	/* Configure the cipher preferences */
	ret = gnutls_set_default_priority(session);
	if (ret != GNUTLS_E_SUCCESS) {
		tls_perror("Failed to set priority", ret);
		return -1;
	}

	/* Associate the socket with the session object */
	gnutls_transport_set_ptr(session, &tls_sk);

	/* Set a push function for gnutls to use to send data */
	gnutls_transport_set_push_function(session, _tls_push_cb);
	/* set a pull function for gnutls to use to receive data */
	gnutls_transport_set_pull_function(session, _tls_pull_cb);

	if (flags == GNUTLS_SERVER) {
		/* Require client certificate */
		gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUIRE);
		/* Do not advertise trusted CAs to the client */
		gnutls_certificate_send_x509_rdn_sequence(session, 1);
	}

	return 0;
}

int tls_x509_init(int sockfd, bool is_server)
{
	if (!opts.tls)
		return 0;

	tls_sk = sockfd;
	if (tls_x509_setup_creds())
		goto err;
	if (tls_x509_setup_session(is_server ? GNUTLS_SERVER : GNUTLS_CLIENT))
		goto err;
	if (tls_handshake())
		goto err;
	if (tls_x509_verify_peer_cert())
		goto err;

	return 0;
err:
	tls_terminate_session(true);
	return -1;
}

static inline int _tls_generate_token(void)
{
	return gnutls_rnd(GNUTLS_RND_KEY, &token, sizeof(token));
}

/**
 * tls_initialize_cipher initializes GnuTLS, loads a public key,
 * and initializes a cipher context that is used to encrypt the
 * content of images during dump and pre-dump.
 */
int tls_initialize_cipher(void)
{
	int ret;
	char *cert_file_path = CRIU_CERT;
	gnutls_x509_crt_t crt;
	gnutls_datum_t cert_data;

	if (!opts.tls)
		return 0;

	if (opts.tls_cert)
		cert_file_path = opts.tls_cert;

	pr_debug("Loading public key from %s\n", cert_file_path);
	ret = gnutls_load_file(cert_file_path, &cert_data);
	if (ret < 0) {
		tls_perror("Failed to load certificate file", ret);
		return -1;
	}

	ret = gnutls_pubkey_init(&pubkey);
	if (ret < 0) {
		tls_perror("Failed to initialize public key", ret);
		return -1;
	}

	ret = gnutls_x509_crt_init(&crt);
	if (ret < 0) {
		tls_perror("Failed to initialize X.509 certificate structure", ret);
		return -1;
	}

	ret = gnutls_x509_crt_import(crt, &cert_data, GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
		tls_perror("Failed to import certificate", ret);
		return -1;
	}

	ret = gnutls_pubkey_import_x509(pubkey, crt, 0);
	if (ret < 0) {
		tls_perror("Failed to load public key", ret);
		return -1;
	}

	ret = _tls_generate_token();
	if (ret < 0) {
		tls_perror("Failed to generate token", ret);
		return -1;
	}

	gnutls_free(cert_data.data);
	gnutls_x509_crt_deinit(crt);

	return 0;
}

/**
 * tls_initialize_cipher_from_image loads a private key and
 * decrypts the token from the cipher.img that is then used
 * to decrypt all other images.
 */
int tls_initialize_cipher_from_image(void)
{
	int ret;
	char *privkey_file_path = CRIU_KEY;
	struct cr_img *img;
	CipherEntry *ce;

	gnutls_datum_t key_data;
	gnutls_privkey_t privkey;
	gnutls_x509_privkey_t x509_key;
	gnutls_datum_t ciphertext;
	gnutls_datum_t decrypted_token;

	if (!opts.tls)
		return 0;

	if (opts.tls_key)
		privkey_file_path = opts.tls_key;

	// FIXME: gnutls_load_file() is not designed for reading sensitive
	// materials, such as private keys. When the reading fails in the middle,
	// the partially loaded content might remain on memory.
	// https://www.gnutls.org/manual/html_node/Core-TLS-API.html#index-gnutls_005fload_005ffile

	// Could we use gnutls_certificate_set_rawpk_key_file() instead?
	// https://www.gnutls.org/manual/html_node/Core-TLS-API.html#index-gnutls_005fload_005ffile

	pr_debug("Loading private key from %s\n", privkey_file_path);
	ret = gnutls_load_file(privkey_file_path, &key_data);
	if (ret < 0) {
		tls_perror("Failed to load private key file", ret);
		return -1;
	}

	ret = gnutls_x509_privkey_init(&x509_key);
	if (ret < 0) {
		tls_perror("Failed to initialize X.509 private key", ret);
		return -1;
	}

	ret = gnutls_x509_privkey_import(x509_key, &key_data, GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
		tls_perror("Failed to load X.509 private key", ret);
		return -1;
	}

	ret = gnutls_privkey_init(&privkey);
	if (ret < 0) {
		tls_perror("Failed to initialize private key", ret);
		return -1;
	}

	ret = gnutls_privkey_import_x509(privkey, x509_key, 0);
	if (ret < 0) {
		tls_perror("Failed to import private key", ret);
		return -1;
	}

	img = open_image(CR_FD_CIPHER, O_RSTR);
	if (!img)
		return -1;

	ret = pb_read_one(img, &ce, PB_CIPHER);
	if (ret < 0) {
		pr_err("Failed to read cipher entry\n");
		goto out_close;
	}

	ciphertext.data = ce->token.data;
	ciphertext.size = ce->token.len;

	ret = gnutls_privkey_decrypt_data(privkey, 0, &ciphertext, &decrypted_token);
	if (ret < 0) {
		tls_perror("Failed to decrypt token data", ret);
		goto out_close;
	}

	if (decrypted_token.size != sizeof(token)) {
		pr_err("Invalid token size (%d != %lu)\n", decrypted_token.size, sizeof(token));
		goto out_close;
	}

	if (memcpy(token, decrypted_token.data, sizeof(token)) != token) {
		pr_perror("Failed to copy token data");
		goto out_close;
	}

	ret = 0;
out_close:
	gnutls_free(key_data.data);
	close_image(img);
	return ret;
}

/**
 * tls_encrypt_data performs in-place encryption of data with ChaCha20-Poly1305
 * AEAD cipher. A 16-bytes tag and 12-bytes nonce are generated and written to
 * tag_data and nonce_data. The caller must ensure that there is enough space
 * allocated for the tag and nonce. Different tag and nonce are used for each
 * invocation, and they must be provided to decrypt the data. The tag's purpose
 * is to verify the integrity of the data, while the nonce is used to prevent
 * replay attacks.
 */
int tls_encrypt_data(void *data, size_t data_size, uint8_t *tag_data, uint8_t *nonce_data)
{
	int ret;
	giovec_t iov[1];
	gnutls_datum_t key;
	static gnutls_aead_cipher_hd_t handle = NULL;
	size_t tag_size = gnutls_cipher_get_tag_size(algo);
	size_t nonce_len = gnutls_cipher_get_iv_size(algo);

	if (!opts.tls)
		return -1;

	if (handle == NULL) {
		key.data = token;
		key.size = gnutls_cipher_get_key_size(algo);

		ret = gnutls_aead_cipher_init(&handle, algo, &key);
		if (ret < 0) {
			tls_perror("Failed to initialize cipher", ret);
			return -1;
		}
	}

	/* A different 96-bit nonce must be used for each invocation.
	 * The nonce should never be reused with the same key.
	 * (RFC 8439, Section 2.8 "AEAD Construction")
	 */
	ret = gnutls_rnd(GNUTLS_RND_NONCE, nonce_data, nonce_len);
	if (ret < 0) {
		tls_perror("Failed to generate random nonce", ret);
		return -1;
	}

	iov[0].iov_base = data;
	iov[0].iov_len = data_size;

	ret = gnutls_aead_cipher_encryptv2(handle, nonce_data, nonce_len, NULL, 0, iov, 1, tag_data, &tag_size);
	if (ret < 0) {
		tls_perror("Failed to encrypt data", ret);
		return -1;
	}

	return 0;
}

/**
 * write_img_cipher encrypts the token with RSA public key and writes
 * it to cipher.img.
 */
int write_img_cipher(void)
{
	int ret;
	struct cr_img *img;
	CipherEntry ce = CIPHER_ENTRY__INIT;
	unsigned max_block_size;
	unsigned key_len = 0;
	gnutls_datum_t plaintext = { .data = token, .size = sizeof(token) };
	gnutls_datum_t ciphertext;

	if (!opts.tls) {
		return 0;
	}

	if (!pubkey) {
		pr_err("Public key is not initialized\n");
		return -1;
	}

	ret = gnutls_pubkey_get_pk_algorithm(pubkey, &key_len);
	if (ret < 0) {
		pr_err("Failed to read public key length\n");
		return -1;
	}
	if (ret != GNUTLS_PK_RSA) {
		pr_err("Public key must be RSA\n");
		return -1;
	}

	/* The data must be small enough to use plain RSA
	 * https://github.com/gnutls/nettle/blob/fe7ae87d/pkcs1-encrypt.c#L66
	 */
	max_block_size = key_len / 8 - 11;
	if (plaintext.size > max_block_size) {
		pr_err("Data size must be less than %u bytes\n", max_block_size);
		return -1;
	}

	ret = gnutls_pubkey_encrypt_data(pubkey, 0, &plaintext, &ciphertext);
	if (ret < 0) {
		tls_perror("Failed to encrypt data", ret);
		return -1;
	}

	pr_debug("Writing cipher image\n");
	img = open_image(CR_FD_CIPHER, O_DUMP);
	if (!img)
		return -1;

	ce.token.len = ciphertext.size;
	ce.token.data = ciphertext.data;
	ret = pb_write_one(img, &ce, PB_CIPHER);
	if (ret < 0) {
		pr_err("Failed to write ciphertext size to image\n");
		goto err;
	}

err:
	gnutls_free(ciphertext.data);
	close_image(img);
	return ret;
}

/**
 * tls_decrypt_data performs in-place decryption of given data
 * with corresponding tag and nonce. On success, it returns zero
 * or a negative error code on error.
 */
int tls_decrypt_data(void *data, size_t data_size, uint8_t *tag_data, uint8_t *nonce_data)
{
	int ret;
	giovec_t iov[1];
	gnutls_datum_t key;
	gnutls_aead_cipher_hd_t handle = NULL;
	size_t tag_size = gnutls_cipher_get_tag_size(algo);
	size_t nonce_len = gnutls_cipher_get_iv_size(algo);

	key.data = token;
	key.size = gnutls_cipher_get_key_size(algo);

	ret = gnutls_aead_cipher_init(&handle, algo, &key);
	if (ret < 0) {
		tls_perror("Failed to initialize cipher", ret);
		return -1;
	}

	iov[0].iov_base = data;
	iov[0].iov_len = data_size;

	ret = gnutls_aead_cipher_decryptv2(handle, nonce_data, nonce_len, NULL, 0, iov, 1, tag_data, tag_size);
	if (ret < 0) {
		tls_perror("Failed to decrypt data", ret);
		return -1;
	}

	gnutls_aead_cipher_deinit(handle);

	return ret;
}

/**
 * tls_encrypt_file_data reads data from fd_in, encrypts the data, and writes
 * the encrypted data to fd_out.
 */
int tls_encrypt_file_data(int fd_in, int fd_out, size_t data_size)
{
	void *buf;
	uint8_t tag_data[16];	// 128-bits tag for ChaCha20-Poly1305
	uint8_t nonce_data[12]; // 96-bits nonce for ChaCha20-Poly1305
	size_t chunk_size = 4096;
	ssize_t num_chunks = 0;
	ssize_t written;
	ssize_t bytes;
	ssize_t total_written = 0;
	ssize_t total_size;

	if (data_size < chunk_size)
		chunk_size = data_size;

	buf = xmalloc(chunk_size);
	if (!buf)
		return -1;

	/* FIXME: Could we use vmsplice instead of read/write here? */
	while (1) {
		bytes = read(fd_in, buf, chunk_size);
		if (bytes < 0) {
			pr_perror("Can't read ghost file data");
			goto err;
		}
		if (bytes == 0) {
			break;
		}

		/* Encrypt buffer data using ChaCha20-Poly1305 */
		if (tls_encrypt_data(buf, bytes, tag_data, nonce_data) < 0) {
			pr_err("Failed to encrypt buffer data\n");
			return -1;
		}

		/* The order of tag and nonce is important */
		if (write(fd_out, tag_data, sizeof(tag_data)) != sizeof(tag_data)) {
			pr_err("Failed to write tag data to image file\n");
			goto err;
		}

		if (write(fd_out, nonce_data, sizeof(nonce_data)) != sizeof(nonce_data)) {
			pr_err("Failed to write nonce data to image file\n");
			goto err;
		}

		written = write(fd_out, buf, bytes);
		if (written != bytes) {
			if (written < 0)
				pr_perror("Failed to write ghost file data");
			else
				pr_err("Failed to write all data to image file (%zd != %zd)\n", written, bytes);
			goto err;
		}

		total_written += written + sizeof(tag_data) + sizeof(nonce_data);
		num_chunks++;
	}

err:
	xfree(buf);
	total_size = data_size + num_chunks * (sizeof(tag_data) + sizeof(nonce_data));
	if (data_size && total_written != total_size) {
		pr_err("Failed to write all data to image file (%ld != %ld)\n", total_written, total_size);
		return -1;
	}

	return 0;
}

/**
 * tls_decrypt_file_data reads encrypted data from fd_in, decrypts the data,
 * and writes the decrypted data to fd_out.
 */
int tls_decrypt_file_data(int fd_in, int fd_out, size_t data_size)
{
	void *buf;
	uint8_t tag_data[16];	// 128-bits tag for ChaCha20-Poly1305
	uint8_t nonce_data[12]; // 96-bits nonce for ChaCha20-Poly1305
	size_t chunk_size = 4096;
	ssize_t total_written = 0;
	ssize_t bytes, written;

	if (data_size > 0 && data_size < chunk_size)
		chunk_size = data_size;

	buf = xmalloc(chunk_size);
	if (!buf)
		return -1;

	/* FIXME: Could we use vmsplice instead of read/write here? */
	while (1) {
		/* Read tag data */
		if (read(fd_in, tag_data, sizeof(tag_data)) != sizeof(tag_data)) {
			pr_err("Failed to read tag data to image file\n");
			goto err;
		}

		/* Read nonce data */
		if (read(fd_in, nonce_data, sizeof(nonce_data)) != sizeof(nonce_data)) {
			pr_err("Failed to read nonce data to image file\n");
			goto err;
		}

		/* Read ciphertext data */
		bytes = read(fd_in, buf, chunk_size);
		if (bytes == 0) {
			break;
		}
		if (bytes < 0) {
			pr_perror("Failed to read ghost file data");
			goto err;
		}

		/* Decrypt buffer data using ChaCha20-Poly1305 */
		if (tls_decrypt_data(buf, bytes, tag_data, nonce_data) < 0) {
			pr_err("Failed to decrypt buffer data\n");
			return -1;
		}

		/* Write plaintext data */
		written = write(fd_out, buf, bytes);
		if (written != bytes) {
			if (written < 0)
				pr_perror("Failed to write ghost file data");
			else
				pr_err("Failed to write all data to file (%zd != %zd)\n", written, bytes);
			goto err;
		}

		total_written += written;
	}

err:
	xfree(buf);
	if (data_size && total_written != data_size) {
		pr_err("Failed to write all data to file (%ld != %ld)\n", total_written, data_size);
		return -1;
	}

	return 0;
}
