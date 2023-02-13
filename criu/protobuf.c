#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <google/protobuf-c/protobuf-c.h>

#include "image.h"
#include "servicefd.h"
#include "common/compiler.h"
#include "log.h"
#include "rst-malloc.h"
#include "string.h"
#include "sockets.h"
#include "cr_options.h"
#include "bfd.h"
#include "protobuf.h"
#include "util.h"
#include "tls.h"

#define image_name(img, buf) __image_name(img, buf, sizeof(buf))
static char *__image_name(struct cr_img *img, char *image_path, size_t image_path_size)
{
	int fd = img->_x.fd;

	if (lazy_image(img))
		return img->path;
	else if (empty_image(img))
		return "(empty-image)";
	else if (fd >= 0 && read_fd_link(fd, image_path, image_path_size) > 0)
		return image_path;

	return NULL;
}

/*
 * Reads PB record (header + packed object) from file @fd and unpack
 * it with @unpack procedure to the pointer @pobj
 *
 *  1 on success
 * -1 on error (or EOF met and @eof set to false)
 *  0 on EOF and @eof set to true
 *
 * Don't forget to free memory granted to unpacked object in calling code if needed
 */

int do_pb_read_one(struct cr_img *img, void **pobj, int type, bool eof)
{
	char img_name_buf[PATH_MAX];
	u8 local[PB_PKOBJ_LOCAL_SIZE];
	void *buf = (void *)&local;
	uint8_t tag_data[16];	// 128-bits tag for ChaCha20-Poly1305
	uint8_t nonce_data[12]; // 96-bits nonce for ChaCha20-Poly1305
	u32 size;
	int ret;

	if (!cr_pb_descs[type].pb_desc) {
		pr_err("Wrong object requested %d on %s\n", type, image_name(img, img_name_buf));
		return -1;
	}

	*pobj = NULL;

	if (unlikely(empty_image(img)))
		ret = 0;
	else
		ret = bread(&img->_x, &size, sizeof(size));
	if (ret == 0) {
		if (eof) {
			return 0;
		} else {
			pr_err("Unexpected EOF on %s\n", image_name(img, img_name_buf));
			return -1;
		}
	} else if (ret < sizeof(size)) {
		pr_perror("Read %d bytes while %d expected on %s", ret, (int)sizeof(size),
			  image_name(img, img_name_buf));
		return -1;
	}

	if (size > sizeof(local)) {
		ret = -1;
		buf = xmalloc(size);
		if (!buf)
			goto err;
	}

	ret = bread(&img->_x, buf, size);
	if (ret < 0) {
		pr_perror("Can't read %d bytes from file %s", size, image_name(img, img_name_buf));
		goto err;
	} else if (ret != size) {
		pr_perror("Read %d bytes while %d expected from %s", ret, size, image_name(img, img_name_buf));
		ret = -1;
		goto err;
	}

	if (opts.tls && type != PB_CIPHER) {
		/* Read tag data */
		ret = bread(&img->_x, tag_data, sizeof(tag_data));
		if (ret < 0) {
			pr_perror("Can't read %lu bytes of tag data from file %s", sizeof(tag_data),
				  image_name(img, img_name_buf));
			goto err;
		} else if (ret != sizeof(tag_data)) {
			pr_perror("Read %d bytes of tag data while %lu expected from %s", ret, sizeof(tag_data),
				  image_name(img, img_name_buf));
			ret = -1;
			goto err;
		}

		/* Read nonce data */
		ret = bread(&img->_x, nonce_data, sizeof(nonce_data));
		if (ret < 0) {
			pr_perror("Can't read %lu bytes of nonce data from file %s", sizeof(nonce_data),
				  image_name(img, img_name_buf));
			goto err;
		} else if (ret != sizeof(nonce_data)) {
			pr_perror("Read %d bytes of nonce data while %lu expected from %s", ret, sizeof(nonce_data),
				image_name(img, img_name_buf));
			ret = -1;
			goto err;
		}

		/* Decrypt the content of buf */
		ret = tls_decrypt_data(buf, size, tag_data, nonce_data);
		if (ret < 0) {
			pr_err("Failed to decrypt object\n");
			goto err;
		}
	}

	*pobj = cr_pb_descs[type].unpack(NULL, size, buf);
	if (!*pobj) {
		ret = -1;
		pr_err("Failed unpacking object %p from %s\n", pobj, image_name(img, img_name_buf));
		goto err;
	}

	ret = 1;
err:
	if (buf != (void *)&local)
		xfree(buf);

	return ret;
}

/*
 * Writes PB record (header + packed object pointed by @obj)
 * to file @fd, using @getpksize to get packed size and @pack
 * to implement packing
 *
 *  0 on success
 * -1 on error
 */
int pb_write_one(struct cr_img *img, void *obj, int type)
{
	u8 local[PB_PKOBJ_LOCAL_SIZE];
	void *buf = (void *)&local;
	u32 size, packed;
	int ret = -1;
	int total_size = 0;
	struct iovec iov[4];
	int iov_cnt = 2;	// size + packed object
	uint8_t nonce_data[12]; // 96-bits nonce for ChaCha20-Poly1305
	uint8_t tag_data[16];	// 128-bits tag for ChaCha20-Poly1305

	if (!cr_pb_descs[type].pb_desc) {
		pr_err("Wrong object requested %d\n", type);
		return -1;
	}

	if (lazy_image(img) && open_image_lazy(img))
		return -1;

	size = cr_pb_descs[type].getpksize(obj);
	if (size > (u32)sizeof(local)) {
		buf = xmalloc(size);
		if (!buf)
			goto err;
	}

	packed = cr_pb_descs[type].pack(obj, buf);
	if (packed != size) {
		pr_err("Failed packing PB object %p\n", obj);
		goto err;
	}

	/* Encrypt packed object using ChaCha20-Poly1305 */
	if (opts.tls && size > 0 && type != PB_CIPHER) {
		ret = tls_encrypt_data(buf, size, tag_data, nonce_data);
		if (ret < 0) {
			pr_err("Failed to encrypt object\n");
			goto err;
		}

		iov[2].iov_base = tag_data;
		iov[2].iov_len = sizeof(tag_data);
		iov[3].iov_base = nonce_data;
		iov[3].iov_len = sizeof(nonce_data);

		iov_cnt = 4;
		total_size = iov[2].iov_len + iov[3].iov_len;
	}

	iov[0].iov_base = &size;
	iov[0].iov_len = sizeof(size);
	iov[1].iov_base = buf;
	iov[1].iov_len = size;

	total_size += iov[0].iov_len + iov[1].iov_len;

	ret = bwritev(&img->_x, iov, iov_cnt);
	if (ret != total_size) {
		pr_perror("Can't write %d bytes", (int)(size + sizeof(size)));
		goto err;
	}

	ret = 0;
err:
	if (buf != (void *)&local)
		xfree(buf);
	return ret;
}

int collect_entry(ProtobufCMessage *msg, struct collect_image_info *cinfo)
{
	void *obj;
	void *(*o_alloc)(size_t size) = malloc;
	void (*o_free)(void *ptr) = free;

	if (cinfo->flags & COLLECT_SHARED) {
		o_alloc = shmalloc;
		o_free = shfree_last;
	}

	if (cinfo->priv_size) {
		obj = o_alloc(cinfo->priv_size);
		if (!obj)
			return -1;
	} else
		obj = NULL;

	cinfo->flags |= COLLECT_HAPPENED;
	if (cinfo->collect(obj, msg, NULL) < 0) {
		o_free(obj);
		cr_pb_descs[cinfo->pb_type].free(msg, NULL);
		return -1;
	}

	if (!cinfo->priv_size && !(cinfo->flags & COLLECT_NOFREE))
		cr_pb_descs[cinfo->pb_type].free(msg, NULL);

	return 0;
}

int collect_image(struct collect_image_info *cinfo)
{
	int ret;
	struct cr_img *img;
	void *(*o_alloc)(size_t size) = malloc;
	void (*o_free)(void *ptr) = free;

	pr_info("Collecting %d/%d (flags %x)\n", cinfo->fd_type, cinfo->pb_type, cinfo->flags);

	img = open_image(cinfo->fd_type, O_RSTR);
	if (!img)
		return -1;

	if (cinfo->flags & COLLECT_SHARED) {
		o_alloc = shmalloc;
		o_free = shfree_last;
	}

	while (1) {
		void *obj;
		ProtobufCMessage *msg;

		if (cinfo->priv_size) {
			ret = -1;
			obj = o_alloc(cinfo->priv_size);
			if (!obj)
				break;
		} else
			obj = NULL;

		ret = pb_read_one_eof(img, &msg, cinfo->pb_type);
		if (ret <= 0) {
			o_free(obj);
			break;
		}

		cinfo->flags |= COLLECT_HAPPENED;
		ret = cinfo->collect(obj, msg, img);
		if (ret < 0) {
			o_free(obj);
			cr_pb_descs[cinfo->pb_type].free(msg, NULL);
			break;
		}

		if (!cinfo->priv_size && !(cinfo->flags & COLLECT_NOFREE))
			cr_pb_descs[cinfo->pb_type].free(msg, NULL);
	}

	close_image(img);
	pr_debug(" `- ... done\n");
	return ret;
}
