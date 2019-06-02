#include <limits.h>
#include <stdbool.h>

#include <stdint.h>
#include "common/list.h"
#include <pthread.h>
#include <semaphore.h>

#ifndef IMAGE_REMOTE_H
#define	IMAGE_REMOTE_H

#define FINISH 0
#define DEFAULT_CACHE_SOCKET "img-cache.sock"
#define DEFAULT_PROXY_SOCKET "img-proxy.sock"

#define DEFAULT_LISTEN 50
#define BUF_SIZE 4096

struct rbuf {
	char buffer[BUF_SIZE];
	int nbytes; /* How many bytes are in the buffer. */
	struct list_head l;
};

struct rimage {
	/* File name (identifier) */
	char path[PATH_MAX];
	/* List anchor. */
	struct list_head l;
	/* List of buffers that compose the image. */
	struct list_head buf_head;
	/* Number of bytes. */
	uint64_t size;
	/* Note: forward (send) operation only. Buffer to start forwarding. */
	struct rbuf *curr_fwd_buf;
	/* Note: forward (send) operation only. Number of fwd bytes in 'curr_fw_buf'. */
	uint64_t curr_fwd_bytes;
};

/* Structure that describes the state of a remote operation on remote images. */
struct roperation {
	/* List anchor. */
	struct list_head l;
	/* File descriptor being used. */
	int fd;
	/* File name (identifier) */
	char path[PATH_MAX];
	/* Remote image being used (may be null if the operation is pending). */
	struct rimage *rimg;
	/* Flags for the operation. */
	int flags;
	/* If fd should be closed when the operation is done. */
	bool close_fd;
	/* Note: recv operation only. How much bytes should be received. */
	uint64_t size;
	/* Note: recv operation only. Buffer being written. */
	struct rbuf *curr_recv_buf; // TODO - needed? Could be replaced by list.last!
	/* Note: send operation only. Pointer to buffer being sent. */
	struct rbuf *curr_sent_buf;
	/* Note: send operation only. Number of bytes sent in 'curr_send_buf. */
	uint64_t curr_sent_bytes;
};

/* This is the proxy to cache TCP socket FD. */
extern int remote_sk;
/* This the unix socket used to fulfill local requests. */
extern int local_sk;
/* True if we are running the cache/restore, false if proxy/dump. */
extern bool restoring;

void accept_image_connections();
struct rimage *get_rimg_by_name(const char *path);

int setup_UNIX_server_socket(char *path);

/* Called by restore to get the fd correspondent to a particular path.  This call
 * will block until the connection is received.
 */
int read_remote_image_connection(char *path);

/* Called by dump to create a socket connection to the restore side. The socket
 * fd is returned for further writing operations.
 */
int write_remote_image_connection(char *path, int flags);

/* Called by dump/restore when everything is dumped/restored. This function
 * creates a new connection with a special control name. The receiver side uses
 * it to ack that no more files are coming.
 */
int finish_remote_dump();
int finish_remote_restore();

/* Starts an image proxy daemon (dump side). It receives image files through
 * socket connections and forwards them to the image cache (restore side).
 */
int image_proxy(bool background, char *local_proxy_path);

/* Starts an image cache daemon (restore side). It receives image files through
 * socket connections and caches them until they are requested by the restore
 * process.
 */
int image_cache(bool background, char *local_cache_path);

/* Reads (discards) 'len' bytes from fd. This is used to emulate the function
 * lseek, which is used to advance the file needle.
 */
int skip_remote_bytes(int fd, unsigned long len);

#endif
