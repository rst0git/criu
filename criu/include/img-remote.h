#include <sys/epoll.h>
#include <limits.h>
#include <stdbool.h>

#include <stdint.h>
#include "common/list.h"

#ifndef IMAGE_REMOTE_H
#define	IMAGE_REMOTE_H

#define FINISH 0
#define DEFAULT_PROXY_SOCKET "img-proxy.sock"

#include "image.h"

#define DEFAULT_LISTEN 50
#define BUF_SIZE 4096

/* This is the proxy to cache TCP socket FD. */
extern int remote_sk;
/* This the unix socket used to fulfill local requests. */
extern int local_sk;
/* True if we are running the cache/restore, false if proxy/dump. */
extern bool restoring;

void accept_image_connections();
struct rimage *get_rimg_by_name(const char *path, int type);

int setup_UNIX_server_socket(char *path);

/* Called by dump to create a socket connection to the restore side. The socket
 * fd is returned for further writing operations.
 */
int write_remote_image_connection(char *path, int type, uint64_t size);

/* Called by dump/restore when everything is dumped/restored. This function
 * creates a new connection with a special control name. The receiver side uses
 * it to ack that no more files are coming.
 */
int finish_remote_dump();

/* Starts an image proxy daemon (dump side). It receives image files through
 * socket connections and forwards them to the image cache (restore side).
 */
int image_proxy(bool background, char *local_proxy_path);

/* Starts an image cache daemon (restore side). It receives image files through
 * socket connections and caches them until they are requested by the restore
 * process.
 */
int image_cache();

/* Structure that describes the state of a remote operation on remote images. */
struct roperation {
	/* List anchor. */
	struct list_head l;
	/* File descriptor being used. */
	int fd;
	/* File path (identifies) */
	char path[PATH_MAX];
	/* Image fd type, specified in image-desc.h */
	int type;
	/* Remote image being used (may be null if the operation is pending). */
	struct rimage *rimg;
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

/* Reads (discards) 'len' bytes from fd. This is used to emulate the function
 * lseek, which is used to advance the file needle.
 */
int skip_remote_bytes(int fd, unsigned long len);

struct rimage *new_remote_image(char *path);
int event_set(int epoll_fd, int op, int fd, uint32_t events, void *data);
int64_t pb_read_obj(int fd, void **pobj, int type);
int get_img_from_cache(const char *path, int type);

int do_remote_read_one(void **entry, int pbtype, int crtype, ...);
#define remote_read_one(entry, pbtype, crtype, ...)	\
	do_remote_read_one((void **)entry, pbtype, crtype, ##__VA_ARGS__)

int remote_send_entry(void *entry, int pbtype, int crtype, ...);

#endif
