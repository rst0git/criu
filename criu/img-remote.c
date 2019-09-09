#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "cr_options.h"
#include "img-remote.h"
#include "image.h"
#include "images/remote-image.pb-c.h"
#include "protobuf.h"
#include "servicefd.h"
#include "xmalloc.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "img-remote: "

#define EPOLL_MAX_EVENTS 50

#define BUF_SIZE 4096
struct rbuf {
	char buffer[BUF_SIZE];
	int nbytes;
	struct list_head l;
};

struct rimage {
	int fd;
	/* File path (identifer) */
	char path[PATH_MAX];
	/* Image fd type (identifer) */
	int type;
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

// List of local operations currently in-progress.
static LIST_HEAD(rop_inprogress);

// List of local operations pending (reads on the restore side for images that
// still haven't arrived).
static LIST_HEAD(rop_pending);

// List of images waiting to be forwarded. The head of the list is currently
// being forwarded.
static LIST_HEAD(rop_forwarding);

// True if the proxy to cache socket is being used (receiving or sending).
static bool forwarding = false;

// True if the local dump or restore is finished.
static bool finished_local = false;

// Proxy to cache socket fd; Local dump or restore servicing fd.
int remote_sk;
int local_sk;

// Epoll fd and event array.
static int epoll_fd;
static struct epoll_event *events;

static int64_t recv_image_async(struct roperation *op);
static int64_t send_image_async(struct roperation *op);

static struct list_head rimg_set[CR_FD_MAX];

struct rimage *get_rimg_by_name(const char *path, int type)
{
	struct rimage *rimg = NULL;

	if (rimg_set[type].next)
		list_for_each_entry(rimg, &(rimg_set[type]), l) {
			if (!strncmp(rimg->path, path, PATH_MAX)) {
				return rimg;
			}
		}
	return NULL;
}

int event_set(int epoll_fd, int op, int fd, uint32_t events, void *data)
{
	int ret;
	struct epoll_event event;
	event.events = events;
	event.data.ptr = data;

	ret = epoll_ctl(epoll_fd, op, fd, &event);
	if (ret)
		pr_perror("[fd=%d] Unable to set event", fd);
	return ret;
}

int setup_UNIX_server_socket(char *path)
{
	struct sockaddr_un addr;
	int sockfd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);

	if (sockfd < 0) {
		pr_perror("Unable to open image socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);

	unlink(path);

	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		pr_perror("Unable to bind image socket");
		goto err;
	}

	if (listen(sockfd, 50) == -1) {
		pr_perror("Unable to listen image socket");
		goto err;
	}

	return sockfd;
err:
	close(sockfd);
	return -1;
}

static int setup_UNIX_client_socket(char *path)
{
	struct sockaddr_un addr;
	int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (sockfd < 0) {
		pr_perror("Unable to open local image socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);

	if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		pr_perror("Unable to connect to local socket: %s", path);
		close(sockfd);
		return -1;
	}

	return sockfd;
}

static inline int64_t pb_write_obj(int fd, void *obj, int type)
{
	struct cr_img img;

	img._x.fd = fd;
	bfd_setraw(&img._x);
	return pb_write_one(&img, obj, type);
}

int64_t pb_read_obj(int fd, void **pobj, int type)
{
	struct cr_img img;

	img._x.fd = fd;
	bfd_setraw(&img._x);
	return do_pb_read_one(&img, pobj, type, true);
}

static inline int64_t write_header(int fd, char *path, int type, uint64_t size)
{
	RemoteImageEntry ri = REMOTE_IMAGE_ENTRY__INIT;

	ri.name = path;
	ri.type = type;
	if (size > 0) {
		ri.has_size = true;
		ri.size = size;
	}

	pr_debug("send header: %s\n", (path == FINISH) ? "(EOF)" : path);
	return pb_write_obj(fd, &ri, PB_REMOTE_IMAGE);
}

static struct roperation *new_remote_operation(char *path, int type, int cli_fd)
{
	struct roperation *rop = xzalloc(sizeof(struct roperation));

	if (rop == NULL)
		return NULL;

	strncpy(rop->path, path, PATH_MAX -1 );
	rop->path[PATH_MAX - 1] = '\0';
	rop->type = type;
	rop->fd = cli_fd;

	return rop;
}

static inline void rop_set_rimg(struct roperation *rop, struct rimage *rimg)
{
	rop->rimg = rimg;
	rop->size = rimg->size;
	rop->rimg->type = rop->type;

	rop->curr_recv_buf = list_entry(rimg->buf_head.next, struct rbuf, l);
	rop->curr_sent_buf = list_entry(rimg->buf_head.next, struct rbuf, l);
	rop->curr_sent_bytes = 0;
}


static inline void finish_local()
{
	int ret;
	finished_local = true;
	ret = event_set(epoll_fd, EPOLL_CTL_DEL, local_sk, 0, 0);
	if (ret) {
		pr_perror("Failed to del local fd from epoll");
	}
}

static void forward_remote_image(struct roperation *rop)
{
	int64_t ret = 0;

	// Set blocking during the setup.
	fd_set_nonblocking(rop->fd, false);

	pr_info("Forward %s (%" PRIu64 " bytes)\n", rop->path, rop->size);
	ret = write_header(rop->fd, rop->path, rop->type, rop->size);

	if (ret < 0) {
		pr_perror("Error writing header for %s", rop->path);
		return;
	}

	// Go back to non-blocking
	fd_set_nonblocking(rop->fd, true);

	forwarding = true;
	event_set(epoll_fd, EPOLL_CTL_ADD, rop->fd, EPOLLOUT, rop);
}

static void check_pending()
{
	struct roperation *rop = NULL;
	struct rimage *rimg = NULL;

	list_for_each_entry(rop, &rop_pending, l) {
		rimg = get_rimg_by_name(rop->path, rop->type);
		if (rimg != NULL) {
			rop_set_rimg(rop, rimg);
			forward_remote_image(rop);
			return;
		}
	}
}

struct rimage *new_remote_image(char *path)
{
	struct rimage *rimg = xzalloc(sizeof(struct rimage));
	struct rbuf *buf = xzalloc(sizeof(struct rbuf));

	if (rimg == NULL || buf == NULL)
		goto err;

	strncpy(rimg->path, path, PATH_MAX -1 );
	rimg->path[PATH_MAX - 1] = '\0';
	INIT_LIST_HEAD(&(rimg->buf_head));
	list_add_tail(&(buf->l), &(rimg->buf_head));
	rimg->curr_fwd_buf = buf;

	return rimg;
err:
	xfree(rimg);
	xfree(buf);
	return NULL;
}

static struct roperation *handle_accept_write(int cli_fd, char *path,
	int type, uint64_t size)
{
	struct roperation *rop = NULL;
	struct rimage *rimg = get_rimg_by_name(path, type);

	if (rimg == NULL) {
		rimg = new_remote_image(path);
		if (rimg == NULL) {
			pr_perror("Error preparing remote image");
			goto err;
		}
	} else {
		list_del(&(rimg->l));
 	}
	rop = new_remote_operation(path, type, cli_fd);
	if (rop == NULL) {
		pr_perror("Error preparing remote operation");
		goto err;
	}

	rop_set_rimg(rop, rimg);
	rop->size = size;
	return rop;
err:
	xfree(rimg);
	xfree(rop);
	return NULL;
}

static inline struct roperation *handle_accept_proxy_write(int cli_fd,
	char *path, int type)
{
	return handle_accept_write(cli_fd, path, type, 0);
}

static inline void finish_proxy_read(struct roperation *rop)
{
	// If finished forwarding image
	if (rop->fd == remote_sk) {
		// Update fwd buffer and byte count on rimg.
		rop->rimg->curr_fwd_buf = rop->curr_sent_buf;
		rop->rimg->curr_fwd_bytes = rop->curr_sent_bytes;

		forwarding = false;

		// If there are images waiting to be forwarded, forward the next.
		if (!list_empty(&rop_forwarding)) {
			forward_remote_image(list_entry(rop_forwarding.next,
				struct roperation, l));
		}
	}
}

void handle_local_accept(int fd)
{
	int cli_fd;
	struct sockaddr_in cli_addr;
	socklen_t clilen = sizeof(cli_addr);
	struct roperation *rop = NULL;
	RemoteImageEntry *ri;

	cli_fd = accept(fd, (struct sockaddr *) &cli_addr, &clilen);
	if (cli_fd < 0) {
		pr_perror("Unable to accept local image connection");
		return;
	}

	if (pb_read_obj(cli_fd, (void **)&ri, PB_REMOTE_IMAGE) < 0) {
		pr_err("Error reading local image header\n");
		goto err;
	}

	if (ri->name[0] == FINISH) {
		close(cli_fd);
		finish_local();
		return;
	}

	rop = handle_accept_proxy_write(cli_fd, ri->name, ri->type);
	free(ri);

	// If we have an operation. Check if we are ready to start or not.
	if (rop != NULL) {
		if (rop->rimg != NULL) {
			list_add_tail(&(rop->l), &rop_inprogress);
			event_set(epoll_fd, EPOLL_CTL_ADD, rop->fd, EPOLLIN, rop);
		} else {
			list_add_tail(&(rop->l), &rop_pending);
		}
		fd_set_nonblocking(rop->fd, false);
	}

	return;
err:
	close(cli_fd);
}

static inline void append_rimg(struct roperation *rop)
{
	BUG_ON(rop->type > CR_FD_MAX);
	if (!rimg_set[rop->type].next)
		INIT_LIST_HEAD(&rimg_set[rop->type]);
	list_add_tail(&(rop->rimg->l), &rimg_set[rop->type]);
}


static inline void finish_proxy_write(struct roperation *rop)
{
	/* Normal image received, forward it */
	struct roperation *rop_to_forward = new_remote_operation(
		rop->path, rop->type, remote_sk);

	// Add image to list of images.
	append_rimg(rop);

	rop_set_rimg(rop_to_forward, rop->rimg);
	if (list_empty(&rop_forwarding)) {
		forward_remote_image(rop_to_forward);
	}
	list_add_tail(&(rop_to_forward->l), &rop_forwarding);
}

int handle_roperation(struct epoll_event *event, struct roperation *rop)
{
	int64_t ret = (EPOLLOUT & event->events) ?
		send_image_async(rop) :
		recv_image_async(rop);

	if (ret > 0 || ret == EAGAIN || ret == EWOULDBLOCK) {
		event_set(
			epoll_fd,
			EPOLL_CTL_ADD,
			rop->fd,
			event->events,
			rop);
		return ret;
	}

	// Remove rop from list (either in progress or forwarding).
	list_del(&(rop->l));

	// Operation is finished.
	if (ret < 0) {
		pr_perror("Unable to %s %s (returned %" PRId64 ")",
				event->events & EPOLLOUT ? "send" : "receive",
				rop->rimg->path, ret);
		goto err;
	}

	pr_info("%s %s (%" PRIu64 " bytes)\n",
			event->events & EPOLLOUT ? "Sent" : "Received",
			rop->rimg->path, rop->rimg->size);

	if (event->events & EPOLLIN)
		// Finished receiving local image
		finish_proxy_write(rop);
	else
		// Finished forwarding image or reading it locally
		finish_proxy_read(rop);

err:
	xfree(rop);
	return ret;
}

void accept_image_connections() {
	int ret;

	epoll_fd = epoll_create(EPOLL_MAX_EVENTS);
	if (epoll_fd < 0) {
		pr_perror("Unable to open epoll");
		return;
	}

	events = calloc(EPOLL_MAX_EVENTS, sizeof(struct epoll_event));
	if (events == NULL) {
		pr_perror("Failed to allocated epoll events");
		goto end;
	}

	ret = event_set(epoll_fd, EPOLL_CTL_ADD, local_sk, EPOLLIN, &local_sk);
	if (ret) {
		pr_perror("Failed to add local fd to epoll");
		goto end;
	}

	while (1) {
		int n_events, i;

		n_events = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, 250);

		/* epoll_wait isn't restarted after interrupted by a signal */
		if (n_events < 0 && errno != EINTR) {
			pr_perror("Failed to epoll wait");
			goto end;
		}

		for (i = 0; i < n_events; i++) {
			if (events[i].data.ptr == &local_sk) {
				if (events[i].events & EPOLLHUP || events[i].events & EPOLLERR) {
					if (!finished_local)
						pr_perror("Unable to accept more local image connections");
					goto end;
				}
				handle_local_accept(local_sk);
			} else {
				struct roperation *rop = (struct roperation*)events[i].data.ptr;
				event_set(epoll_fd, EPOLL_CTL_DEL, rop->fd, 0, 0);
				if (handle_roperation(&events[i], rop) < 0) {
					pr_err("remote operation failed\n");
					goto end;
				}

			}
		}

		if (!forwarding)
			check_pending();

		if (finished_local && list_empty(&rop_pending) && list_empty(&rop_forwarding)) {
			pr_info("Finished both local and remote, exiting\n");
			break;
		}
	}
end:
	close(epoll_fd);
	close(local_sk);
	free(events);
}


/* Note: size is a limit on how much we want to read from the socket.  Zero means
 * read until the socket is closed.
 */
static int64_t recv_image_async(struct roperation *op)
{
	int fd = op->fd;
	struct rimage *rimg = op->rimg;
	uint64_t size = op->size;
	struct rbuf *curr_buf = op->curr_recv_buf;
	int n;

	n = read(fd,
			 curr_buf->buffer + curr_buf->nbytes,
			 size ?
				min((int) (size - rimg->size), BUF_SIZE - curr_buf->nbytes) :
				BUF_SIZE - curr_buf->nbytes);
	if (n == 0) {
		if (fd != remote_sk)
			close(fd);
		return n;
	} else if (n > 0) {
		curr_buf->nbytes += n;
		rimg->size += n;
		if (curr_buf->nbytes == BUF_SIZE) {
			struct rbuf *buf = xmalloc(sizeof(struct rbuf));
			if (buf == NULL) {
				if (fd != remote_sk)
					close(fd);
				return -1;
			}
			buf->nbytes = 0;
			list_add_tail(&(buf->l), &(rimg->buf_head));
			op->curr_recv_buf = buf;
			return n;
		}
		if (size && rimg->size == size) {
			if (fd != remote_sk)
				close(fd);
			return 0;
		}
	} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
		return errno;
	} else {
		pr_perror("Read for %s socket on fd=%d failed",
			rimg->path, fd);
		if (fd != remote_sk)
			close(fd);
		return -1;
	}
	return n;
}

static int64_t send_image_async(struct roperation *op)
{
	int fd = op->fd;
	struct rimage *rimg = op->rimg;
	int n;

	n = write(
		fd,
		op->curr_sent_buf->buffer + op->curr_sent_bytes,
		min(BUF_SIZE, op->curr_sent_buf->nbytes) - op->curr_sent_bytes);

	if (n > -1) {
		op->curr_sent_bytes += n;
		if (op->curr_sent_bytes == BUF_SIZE) {
			op->curr_sent_buf =
				list_entry(op->curr_sent_buf->l.next, struct rbuf, l);
			op->curr_sent_bytes = 0;
			return n;
		} else if (op->curr_sent_bytes == op->curr_sent_buf->nbytes) {
			if (fd != remote_sk)
				close(fd);
			return 0;
		}
		return n;
	} else if (errno == EPIPE || errno == ECONNRESET) {
		pr_warn("Connection for %s was closed early than expected\n",
			rimg->path);
		return -1;
	} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
		return errno;
	} else {
		pr_perror("Write on %s socket failed", rimg->path);
		return -1;
	}
}

int write_remote_image_connection(char *path, int type, uint64_t size)
{
	int sockfd = setup_UNIX_client_socket(DEFAULT_PROXY_SOCKET);

	if (sockfd < 0)
		return -1;

	if (write_header(sockfd, path, type, size) < 0) {
		pr_err("Error writing header for %s\n", path);
		return -1;
	}
	return sockfd;
}

int finish_remote_dump(void)
{
	pr_info("Dump side is calling finish\n");
	int fd = write_remote_image_connection(FINISH, 0, 0);

	if (fd == -1) {
		pr_err("Unable to open finish dump connection");
		return -1;
	}

	close(fd);
	return 0;
}

int skip_remote_bytes(int fd, unsigned long len)
{
	static char buf[4096];
	int n = 0;
	unsigned long curr = 0;

	for (; curr < len; ) {
		n = read(fd, buf, min(len - curr, (unsigned long)4096));
		if (n == 0) {
			pr_perror("Unexpected end of stream (skipping %lx/%lx bytes)",
				curr, len);
			return -1;
		} else if (n > 0) {
			curr += n;
		} else {
			pr_perror("Error while skipping bytes from stream (%lx/%lx)",
				curr, len);
			return -1;
		}
	}

	if (curr != len) {
		pr_err("Unable to skip the current number of bytes: %lx instead of %lx\n",
			curr, len);
		return -1;
	}
	return 0;
}

int remote_send_entry(void *entry, int pbtype, int crtype, ...)
{
	int fd;
	void *buf;
	uint64_t len;
	char name[PATH_MAX];
	va_list args;

	len = cr_pb_descs[pbtype].getpksize(entry);
	buf = xmalloc(len);
	if (!buf)
		return -1;

	if (cr_pb_descs[pbtype].pack(entry, buf) != len) {
		pr_err("Failed to serialize object\n");
		return -1;
	}

	va_start(args, crtype);
	vsnprintf(name, PATH_MAX, imgset_template[crtype].fmt, args);
	va_end(args);

	fd = write_remote_image_connection(name, crtype, len);

	fd_set_nonblocking(fd, false);
	if (send(fd, buf, len, 0) != len) {
		pr_info("Sending object with size: %"PRIu64"\n", len);
		pr_perror("failed sending entry");
		return -1;
	}

	xfree(buf);
	close(fd);
	return 0;
}