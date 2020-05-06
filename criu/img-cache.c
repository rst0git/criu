#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>

#include <compel/plugins/std/syscall-codes.h>
#include "cr_options.h"
#include "criu-log.h"
#include "image.h"
#include "images/inventory.pb-c.h"
#include "images/pagemap.pb-c.h"
#include "images/pipe-data.pb-c.h"
#include "images/tcp-stream.pb-c.h"
#include "page.h"
#include "page-pipe.h"
#include "protobuf.h"
#include "protobuf-desc.h"
#include "util.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "img-cache: "

#define EPOLL_MAX_EVENTS 50

static bool finish = false;

static struct list_head cache[CR_FD_MAX];

typedef struct {
	uint32_t pb_type;
	uint8_t *data;
	off_t extra_data_offset;
	uint64_t extra_data_size;
	uint8_t *extra_data;
	struct list_head l;
} img_entry_t;

typedef struct {
	char *name;
	uint32_t fd_type;
	union {
		struct {
			uint8_t *data;
			uint64_t size;
		};
		struct {
			img_entry_t *current_entry;
			struct list_head entries;
		};
	};
	struct list_head l;
} img_t;

static uint64_t get_extra_data_size(img_entry_t *e)
{
	uint64_t len = 0;

	switch (e->pb_type) {
	case PB_PIPE_DATA:
		len = ((PipeDataEntry*)e->data)->bytes;
		break;
	case PB_TCP_STREAM:
		len = ((TcpStreamEntry*)e->data)->inq_len + ((TcpStreamEntry*)e->data)->outq_len;
		break;
	}

	return len;
}

uint64_t recv_data(int fd, uint8_t *buf, uint64_t len)
{
	uint64_t total = 0;

	while (total < len) {
		int n = read(fd, buf + total, len - total);
		if (n < 0) {
			pr_perror("read failed");
			break;
		}
		total += n;
	}

	return total;
}

static img_t *get_img_from_cache(const char *name, int fd_type)
{
	static img_t *rimg = NULL;

	if (!cache[fd_type].next)
		return NULL;

	if (rimg && rimg->fd_type == fd_type && !strncmp(rimg->name, name, PATH_MAX))
		return rimg;

	list_for_each_entry (rimg, &(cache[fd_type]), l)
		if (!strncmp(rimg->name, name, PATH_MAX))
			return rimg;

	pr_debug("No image %s (fd_type=%d)\n", name, fd_type);
	return NULL;
}

bool exists_in_cache(const char *name, int fd_type)
{
	return get_img_from_cache(name, fd_type) != NULL;
}

static int add_entry_to_cache(RemoteImageEntry *ri, img_entry_t *e)
{
	img_t *rimg;

	rimg = get_img_from_cache(ri->name, ri->fd_type);
	if (!rimg) {
		rimg = xmalloc(sizeof(*rimg));
		if (!rimg)
			return -1;

		rimg->name = xstrdup(ri->name);
		if (!rimg->name) {
			xfree(rimg);
			return -1;
		}

		rimg->fd_type = ri->fd_type;
		rimg->current_entry = NULL;
		INIT_LIST_HEAD(&(rimg->entries));

		if (!cache[rimg->fd_type].next)
			INIT_LIST_HEAD(&cache[rimg->fd_type]);

		list_add_tail(&(rimg->l), &cache[rimg->fd_type]);
	}

	list_add_tail(&(e->l), &(rimg->entries));
	return 0;
}

static int unpack_entry(RemoteImageEntry *ri)
{
	img_entry_t *e;

	e = xmalloc(sizeof(*e));
	if (!e)
		return -1;

	e->pb_type = ri->pb_type;
	e->extra_data = NULL;
	e->extra_data_offset = 0;

	e->data = cr_pb_descs[e->pb_type].unpack(NULL, ri->data.len, ri->data.data);
	if (!e->data) {
		pr_err("Failed to unpack incoming message\n");
		goto err;
	}

	e->extra_data_size = get_extra_data_size(e);
	if (e->extra_data_size) {
		uint64_t ret;
		e->extra_data = xmalloc(e->extra_data_size);
		if (!e->extra_data)
			goto err;

		ret = recv_data(remote_sk, e->extra_data, e->extra_data_size);
		if (ret != e->extra_data_size) {
			pr_perror("Recieved only %"PRIu64" expected %"PRIu64, ret, e->extra_data_size);
			goto err;
		}
		pr_debug("Recieved extra data: %"PRIu64"\n", e->extra_data_size);
	}

	if (add_entry_to_cache(ri, e))
		goto err;

	return 0;
err:
	xfree(e->extra_data);
	if (e->data)
		cr_pb_descs[e->pb_type].free(e->data, NULL);
	xfree(e);
	return -1;
}

static int recieve_raw_image(RemoteImageEntry *ri)
{
	img_t *rimg;
	uint64_t ret;

	rimg = get_img_from_cache(ri->name, ri->fd_type);
	if (!rimg) {
		rimg = xmalloc(sizeof(*rimg));
		if (!rimg)
			return -1;

		rimg->name = xstrdup(ri->name);
		if (!rimg->name) {
			xfree(rimg);
			return -1;
		}

		rimg->fd_type = ri->fd_type;
		rimg->size = 0;
		rimg->data = NULL;

		if (!cache[rimg->fd_type].next)
			INIT_LIST_HEAD(&cache[rimg->fd_type]);
		list_add_tail(&(rimg->l), &cache[rimg->fd_type]);
	}

	rimg->data = realloc(rimg->data, rimg->size + ri->size);
	if (!rimg->data) {
		pr_perror("realloc");
		return -1;
	}

	ret = recv_data(remote_sk, rimg->data + rimg->size, ri->size);
	if (ret != ri->size) {
		pr_perror("Recieved only %"PRIu64" expected %"PRIu64, ret, ri->size);
		return -1;
	}

	rimg->size += ri->size;

	return 0;
}

int pb_read_obj(int fd, void **pobj, int fd_type)
{
	struct cr_img img;
	img._x.fd = fd;
	bfd_setraw(&img._x);
	return do_pb_read_one(&img, pobj, fd_type, true);
}

/* Return value:
 *	 1 remote connection closed
 *	 0 success
 *	-1 error
 */
static int store_image(void)
{
	RemoteImageEntry *ri;
	int ret = -1;

	ret = pb_read_obj(remote_sk, (void **)&ri, PB_REMOTE_IMAGE);
	if (ret < 0) {
		pr_err("Failed to receive image");
		goto out;
	}

	if (ret == 0) {
		pr_info("Remote connection closed\n");
		ret = 1;
		goto out;
	}

	if (!ri->has_pb_type && !ri->has_fd_type && !ri->has_data && ri->name[0] == FINISH) {
		pr_info("Received finish message\n");
		ret = 1;
		goto out;
	}


	if (!ri->has_fd_type || ri->fd_type > CR_FD_MAX) {
		pr_err("Invalid image fd_type=%"PRIu32"\n", ri->fd_type);
		goto out;
	}
	if (!ri->has_pb_type) {
		if (recieve_raw_image(ri)) {
			pr_err("Failed to receive raw image\n");
			goto out;
		}
	} else {
		if (ri->pb_type > (uint32_t)PB_MAX) {
			pr_err("Invalid pb_type=%"PRIu32"\n", ri->pb_type);
			goto out;
		}

		if (!ri->has_data || ri->data.len == 0) {
			pr_err("Received image without data\n");
			goto out;
		}

		if (unpack_entry(ri)) {
			pr_err("Failed to unpack image\n");
			goto out;
		}
	}

	pr_debug("Recieved %s (fd_type=%u size=%zu)\n",
		ri->name, ri->fd_type, ri->data.len);

	if (ri->fd_type == CR_FD_INVENTORY)
		finish = true;

	ret = 0;
out:
	cr_pb_descs[PB_REMOTE_IMAGE].free(ri, NULL);
	return ret;
}

static int event_set(int epoll_fd, int op, int fd, uint32_t events, void *data)
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

/*
 * return:
 *	 1 remote connection closed
 *	 0 success
 *	-1 error
 */
static int image_cache_serve(void)
{
	int ret = -1;
	int epollfd;
	struct epoll_event *events;

	epollfd = epoll_create(EPOLL_MAX_EVENTS);
	if (epollfd < 0) {
		pr_perror("Unable to open epoll");
		return -1;
	}

	events = calloc(EPOLL_MAX_EVENTS, sizeof(struct epoll_event));
	if (!events) {
		pr_perror("Failed to allocate epoll events");
		goto end;
	}

	if (event_set(epollfd, EPOLL_CTL_ADD, remote_sk, EPOLLIN, &remote_sk)) {
		pr_perror("Failed to add proxy to cache fd to epoll");
		goto end;
	}

	while (1) {
		int i, n = epoll_wait(epollfd, events, EPOLL_MAX_EVENTS, -1);

		/* epoll_wait isn't restarted after interrupted by a signal */
		if (n < 0 && errno != EINTR) {
			pr_perror("Failed to epoll wait");
			ret = -1;
			goto end;
		}

		for (i = 0; i < n; i++) {
			if (events[i].events & EPOLLHUP || events[i].events & EPOLLERR) {
				pr_debug("Remote connection closed");
				ret = 1;
				break;
			}

			ret = store_image();
			if (ret != 0)
				goto end;
		}
	}
end:
	close(epollfd);
	free(events);
	return ret;
}

int start_img_cache(void)
{
	int tcp_sk, ret;

	if (!opts.remote)
		return 0;

	if (opts.ps_socket != -1) {
		remote_sk = opts.ps_socket;
		pr_info("Re-using ps socket %d\n", remote_sk);
	} else {
		if (!opts.port) {
			pr_err("port not specified\n");
			return -1;
		}

		tcp_sk = setup_tcp_server("image cache");
		if (tcp_sk < 0) {
			pr_perror("Failed to setup TCP socket");
			return -1;
		}

		/* Wait to accept connection from proxy */
		remote_sk = accept(tcp_sk, NULL, 0);
		if (remote_sk < 0) {
			pr_perror("Failed to accept connection");
			close(tcp_sk);
			return -1;
		}
		pr_info("Image-cache is connected to remote host\n");
	}

	fd_set_nonblocking(remote_sk, false);
	ret = image_cache_serve();

	if (finish && ret == 1)
		return 0;

	return -1;
}

int remote_get_entry(void **entry, int fd_type, char *name, bool eof)
{
	img_t *rimg;

	rimg = get_img_from_cache(name, fd_type);
	if (!rimg)
		return -1;

	if (rimg->current_entry == NULL)
		rimg->current_entry = list_entry(rimg->entries.next, img_entry_t, l);
	else if (list_is_last(&rimg->current_entry->l, &rimg->entries))
		return eof ? 0 : -1;
	else
		rimg->current_entry = list_entry(rimg->current_entry->l.next, img_entry_t, l);

	pr_debug("Reading entry from %s (fd_type=%d)\n", name, fd_type);
	*entry = rimg->current_entry->data;

	return 1;
}

int remote_get_extra_data(const char *name, int fd_type, void *buf, int len, off_t offset)
{
	img_t *rimg;
	img_entry_t *e;

	rimg = get_img_from_cache(name, fd_type);
	if (!rimg)
		return -1;

	BUG_ON(rimg->current_entry == NULL);
	e = rimg->current_entry;

	if (offset)
		e->extra_data_offset = offset;

	BUG_ON(e->extra_data_offset + len > e->extra_data_size);

	pr_debug("Reading extra data %s (fd_type=%d len=%d)\n", name, fd_type, len);
	memcpy(buf, e->extra_data + e->extra_data_offset, len);
	e->extra_data_offset += len;

	return 0;
}

/*
 * return:
 *	FD (>=0) success
 *	-1 error
 *	-2 image does not exist
 */
int remote_get_raw_image_fd(const char *name, int fd_type)
{
	int p[2], tmpfd = -1;
	img_t *rimg;
	ssize_t ret;
	FILE *tmp_file;
	struct iovec iov;

	rimg = get_img_from_cache(name, fd_type);
	if (!rimg)
		return -2;

	pr_debug("Reading raw image %s (fd_type=%d)\n", name, fd_type);

	tmp_file = tmpfile();
	if (!tmp_file) {
		pr_perror("Failed to open tmpfile");
		goto out;
	}

	if (pipe(p)) {
		pr_perror("Can't create pipe");
		fclose(tmp_file);
		goto out;
	}

	iov.iov_base = rimg->data;
	iov.iov_len = rimg->size;

	while (iov.iov_len > 0) {
		ret = vmsplice(p[1], &iov, 1, SPLICE_F_GIFT);
		if (ret < 0) {
			pr_perror("vmsplice failed");
			fclose(tmp_file);
			goto out;
		}

		ret = splice(p[0], NULL, fileno(tmp_file), NULL, ret, SPLICE_F_MOVE);
		if (ret < 0) {
			pr_perror("Can't splice data");
			fclose(tmp_file);
			goto out;

		}

		if (ret == 0) {
			pr_err("A pipe was closed unexpectedly\n");
			fclose(tmp_file);
			goto out;

		}

		iov.iov_base += ret;
		iov.iov_len -= ret;
	}

	if (fseek(tmp_file, 0, SEEK_SET)) {
		pr_perror("Failed to set file position to beginning of tmpfile");
		fclose(tmp_file);
		goto out;
	}

	tmpfd = fileno(tmp_file);
out:
	close(p[0]);
	close(p[1]);
	return tmpfd;
}
