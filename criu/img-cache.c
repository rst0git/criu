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
#include "img-remote.h"
#include "images/inventory.pb-c.h"
#include "images/pstree.pb-c.h"
#include "images/remote-image.pb-c.h"
#include "protobuf-desc.h"
#include "util.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "img-cache: "

#define EPOLL_MAX_EVENTS 50

struct list_head cache[CR_FD_MAX];
static InventoryEntry *he = NULL;

struct rbuf {
	char *path;
	int type;
	int size;
	void *buffer;
	struct list_head l;
};

static inline int recv_image(struct rbuf *img)
{
	uint64_t off = 0;
	int n;

	while((img->size - off > 0)
			&& (n = read(remote_sk, img->buffer + off, img->size - off)) > 0) {
		off += n;
	}

	pr_debug("recieved %lu bytes\n", off);
	if (off < img->size)
		return -1;

	return 0;
}

static struct rbuf *get_img(const char *path, int type)
{
	struct rbuf *img = NULL;

	if (cache[type].next)
		list_for_each_entry(img, &(cache[type]), l)
			if (!strncmp(img->path, path, PATH_MAX))
				return img;

	return NULL;
}

static size_t read_buffer(unsigned len, uint8_t *buf)
{
	size_t n;
	size_t cur = 0;
	while ((n = read(remote_sk, buf + cur, len - cur)) != 0) {
		cur += n;
		if (cur == len)
			break;
	}
	return cur;
}

static int store_image()
{
	struct rbuf *img;
	RemoteImageEntry *ri;
	int ret;

	ret = pb_read_obj(remote_sk, (void **)&ri, PB_REMOTE_IMAGE);

	if (ret < 0) {
		pr_perror("Failed to receive image header");
		goto err;
	}

	if (!ret) {
		pr_info("Remote connection closed\n");
		free(ri);
		return 1;
	}

	if (!ri->has_size || ri->size == 0) {
		pr_err("Image size not specified\n");
		goto err;
	}

	if (ri->type > CR_FD_MAX || ri->type < 0) {
		pr_err("Invalid image type %ld\n", ri->type);
		goto err;
	}

	pr_debug("recieved header: %s (type=%ld)\n",
		((ri->name[0] == FINISH) ? "(null)" : ri->name), ri->type);

	if (ri->name[0] == FINISH) {
		if (write(remote_sk, FINISH, sizeof(FINISH)) < 0)
			pr_err("Error writing finish message\n");
		return 1;
	}

	if (ri->type == CR_FD_INVENTORY) {
		void *buf = xmalloc(ri->size);
		if (!buf)
			return -1;

		if (read_buffer(ri->size, buf) != ri->size) {
			pr_err("Failed to recieve incoming message\n");
			return -1;
		}

		he = cr_pb_descs[PB_INVENTORY].unpack(NULL, ri->size, buf);
		if (he == NULL) {
			pr_err("Failed to unpack incoming message\n");
			return -1;
		}

		pr_info("Recieved inventory size: %ld\n", ri->size);
		return 0;
	}

	img = xmalloc(sizeof(*img));
	if (!img)
		goto err;

	img->buffer = xmalloc(ri->size);
	if (!img->buffer) {
		xfree(img);
		goto err;
	}

	img->path = xstrdup(ri->name);
	if (!img->path) {
		xfree(img->buffer);
		xfree(img);
		goto err;
	}

	img->type = ri->type;
	img->size = ri->size;

	if (recv_image(img)) {
		pr_perror("Receiving remote image faild");
		xfree(img->path);
		xfree(img->buffer);
		xfree(img);
		goto err;
	}

	if (!cache[ri->type].next)
		INIT_LIST_HEAD(&cache[ri->type]);
	list_add_tail(&(img->l), &cache[ri->type]);

	free(ri);
	return 0;
err:
	free(ri);
	return -1;
}

int image_cache_serve()
{
	int ret = -1;
	int epoll_fd;
	struct epoll_event *e;

	epoll_fd = epoll_create(EPOLL_MAX_EVENTS);
	if (epoll_fd < 0) {
		pr_perror("Unable to open epoll");
		return -1;
	}

	e = calloc(EPOLL_MAX_EVENTS, sizeof(struct epoll_event));
	if (!e) {
		pr_perror("Failed to allocate epoll events");
		goto end;
	}

	if (event_set(epoll_fd, EPOLL_CTL_ADD, remote_sk, EPOLLIN, &remote_sk)) {
		pr_perror("Failed to add proxy to cache fd to epoll");
		goto end;
	}

	while (1) {
		int n = epoll_wait(epoll_fd, e, EPOLL_MAX_EVENTS, 250);

		/* epoll_wait isn't restarted after interrupted by a signal */
		if (n < 0 && errno != EINTR) {
			pr_perror("Failed to epoll wait");
			ret = -1;
			goto end;
		}

		for (int i = 0; i < n; i++) {
			if (e[i].events & EPOLLHUP || e[i].events & EPOLLERR) {
				pr_info("Remote connection closed");
				ret = 1;
				break;
			}

			ret = store_image();
			if (ret != 0)
				goto end;
		}
	}
	ret = 0;
end:
	close(epoll_fd);
	free(e);
	return ret;
}

int image_cache()
{
	int tmp;
	int ret;

	if (opts.ps_socket != -1) {
		remote_sk = opts.ps_socket;
		pr_info("Re-using ps socket %d\n", remote_sk);
	} else {
		remote_sk = setup_tcp_server("image cache");
		if (remote_sk < 0) {
			pr_perror("Failed to setup TCP socket");
			return -1;
		}
		pr_info("Running image cache on port %u\n",
			opts.port);

		/* Wait to accept connection from proxy */
		tmp = accept(remote_sk, NULL, 0);
		if (tmp < 0) {
			pr_perror("Failed to accept connection");
			close(remote_sk);
			return -1;
		}
		remote_sk = tmp;
	}
	pr_info("Cache is connected to proxy\n");

	fd_set_nonblocking(remote_sk, false);
	ret = image_cache_serve();

	if (!he) {
	    pr_err("Inventory image is not available\n");
	    return -1;
	}
	return ret == -1;
}

int remote_read_one(const char *path, int type, void **obj)
{
	struct rbuf *img;

	switch(type) {
	case PB_INVENTORY:
		*obj = he;
		break;
	case PB_PSTREE:
		img = get_img(path, CR_FD_PSTREE);
		if (!img)
			return -1;

		*obj = cr_pb_descs[PB_PSTREE].unpack(NULL, img->size, img->buffer);
		if (*obj == NULL) {
			pr_err("Failed to unpack incoming message\n");
			return -1;
		}

		list_del(&img->l);
		break;
	case PB_CGROUP:
		img = get_img(path, CR_FD_CGROUP);
		if (!img)
			return -1;
		*obj = cr_pb_descs[PB_CGROUP].unpack(NULL, img->size, img->buffer);
		if (*obj == NULL) {
			pr_err("Failed to unpack incomming message\n");
			return -1;
		}
		list_del(&img->l);
		break;
	default:
		return -1;
	}

	return 0;
}

int get_img_from_cache(const char *path, int type)
{
	int memfd;
	struct rbuf *img;

	img = get_img(path, type);
	if (!img)
		return -1;

	memfd = syscall(SYS_memfd_create, "", 0);
	if (memfd < 0) {
		pr_perror("memfd failed");
		return -1;
	}

	if (write(memfd, img->buffer, img->size) < img->size)
		return -1;

	lseek(memfd, 0, SEEK_SET);
	return memfd;
}
