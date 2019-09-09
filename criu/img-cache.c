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
#include "images/remote-image.pb-c.h"
#include "protobuf-desc.h"
#include "util.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "img-cache: "

#define EPOLL_MAX_EVENTS 50

struct list_head cache[CR_FD_MAX];
static bool finish = false;

struct rbuf {
	char *name;
	uint64_t size;
	void *buffer;
	struct list_head l;
};

static struct rbuf *get_img(const char *path, int type)
{
	struct rbuf *img = NULL;

	if (cache[type].next)
		list_for_each_entry(img, &(cache[type]), l)
			if (!strncmp(img->name, path, PATH_MAX))
				return img;

	return NULL;
}

static size_t read_buffer(char **buf, uint64_t len)
{
	size_t n;
	size_t cur = 0;
	
	*buf = xmalloc(len);
	if (!*buf)
		return -1;

	while ((n = read(remote_sk, *buf + cur, len - cur)) != 0) {
		cur += n;
		if (cur == len)
			break;
	}
	return cur;
}

static void rbuf_free (struct rbuf *img) {
	if (!img)
		return;
	if (img->buffer)
		free(img->buffer);
	if (img->name)
		free(img->name);
	free(img);
}

static int store_image()
{
	struct rbuf *img = NULL;
	RemoteImageEntry *ri;
	int ret;

	ret = pb_read_obj(remote_sk, (void **)&ri, PB_REMOTE_IMAGE);

	if (ret < 0) {
		pr_perror("Failed to receive image header");
		goto out;
	}

	if (!ret) {
		pr_info("Remote connection closed\n");
		ret = 1;
		goto out;
	}

	ret = -1;
	if (!ri->has_size || ri->size == 0) {
		pr_err("Image size not specified\n");
		goto out;
	}

	if (ri->type > CR_FD_MAX) {
		pr_err("Invalid image type: %"PRIu64"\n", ri->type);
		goto out;
	}

	pr_debug("recieved header: %s (type=%"PRIu64")\n",
		((ri->name[0] == FINISH) ? "(null)" : ri->name), ri->type);

	if (ri->name[0] == FINISH) {
		if (write(remote_sk, FINISH, sizeof(FINISH)) < 0)
			pr_err("Failed to send finish message\n");
		ret = 1;
		goto out;
	}

	ret = -1;
	img = xmalloc(sizeof(*img));
	if (!img)
		goto out;

	img->name = xstrdup(ri->name);
	if (!img->name) {
		rbuf_free(img);
		goto out;
	}

	img->size = ri->size;

	if (read_buffer((char**)&img->buffer, img->size) != img->size) {
		pr_err("Failed to recieve incoming message\n");
		goto out;
	}

	if (!cache[ri->type].next)
		INIT_LIST_HEAD(&cache[ri->type]);
	list_add_tail(&(img->l), &cache[ri->type]);

	if (ri->type == CR_FD_INVENTORY)
		finish = true;

	ret = 0;
out:
	free(ri);
	return ret;
}

int image_cache_serve()
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
	close(epollfd);
	free(events);
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

	if (!finish) {
		pr_err("Inventory image not recieved\n");
		return -1;
	}
	return ret == -1;
}

int do_remote_read_one(void **entry, int pbtype, int crtype, ...)
{
	struct rbuf *img;
	char name[PATH_MAX];
	va_list args;

	va_start(args, crtype);
	vsnprintf(name, PATH_MAX, imgset_template[crtype].fmt, args);
	va_end(args);

	switch(pbtype) {
	case PB_INVENTORY:
	case PB_CGROUP:
	case PB_CPUINFO:
	case PB_UTSNS:
		img = get_img(name, crtype);
		if (!img)
			return -1;

		*entry = cr_pb_descs[pbtype].unpack(NULL, img->size, img->buffer);
		if (*entry == NULL) {
			pr_err("Failed to unpack incoming message\n");
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