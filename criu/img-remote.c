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
#include "util.h"
#include "xmalloc.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "img-remote: "

int remote_sk = -1;

int remote_connect(void)
{
	if (!opts.remote)
		return 0;

	if (opts.ps_socket != -1) {
		remote_sk = opts.ps_socket;
		pr_info("Re-using ps socket %d\n", remote_sk);
	} else {
		if (!opts.addr) {
			pr_err("address not specified\n");
			return -1;
		}

		if (!opts.port) {
			pr_err("port not specified\n");
			return -1;
		}

		remote_sk = setup_tcp_client();
		if (remote_sk < 0) {
			pr_perror("Unable to open proxy to cache TCP socket");
			return -1;
		}
	}

	fd_set_nonblocking(remote_sk, false);
	pr_info("Proxy is connected to Cache through fd %d\n", remote_sk);
	return 0;
}

static inline int remote_send_obj(RemoteImageEntry *ri)
{
	struct cr_img img;
	img._x.fd = remote_sk;
	bfd_setraw(&img._x);
	return pb_write_one(&img, ri, PB_REMOTE_IMAGE);
}

int remote_send_image(const char *name, int fd_type, int pb_type, void *buf, size_t len)
{
	int ret;
	RemoteImageEntry ri = REMOTE_IMAGE_ENTRY__INIT;

	if (len == 0)
		return 0; /* Don't send empty images */

	ri.name = xstrdup(name);
	if (!ri.name)
		return -1;

	ri.has_fd_type = true;
	ri.fd_type = fd_type;
	ri.has_pb_type = true;
	ri.pb_type = pb_type;
	ri.has_data = true;
	ri.data.len = len;
	ri.data.data = buf;

	pr_debug("Sending entry: %s (type=%d size=%zu)\n", name, fd_type, len);

	ret = remote_send_obj(&ri);
	xfree(ri.name);
	return ret;
}

int remote_send_raw_data(const char *name, int fd_type, size_t len)
{
	RemoteImageEntry ri = REMOTE_IMAGE_ENTRY__INIT;
	size_t ret;

	if (len == 0)
		return 0; /* Don't send empty images */

	ri.name = xstrdup(name);
	if (!ri.name)
		return -1;

	ri.has_fd_type = true;
	ri.fd_type = fd_type;
	ri.has_size = true;
	ri.size = len;

	pr_debug("Sending raw image %s (type=%d size=%zu)\n", name, fd_type, len);

	ret = remote_send_obj(&ri);
	xfree(ri.name);
	return ret;
}

int remote_send_finish_msg(void)
{
	RemoteImageEntry ri = REMOTE_IMAGE_ENTRY__INIT;

	if (!opts.remote)
		return 0;

	ri.name = FINISH;
	pr_info("Sending finish message\n");
	if (remote_send_obj(&ri))
		return -1;
	return 0;
}

int remote_dump_finish(void)
{
	RemoteImageEntry *ri;
	int ret;

	if (!opts.remote)
		return 0;

	if (remote_send_finish_msg())
		return -1;

	pr_info("Wait for finish ACK\n");
	ret = pb_read_obj(remote_sk, (void **)&ri, PB_REMOTE_IMAGE);
	if (ret < 0) {
		pr_perror("Failed to receive image");
		return -1;
	}

	if (ret == 0) {
		pr_info("Remote connection closed\n");
		return -1;
	}

	if (!ri->has_pb_type && !ri->has_fd_type && !ri->has_data && ri->name[0] == FINISH) {
		return 0;
	}

	return -1;
}
