#include <unistd.h>

#include "cr_options.h"
#include "criu-log.h"
#include "img-remote.h"
#include "util.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "img-proxy: "

/*
 * Image proxy is used to establish a TCP connection with the destination
 * that is running image-cache as part of a restore process. A file descriptor
 * to an open socket is provided to dump (or pre-dump) process via a UNIX
 * socket created in the specified working directory upon establish connection.
 * This mechanism is useful only pre-copy migration to avoid the overhead of
 * establishing multiple TCP connections with the restore side. However, this
 * feature is not necessary to be used by applications that make use of CRIU's
 * remote option, and the overhead mentioned above can be avoided by providing
 * a file descriptor to an open TCP connection with --ps-socket option.
 */
int image_proxy(bool background, char *local_proxy_path)
{
	pr_info("CRIU to Proxy Path: %s, Cache Address %s:%u\n",
		local_proxy_path, opts.addr, opts.port);

	local_sk = setup_UNIX_server_socket(local_proxy_path);
	if (local_sk < 0) {
		pr_perror("Unable to open CRIU to proxy UNIX socket");
		return -1;
	}

	if (opts.ps_socket != -1) {
		remote_sk = opts.ps_socket;
		pr_info("Re-using ps socket %d\n", remote_sk);
	} else {
		remote_sk = setup_tcp_client();
		if (remote_sk < 0) {
			pr_perror("Unable to open proxy to cache TCP socket");
			close(local_sk);
			return -1;
		}
	}

	pr_info("Proxy is connected to Cache through fd %d\n", remote_sk);

	if (background) {
		if (daemon(1, 0) == -1) {
			pr_perror("Can't run service server in the background");
			return -1;
		}
	}

	// TODO - local_sk and remote_sk send as args.
	accept_image_connections();
	pr_info("Finished image proxy\n");
	return 0;
}
