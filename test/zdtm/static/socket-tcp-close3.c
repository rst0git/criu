#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <signal.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check if buffered data is restored with tcp_close on TCP_CLOSE sockets";
const char *test_author = "Radostin Stoyanov <radostin.stoyanov@eng.ox.ac.uk>";

static int port = 8880;

int main(int argc, char **argv)
{
	int socket_fd, write_fd, read_fd, ret;
	const char string[] = "abcdefghijklmnopqrstuvwxyz";
	char buffer[27];

	test_init(argc, argv);
	signal(SIGPIPE, SIG_IGN);

	socket_fd = tcp_init_server(AF_INET, &port);
	if (socket_fd < 0) {
		pr_err("Server initializations failed\n");
		return 1;
	}

	read_fd = tcp_init_client(AF_INET, "localhost", port);
	if (read_fd < 0) {
		pr_err("Client initializations failed\n");
		return 1;
	}

	write_fd = tcp_accept_server(socket_fd);
	if (write_fd < 0) {
		pr_err("Can't accept client\n");
		return 1;
	}
	close(socket_fd);

	ret = send(write_fd, string, sizeof(string), 0);
	if (ret != sizeof(string)) {
		pr_err("Failed sending data\n");
		return 1;
	}

	shutdown(write_fd, SHUT_RDWR);
	shutdown(read_fd, SHUT_RDWR);

	test_daemon();
	test_waitsig();

	ret = read(read_fd, &buffer, sizeof(string));
	if (ret != sizeof(string)) {
		fail("Did't receieve all buffered data");
		return 1;
	}

	if (strncmp(buffer, string, sizeof(string))) {
		fail("Received data does't match");
		return 1;
	}

	pass();
	return 0;
}
