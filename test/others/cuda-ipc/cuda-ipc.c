// SPDX-License-Identifier: GPL-2.0
/* Two real CUDA IPC peers, forked before either initializes CUDA.
 * Keep the exported allocation and imported mapping alive until SIGUSR1.
 */
#define _GNU_SOURCE
#include <cuda.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define WORDS 4096
#define BEFORE 0x12340000U
#define AFTER  0x56780000U

static pid_t peer = -1;

static void die(const char *message)
{
	fprintf(stderr, "pid %ld: %s\n", (long)getpid(), message);
	if (peer > 0) {
		kill(peer, SIGKILL);
		while (waitpid(peer, NULL, 0) < 0 && errno == EINTR)
			;
	}
	exit(EXIT_FAILURE);
}

static void cuda_check(CUresult result, const char *operation)
{
	const char *name = "unknown", *description = "unknown";

	if (result == CUDA_SUCCESS)
		return;
	cuGetErrorName(result, &name);
	cuGetErrorString(result, &description);
	fprintf(stderr, "%s: %s (%s)\n", operation, name, description);
	die("CUDA operation failed");
}

#define CUDA(call) cuda_check((call), #call)

static void transfer(int fd, void *buffer, size_t length, int sending)
{
	char *cursor = buffer;

	while (length) {
		ssize_t n = sending ? write(fd, cursor, length) : read(fd, cursor, length);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			die("peer connection failed");
		cursor += n;
		length -= n;
	}
}

static void verify(CUdeviceptr memory, uint32_t expected)
{
	uint32_t values[WORDS];
	unsigned int i;

	CUDA(cuMemcpyDtoH(values, memory, sizeof(values)));
	for (i = 0; i < WORDS; i++) {
		if (values[i] != expected) {
			fprintf(stderr, "word %u: got %#x, expected %#x\n", i, values[i], expected);
			die("IPC data mismatch");
		}
	}
}

static void importer(int fd)
{
	CUipcMemHandle handle;
	CUdeviceptr memory;
	uint32_t expected;
	char done = 'D';
	unsigned int round;

	transfer(fd, &handle, sizeof(handle), 0);
	CUDA(cuIpcOpenMemHandle(&memory, handle, CU_IPC_MEM_LAZY_ENABLE_PEER_ACCESS));
	for (round = 0; round < 2; round++) {
		transfer(fd, &expected, sizeof(expected), 0);
		verify(memory, expected);
		CUDA(cuMemsetD32(memory, expected + 1, WORDS));
		CUDA(cuCtxSynchronize());
		transfer(fd, &done, sizeof(done), 1);
	}
	CUDA(cuIpcCloseMemHandle(memory));
}

static void exchange(int fd, CUdeviceptr memory, uint32_t expected)
{
	char done;

	CUDA(cuMemsetD32(memory, expected, WORDS));
	CUDA(cuCtxSynchronize());
	transfer(fd, &expected, sizeof(expected), 1);
	transfer(fd, &done, sizeof(done), 0);
	if (done != 'D')
		die("invalid peer reply");
	verify(memory, expected + 1);
}

int main(int argc, char **argv)
{
	CUcontext context;
	CUdevice device;
	CUdeviceptr memory;
	CUipcMemHandle handle;
	sigset_t signals;
	int sockets[2], sig, status;
	FILE *ready;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s READY_FILE\n", argv[0]);
		return EXIT_FAILURE;
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
	signal(SIGPIPE, SIG_IGN);
	sigemptyset(&signals);
	sigaddset(&signals, SIGUSR1);
	if (sigprocmask(SIG_BLOCK, &signals, NULL) || socketpair(AF_UNIX, SOCK_STREAM, 0, sockets))
		die("signal/socket setup failed");
	peer = fork(); /* Never fork a process that has already initialized CUDA. */
	if (peer < 0)
		die("fork failed");
	close(sockets[peer == 0 ? 0 : 1]);
	CUDA(cuInit(0));
	CUDA(cuDeviceGet(&device, 0));
	CUDA(cuDevicePrimaryCtxRetain(&context, device));
	CUDA(cuCtxSetCurrent(context));
	if (!peer) {
		importer(sockets[1]);
		CUDA(cuDevicePrimaryCtxRelease(device));
		close(sockets[1]);
		return EXIT_SUCCESS;
	}

	CUDA(cuMemAlloc(&memory, WORDS * sizeof(uint32_t)));
	CUDA(cuIpcGetMemHandle(&handle, memory));
	transfer(sockets[0], &handle, sizeof(handle), 1);
	exchange(sockets[0], memory, BEFORE);
	printf("IPC verified before checkpoint; owner=%ld importer=%ld job=%s\n",
	       (long)getpid(), (long)peer, getenv("CUDA_CHECKPOINT_JOB_FILE") ?: "<none>");
	ready = fopen(argv[1], "wx");
	if (!ready)
		die("cannot create ready file (use a fresh path)");
	if (fprintf(ready, "%ld %ld\n", (long)getpid(), (long)peer) < 0 || fclose(ready))
		die("cannot write ready file");
	puts("READY: checkpoint both PIDs, restore/unlock them, then send SIGUSR1 to owner");
	if (sigwait(&signals, &sig))
		die("sigwait failed");

	/* Check saved contents before writing anything after restore. */
	verify(memory, BEFORE + 1);
	exchange(sockets[0], memory, AFTER);
	if (waitpid(peer, &status, 0) != peer || !WIFEXITED(status) || WEXITSTATUS(status))
		die("importer failed");
	peer = -1;
	CUDA(cuMemFree(memory));
	CUDA(cuDevicePrimaryCtxRelease(device));
	close(sockets[0]);
	puts("PASS: saved GPU contents and bidirectional IPC access verified after resume");
	return EXIT_SUCCESS;
}
