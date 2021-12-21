/*
 * test for rseq() syscall
 * See also https://www.efficios.com/blog/2019/02/08/linux-restartable-sequences/
 * https://github.com/torvalds/linux/commit/d7822b1e24f2df5df98c76f0e94a5416349ff759
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <syscall.h>

#include "zdtmtst.h"

#if defined(__x86_64__)

const char *test_doc = "Check that rseq() basic C/R works";
const char *test_author = "Alexander Mikhalitsyn <alexander.mikhalitsyn@virtuozzo.com>";
/* parts of code borrowed from https://www.efficios.com/blog/2019/02/08/linux-restartable-sequences/ */

/* some useful definitions from kernel uapi */
enum rseq_flags {
	RSEQ_FLAG_UNREGISTER = (1 << 0),
};

struct rseq {
	uint32_t cpu_id_start;
	uint32_t cpu_id;
	uint64_t rseq_cs;
	uint32_t flags;
} __attribute__((aligned(4 * sizeof(uint64_t))));

#ifndef __NR_rseq
#define __NR_rseq 334
#endif
/* EOF */

static __thread volatile struct rseq __rseq_abi;

#define RSEQ_SIG 0x53053053

static int sys_rseq(volatile struct rseq *rseq_abi, uint32_t rseq_len, int flags, uint32_t sig)
{
	return syscall(__NR_rseq, rseq_abi, rseq_len, flags, sig);
}

static void register_thread(void)
{
	int rc;
	rc = sys_rseq(&__rseq_abi, sizeof(struct rseq), 0, RSEQ_SIG);
	if (rc) {
		fail("Failed to register rseq");
		exit(1);
	}
}

static void unregister_thread(void)
{
	int rc;
	rc = sys_rseq(&__rseq_abi, sizeof(struct rseq), RSEQ_FLAG_UNREGISTER, RSEQ_SIG);
	if (rc) {
		fail("Failed to unregister rseq");
		exit(1);
	}
}

static void check_thread(void)
{
	int rc;
	rc = sys_rseq(&__rseq_abi, sizeof(struct rseq), 0, RSEQ_SIG);
	if (!(rc && errno == EBUSY)) {
		fail("Failed to check rseq %d", rc);
		exit(1);
	}
}

#define RSEQ_ACCESS_ONCE(x) (*(__volatile__ __typeof__(x) *)&(x))

#define rseq_after_asm_goto() asm volatile("" : : : "memory")

static int rseq_addv(intptr_t *v, intptr_t count, int cpu)
{
	/* clang-format off */
	__asm__ __volatile__ goto(
		".pushsection __rseq_table, \"aw\"\n\t"
		".balign 32\n\t"
		"cs_obj:\n\t"
		/* version, flags */
		".long 0, 0\n\t"
		/* start_ip, post_commit_offset, abort_ip */
		".quad 1f, (2f-1f), 4f\n\t"
		".popsection\n\t"
		"1:\n\t"
		"leaq cs_obj(%%rip), %%rax\n\t"
		"movq %%rax, %[rseq_cs]\n\t"
		"cmpl %[cpu_id], %[current_cpu_id]\n\t"
		"jnz 4f\n\t"
		"addq %[count], %[v]\n\t"	/* final store */
		"2:\n\t"
		".pushsection __rseq_failure, \"ax\"\n\t"
		/* Disassembler-friendly signature: nopl <sig>(%rip). */
		".byte 0x0f, 0x1f, 0x05\n\t"
		".long 0x53053053\n\t"	/* RSEQ_FLAGS */
		"4:\n\t"
		"jmp abort\n\t"
		".popsection\n\t"
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]            "r" (cpu),
		[current_cpu_id]      "m" (__rseq_abi.cpu_id),
		[rseq_cs]             "m" (__rseq_abi.rseq_cs),
		/* final store input */
		[v]                   "m" (*v),
		[count]               "er" (count)
		: "memory", "cc", "rax"
		: abort
	);
	/* clang-format on */
	rseq_after_asm_goto();
	return 0;
abort:
	rseq_after_asm_goto();
	return -1;
}

int main(int argc, char *argv[])
{
	int cpu, ret;
	intptr_t *cpu_data;
	long nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);

	test_init(argc, argv);

	cpu_data = calloc(nr_cpus, sizeof(*cpu_data));
	if (!cpu_data) {
		fail("calloc");
		exit(EXIT_FAILURE);
	}

	register_thread();

	test_daemon();
	test_waitsig();

	check_thread();

	cpu = RSEQ_ACCESS_ONCE(__rseq_abi.cpu_id_start);
	ret = rseq_addv(&cpu_data[cpu], 2, cpu);
	if (ret)
		fail("Failed to increment per-cpu counter");
	else
		test_msg("cpu_data[%d] == %ld\n", cpu, (long int)cpu_data[cpu]);

	if (cpu_data[cpu] == 2)
		pass();
	else
		fail();

	return 0;
}

#else /* #if defined(__x86_64__) */

int main(int argc, char *argv[])
{
	test_init(argc, argv);
	skip("Unsupported arch");
	test_daemon();
	test_waitsig();
	pass();
	return 0;
}

#endif /* #if defined(__x86_64__) */