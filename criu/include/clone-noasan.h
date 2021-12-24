#ifndef __CR_CLONE_NOASAN_H__
#define __CR_CLONE_NOASAN_H__

#include "linux/rseq.h"

#if defined(RSEQ_SIG)
static inline void unregister_glibc_rseq(void)
{
	/* unregister rseq */
	syscall(__NR_rseq, (void *)((char *)__criu_thread_pointer() + __rseq_offset), __rseq_size, 1, RSEQ_SIG);
}
#else
static inline void unregister_glibc_rseq(void)
{
}
#endif

int clone_noasan(int (*fn)(void *), int flags, void *arg);
int clone3_with_pid_noasan(int (*fn)(void *), void *arg, int flags, int exit_signal, pid_t pid);

#endif /* __CR_CLONE_NOASAN_H__ */
