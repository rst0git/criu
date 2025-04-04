#ifndef __CR_ASM_RESTORE_H__
#define __CR_ASM_RESTORE_H__

#include "asm/restorer.h"

#include "images/core.pb-c.h"

/* clang-format off */
#define JUMP_TO_RESTORER_BLOB(new_sp, restore_task_exec_start,	\
			      task_args)			\
	asm volatile(						\
			"and  sp, %0, ~15		\n"	\
			"mv  a0, %2			\n"	\
			"jr   %1 			\n"	\
			:					\
			: "r"(new_sp),				\
			  "r"(restore_task_exec_start),		\
			  "r"(task_args)			\
			: "a0", "memory")
/* clang-format on */

static inline void core_get_tls(CoreEntry *pcore, tls_t *ptls)
{
	*ptls = pcore->ti_riscv64->tls;
}

int restore_fpu(struct rt_sigframe *sigframe, CoreEntry *core);

#endif
