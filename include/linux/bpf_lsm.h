/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright 2019 Google LLC.
 */

#ifndef _LINUX_BPF_LSM_H
#define _LINUX_BPF_LSM_H

#include <linux/bpf.h>
#include <linux/jump_label.h>

#ifdef CONFIG_BPF_LSM

#define LSM_HOOK(RET, NAME, ...)		\
DECLARE_STATIC_KEY_FALSE(bpf_lsm_key_##NAME);   \
void bpf_lsm_##NAME##_set_enabled(bool value);
#include <linux/lsm_hook_names.h>
#undef LSM_HOOK

#define LSM_HOOK(RET, NAME, ...) RET bpf_lsm_##NAME(__VA_ARGS__);
#include <linux/lsm_hook_names.h>
#undef LSM_HOOK

#define HAS_BPF_LSM_PROG(FUNC) (static_branch_unlikely(&bpf_lsm_key_##FUNC))

#define RUN_BPF_LSM_VOID_PROGS(FUNC, ...)				\
	do {								\
		if (HAS_BPF_LSM_PROG(FUNC))				\
			bpf_lsm_##FUNC(__VA_ARGS__);			\
	} while (0)

#define RUN_BPF_LSM_INT_PROGS(RC, FUNC, ...) ({				\
	do {								\
		if (HAS_BPF_LSM_PROG(FUNC)) {				\
			if (RC == 0)					\
				RC = bpf_lsm_##FUNC(__VA_ARGS__);	\
		}							\
	} while (0);							\
	RC;								\
})

int bpf_lsm_set_enabled(const char *name, bool value);

#else /* !CONFIG_BPF_LSM */

#define HAS_BPF_LSM_PROG false
#define RUN_BPF_LSM_INT_PROGS(RC, FUNC, ...) (RC)
#define RUN_BPF_LSM_VOID_PROGS(FUNC, ...)

static inline int bpf_lsm_set_enabled(const char *name, bool value)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_BPF_LSM */

#endif /* _LINUX_BPF_LSM_H */
