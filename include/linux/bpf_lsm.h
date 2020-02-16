/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright 2019 Google LLC.
 */

#ifndef _LINUX_BPF_LSM_H
#define _LINUX_BPF_LSM_H

#include <linux/bpf.h>

#ifdef CONFIG_BPF_LSM

#define LSM_HOOK(RET, NAME, ...) RET bpf_lsm_##NAME(__VA_ARGS__);
#include <linux/lsm_hook_names.h>
#undef LSM_HOOK

#define RUN_BPF_LSM_VOID_PROGS(FUNC, ...) bpf_lsm_##FUNC(__VA_ARGS__)
#define RUN_BPF_LSM_INT_PROGS(RC, FUNC, ...) ({				\
	do {								\
		if (RC == 0)						\
			RC = bpf_lsm_##FUNC(__VA_ARGS__);		\
	} while (0);							\
	RC;								\
})

#else /* !CONFIG_BPF_LSM */

#define RUN_BPF_LSM_INT_PROGS(RC, FUNC, ...) (RC)
#define RUN_BPF_LSM_VOID_PROGS(FUNC, ...)

#endif /* CONFIG_BPF_LSM */

#endif /* _LINUX_BPF_LSM_H */
