/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2020 Google LLC.
 */

#ifndef _LINUX_BPF_LSM_STATS_H
#define _LINUX_BPF_LSM_STATS_H

#include <linux/sched.h>
#include <linux/bpf.h>
#include <linux/lsm_hooks.h>

#ifdef CONFIG_BPF_LSM

enum bpf_lsm_hook_type {
	#define LSM_HOOK(S, RET, DEFAULT, NAME, ...) NAME##_type,
	#include <linux/lsm_hook_defs.h>
	#undef LSM_HOOK
	__MAX_BPF_LSM_HOOK_TYPE,
};

struct bpf_lsm_hook_stats {
	const char *name;
	atomic_t calls;
};

extern struct bpf_lsm_hook_stats bpf_lsm_hook_stats_list[];

#else /* !CONFIG_BPF_LSM */

#endif /* CONFIG_BPF_LSM */

#endif /* _LINUX_BPF_LSM_STATS_H */
