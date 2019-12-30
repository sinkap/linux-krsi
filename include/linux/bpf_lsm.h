/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright 2019 Google LLC.
 */

#ifndef _LINUX_BPF_LSM_H
#define _LINUX_BPF_LSM_H

#include <linux/bpf.h>
#include <linux/lsm_hooks.h>

#ifdef CONFIG_SECURITY_BPF

/* Mutable hooks defined at runtime and executed after all the statically
 * define LSM hooks.
 */
extern struct security_hook_heads bpf_lsm_hook_heads;

int bpf_lsm_srcu_read_lock(void);
void bpf_lsm_srcu_read_unlock(int idx);

#define CALL_BPF_LSM_VOID_HOOKS(FUNC, ...)			\
	do {							\
		struct security_hook_list *P;			\
		int _idx;					\
								\
		if (hlist_empty(&bpf_lsm_hook_heads.FUNC))	\
			break;					\
								\
		_idx = bpf_lsm_srcu_read_lock();		\
		hlist_for_each_entry(P, &bpf_lsm_hook_heads.FUNC, list) \
			P->hook.FUNC(__VA_ARGS__);		\
		bpf_lsm_srcu_read_unlock(_idx);			\
	} while (0)

#define CALL_BPF_LSM_INT_HOOKS(RC, FUNC, ...) ({		\
	do {							\
		struct security_hook_list *P;			\
		int _idx;					\
								\
		if (hlist_empty(&bpf_lsm_hook_heads.FUNC))	\
			break;					\
								\
		_idx = bpf_lsm_srcu_read_lock();		\
								\
		hlist_for_each_entry(P,				\
			&bpf_lsm_hook_heads.FUNC, list) {	\
			RC = P->hook.FUNC(__VA_ARGS__);		\
			if (RC)					\
				break;				\
		}						\
		bpf_lsm_srcu_read_unlock(_idx);			\
	} while (0);						\
	IS_ENABLED(CONFIG_SECURITY_BPF_ENFORCE) ? RC : 0;	\
})

#else

#define BPF_LSM_INT_HOOKS(RC, FUNC, ...) (RC)
#define BPF_LSM_VOID_HOOKS(...)

static inline int bpf_lsm_srcu_read_lock(void)
{
	return 0;
}

static inline void bpf_lsm_srcu_read_unlock(int idx) {}
#endif /* CONFIG_SECURITY_BPF */

#endif /* _LINUX_BPF_LSM_H */
