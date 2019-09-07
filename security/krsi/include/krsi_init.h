/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _KRSI_INIT_H
#define _KRSI_INIT_H

#include "krsi_fs.h"

#include <linux/binfmts.h>

enum krsi_hook_type {
	PROCESS_EXECUTION,
	__MAX_KRSI_HOOK_TYPE, /* delimiter */
};

extern int krsi_fs_initialized;

struct krsi_bprm_ctx {
	struct linux_binprm *bprm;
};

/*
 * krsi_ctx is the context that is passed to all KRSI eBPF
 * programs.
 */
struct krsi_ctx {
	union {
		struct krsi_bprm_ctx bprm_ctx;
	};
};

/*
 * The LSM creates one file per hook.
 *
 * A pointer to krsi_hook data structure is stored in the
 * private fsdata of the dentry of the per-hook file created
 * in securityfs.
 */
struct krsi_hook {
	/*
	 * The name of the security hook, a file with this name will be created
	 * in the securityfs.
	 */
	const char *name;
	/*
	 * The type of the LSM hook, the LSM uses this to index the list of the
	 * hooks to run the eBPF programs that may have been attached.
	 */
	enum krsi_hook_type h_type;
	/*
	 * The dentry of the file created in securityfs.
	 */
	struct dentry *h_dentry;
	/*
	 * The mutex must be held when updating the progs attached to the hook.
	 */
	struct mutex mutex;
	/*
	 * The eBPF programs that are attached to this hook.
	 */
	struct bpf_prog_array __rcu	*progs;
};

extern struct krsi_hook krsi_hooks_list[];

static inline int krsi_run_progs(enum krsi_hook_type t, struct krsi_ctx *ctx)
{
	struct bpf_prog_array_item *item;
	struct bpf_prog *prog;
	struct krsi_hook *h = &krsi_hooks_list[t];
	int ret, retval = 0;

	preempt_disable();
	rcu_read_lock();

	item = rcu_dereference(h->progs)->items;
	while ((prog = READ_ONCE(item->prog))) {
		ret = BPF_PROG_RUN(prog, ctx);
		if (ret < 0) {
			retval = ret;
			goto out;
		}
		item++;
	}

out:
	rcu_read_unlock();
	preempt_enable();
	return IS_ENABLED(CONFIG_SECURITY_KRSI_ENFORCE) ? retval : 0;
}

#define krsi_for_each_hook(hook) \
	for ((hook) = &krsi_hooks_list[0]; \
	     (hook) < &krsi_hooks_list[__MAX_KRSI_HOOK_TYPE]; \
	     (hook)++)

#endif /* _KRSI_INIT_H */
