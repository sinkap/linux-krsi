/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _BPF_LSM_H
#define _BPF_LSM_H

#include <linux/bpf_event.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include "fs.h"

/*
 * This enum indexes one of the LSM hooks defined in hooks.h.
 * Each value of the enum is defined as <hook>_type.
 */
enum lsm_hook_type {
	#define BPF_LSM_HOOK(hook, ...) hook##_type,
	#include "hooks.h"
	#undef BPF_LSM_HOOK
	__MAX_LSM_HOOK_TYPE,
};

/*
 * bpf_lsm_argv_header is added after the metadata when using the
 * bpf_lsm_argv_info eBPF helper which output the args to the perf event
 * buffer.
 * TODO: This should ideally be moved to a uapi file.
 */
struct bpf_lsm_argv_header {
	unsigned long argc;
	unsigned long envc;
} __packed;

struct bpf_lsm_argv_info {
	const struct bpf_lsm_argv_header *header;
	const struct linux_binprm *bprm;
};

/*
 * TODO: This should ideally be moved to a uapi file.
 */
enum running_exec_unlink_type {
	/*
	 * Not a running executable.
	 */
	BPF_LSM_EXEC_NOT_RUNNING,
	/*
	 * The current process is trying to unlink its own executable.
	 */
	BPF_LSM_EXEC_UNLINK_SELF,
	/*
	 * The current process is trying to unlink an executable which is the
	 * same as the real_parent.
	 */
	BPF_LSM_EXEC_UNLINK_PARENT,
	/*
	 * The current process is trying to delete an a running executable
	 * not covered above.
	 */
	BPF_LSM_EXEC_UNLINK_OTHER,
};

extern int bpf_lsm_fs_initialized;

/*
 * This data structure contains all the information required by the LSM for a
 * a hook.
 */
struct bpf_lsm_hook {
	/*
	 * The name of the security hook, a file with this name will be created
	 * in the securityfs.
	 */
	const char *name;
	/*
	 * The type of the LSM hook, the LSM uses this to index the list of the
	 * hooks to run the eBPF programs that may have been attached.
	 */
	enum lsm_hook_type h_type;
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
	struct bpf_prog_array __rcu *progs;
	/*
	 * The actual implementation of the hook. This also ensures that
	 * BTF information is generated for the hook.
	 */
	void *btf_hook_func;
};

extern struct bpf_lsm_hook bpf_lsm_hooks_list[];

#define lsm_for_each_hook(hook) \
	for ((hook) = &bpf_lsm_hooks_list[0]; \
	     (hook) < &bpf_lsm_hooks_list[__MAX_LSM_HOOK_TYPE]; \
	     (hook)++)

#endif /* _BPF_LSM_H */
