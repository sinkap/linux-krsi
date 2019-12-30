/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _BPF_LSM_H
#define _BPF_LSM_H

#include <linux/filter.h>
#include <linux/lsm_hooks.h>
#include <linux/bpf.h>
#include <linux/btf.h>

struct bpf_lsm_hook {
	/* The security_hook_list is initialized dynamically. These are
	 * initialized in static LMSs by LSM_HOOK_INIT.
	 */
	struct security_hook_list sec_hook;
	/* The BPF program for which this hook was allocated, this is used upon
	 * detachment to find the hook corresponding to a program.
	 */
	struct bpf_prog *prog;
	/* The address of the trampoline callback allocated as the LSM hook */
	void *image;
};

struct bpf_lsm_list {
	bool initialized;
	const char *name;
	/* This mutex must be held when updatng the security_list_head and
	 * and accessing the attached trampolines.
	 */
	struct mutex mutex;
	/* The offset into the security_hook_heads at which this hook is
	 * attached.
	 */
	u32 offset;
	/* The BTF type for this hook.
	 */
	const struct btf_type *attach_type;
	/* func_model for the trampoline setup.
	 */
	struct btf_func_model func_model;
	/* The list of trampolines currently associated with the LSM hook.
	 * Mutex must be held when updating the tramp_list.
	 */
	struct list_head tramp_list;
	/* The head to which the allocated hooks must be attached to.
	 */
	struct hlist_head *security_list_head;
};

#endif /* _BPF_LSM_H */
