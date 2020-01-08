/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _BPF_LSM_H
#define _BPF_LSM_H

#include <linux/filter.h>
#include <linux/lsm_hooks.h>
#include <linux/bpf.h>
#include <linux/btf.h>


struct bpf_lsm_hook {
	/* The security_hook_list is initialized dynamically. These are
	 * initialized in static LSMs by LSM_HOOK_INIT.
	 */
	struct security_hook_list sec_hook;
	/* The BPF program for which this hook was allocated, this is used upon
	 * detachment to find the hook corresponding to a program.
	 */
	struct bpf_prog *prog;
	/* The address of the allocated function */
	void *image;
};

/* The list represents the list of hooks attached to a particular security
 * list_head and contains information required for attaching and detaching
 * BPF Programs.
 */
struct bpf_lsm_list {
	/* Used on the first attached BPF program to populate the remaining
	 * information
	 */
	bool initialized;
	/* This mutex is used to serialize accesses to all the fields in
	 * this structure.
	 */
	struct mutex mutex;
	/* The BTF type for this hook.
	 */
	const struct btf_type *attach_type;
	/* func_model for the setup of the callback.
	 */
	struct btf_func_model func_model;
	/* The list of functions currently associated with the LSM hook.
	 */
	struct list_head callback_list;
	/* The head to which the allocated hooks must be attached to.
	 */
	struct hlist_head *security_list_head;
};

struct bpf_lsm_info {
	/* Dynamic Hooks can only be attached after the LSM is initialized.
	 */
	bool initialized;
	/* The number of hooks is calculated at runtime using the BTF
	 * information of the struct security_hook_heads.
	 */
	size_t num_hooks;
	/* The hook_lists is allocated during __init and mutexes for each
	 * allocated on __init, the remaining initialization happens when a
	 * BPF program is attached to the list.
	 */
	struct bpf_lsm_list *hook_lists;
	/* BTF type for security_hook_heads populated at init.
	 */
	const struct btf_type *btf_hook_heads;
	/* BTF type for security_list_options populated at init.
	 */
	const struct btf_type *btf_hook_types;
};

extern struct bpf_lsm_info bpf_lsm_info;

#endif /* _BPF_LSM_H */
