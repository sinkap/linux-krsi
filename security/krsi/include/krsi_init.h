/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _KRSI_INIT_H
#define _KRSI_INIT_H

#include "krsi_fs.h"

enum krsi_hook_type {
	PROCESS_EXECUTION,
	__MAX_KRSI_HOOK_TYPE, /* delimiter */
};

extern int krsi_fs_initialized;
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
};

extern struct krsi_hook krsi_hooks_list[];

#define krsi_for_each_hook(hook) \
	for ((hook) = &krsi_hooks_list[0]; \
	     (hook) < &krsi_hooks_list[__MAX_KRSI_HOOK_TYPE]; \
	     (hook)++)

#endif /* _KRSI_INIT_H */
