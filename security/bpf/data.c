// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <linux/cred.h>
#include <linux/lsm_hooks.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/bpf.h>

#include "data.h"

static void bpf_lsm_task_to_inode(struct task_struct *t, struct inode *i)
{
	struct bpf_lsm_inode_blob *data = get_bpf_lsm_inode_blob(i);

	data->proc_pid = get_task_pid(t, PIDTYPE_PID);
	if (!data->proc_pid)
		pr_err("unable to determine pid in inode task hook\n");
}

static struct security_hook_list data_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(task_to_inode, bpf_lsm_task_to_inode),
};

struct lsm_blob_sizes bpf_lsm_blob_sizes __lsm_ro_after_init = {
	.lbs_cred = sizeof(struct bpf_lsm_task_blob),
	.lbs_inode = sizeof(struct bpf_lsm_inode_blob),
};

int __init bpf_lsm_data_init(void)
{
	security_add_hooks(data_hooks, ARRAY_SIZE(data_hooks), "bpf");
	return 0;
}
