// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#ifndef __BPF_LSM_DATA_H
#define __BPF_LSM_DATA_H

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/lsm_hooks.h>
#include <linux/list.h>
#include <linux/pid.h>
#include <linux/spinlock.h>

extern struct lsm_blob_sizes bpf_lsm_blob_sizes __lsm_ro_after_init;

int bpf_lsm_data_init(void) __init;

/*
 * Security blob for the inode.
 */
struct bpf_lsm_inode_blob {
	/*
	 * Set to the struct pid of the process that created the inode in
	 * in /proc/<pid>/
	 */
	struct pid *proc_pid;
};

/*
 * Security blob for struct task_struct.
 */
struct bpf_lsm_task_blob {
	struct inode *exec_inode;
	struct pid *pid;
	char *arg_pages;
	unsigned long num_arg_pages;
};

static inline struct bpf_lsm_inode_blob *get_bpf_lsm_inode_blob(
						const struct inode *inode)
{
	if (unlikely(!inode->i_security))
		return NULL;
	return inode->i_security + bpf_lsm_blob_sizes.lbs_inode;
}

static inline struct bpf_lsm_task_blob *get_bpf_lsm_task_blob(
						const struct cred *cred)
{
	return cred->security + bpf_lsm_blob_sizes.lbs_cred;
}

#endif /* __BPF_LSM_DATA_H */
