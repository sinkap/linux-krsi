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

/*
 * Security blob for struct task_struct.
 */
struct bpf_lsm_task_blob {
	char *arg_pages;
	unsigned long num_arg_pages;
};

static inline struct bpf_lsm_task_blob *get_bpf_lsm_task_blob(
						const struct cred *cred)
{
	return cred->security + bpf_lsm_blob_sizes.lbs_cred;
}

#endif /* __BPF_LSM_DATA_H */
