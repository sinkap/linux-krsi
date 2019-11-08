/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright 2019 Google LLC.
 */

#ifndef _BPF_LSM_FS_H
#define _BPF_LSM_FS_H

#include <linux/bpf.h>
#include <linux/fs.h>
#include <linux/types.h>

bool is_bpf_lsm_hook_file(struct file *f);

/*
 * The name of the directory created in securityfs
 *
 *	/sys/kernel/security/<dir_name>
 */
#define BPF_LSM_SFS_NAME "bpf"

#endif /* _BPF_LSM_FS_H */
