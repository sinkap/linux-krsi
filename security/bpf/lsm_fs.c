// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <linux/err.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/security.h>
#include <linux/bpf_lsm.h>

#include "fs.h"
#include "bpf_lsm.h"

static struct dentry *bpf_lsm_dir;

static const struct file_operations hook_ops = {};

int bpf_lsm_fs_initialized;

bool is_bpf_lsm_hook_file(struct file *f)
{
	return f->f_op == &hook_ops;
}

static void __init free_hook(struct bpf_lsm_hook *h)
{
	securityfs_remove(h->h_dentry);
	h->h_dentry = NULL;
}

static int __init init_hook(struct bpf_lsm_hook *h, struct dentry *parent)
{
	struct dentry *h_dentry;

	h_dentry = securityfs_create_file(h->name, 0600, parent,
			NULL, &hook_ops);
	if (IS_ERR(h_dentry))
		return PTR_ERR(h_dentry);

	h_dentry->d_fsdata = h;
	h->h_dentry = h_dentry;
	return 0;
}

static int __init bpf_lsm_fs_init(void)
{
	struct bpf_lsm_hook *hook;
	int ret;

	bpf_lsm_dir = securityfs_create_dir(BPF_LSM_SFS_NAME, NULL);
	if (IS_ERR(bpf_lsm_dir)) {
		ret = PTR_ERR(bpf_lsm_dir);
		pr_err("BPF LSM: Unable to create sysfs dir: %d\n", ret);
		return ret;
	}

	/*
	 * If there is an error in initializing a hook, the initialization
	 * logic makes sure that it has been freed, but this means that
	 * cleanup should be called for all the other hooks. The cleanup
	 * logic handles uninitialized data.
	 */
	lsm_for_each_hook(hook) {
		ret = init_hook(hook, bpf_lsm_dir);
		if (ret < 0)
			goto error;
	}

	bpf_lsm_fs_initialized = 1;
	return 0;
error:
	lsm_for_each_hook(hook)
		free_hook(hook);
	securityfs_remove(bpf_lsm_dir);
	return ret;
}

late_initcall(bpf_lsm_fs_init);
