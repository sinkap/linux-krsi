// SPDX-License-Identifier: GPL-2.0

#include <linux/err.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/security.h>

#include "krsi_fs.h"
#include "krsi_init.h"

extern struct krsi_hook krsi_hooks_list[];

static struct dentry *krsi_dir;

static const struct file_operations krsi_hook_ops = {
	.llseek = generic_file_llseek,
};

int krsi_fs_initialized;

bool is_krsi_hook_file(struct file *f)
{
	return f->f_op == &krsi_hook_ops;
}

static void __init krsi_free_hook(struct krsi_hook *h)
{
	securityfs_remove(h->h_dentry);
	h->h_dentry = NULL;
}

static int __init krsi_init_hook(struct krsi_hook *h, struct dentry *parent)
{
	struct dentry *h_dentry;
	int ret;

	h_dentry = securityfs_create_file(h->name, 0600, parent,
			NULL, &krsi_hook_ops);

	if (IS_ERR(h_dentry))
		return PTR_ERR(h_dentry);
	h_dentry->d_fsdata = h;
	h->h_dentry = h_dentry;
	return 0;

error:
	securityfs_remove(h_dentry);
	return ret;
}

static int __init krsi_fs_init(void)
{

	struct krsi_hook *hook;
	int ret;

	krsi_dir = securityfs_create_dir(KRSI_SFS_NAME, NULL);
	if (IS_ERR(krsi_dir)) {
		ret = PTR_ERR(krsi_dir);
		pr_err("Unable to create krsi sysfs dir: %d\n", ret);
		krsi_dir = NULL;
		return ret;
	}

	/*
	 * If there is an error in initializing a hook, the initialization
	 * logic makes sure that it has been freed, but this means that
	 * cleanup should be called for all the other hooks. The cleanup
	 * logic handles uninitialized data.
	 */
	krsi_for_each_hook(hook) {
		ret = krsi_init_hook(hook, krsi_dir);
		if (ret < 0)
			goto error;
	}

	krsi_fs_initialized = 1;
	return 0;
error:
	krsi_for_each_hook(hook)
		krsi_free_hook(hook);
	securityfs_remove(krsi_dir);
	return ret;
}

late_initcall(krsi_fs_init);
