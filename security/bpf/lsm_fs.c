// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <linux/err.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/seq_file.h>
#include <linux/bpf.h>
#include <linux/security.h>
#include <linux/bpf_lsm.h>

#include "fs.h"
#include "bpf_lsm.h"

static struct dentry *bpf_lsm_dir;

static void *seq_start(struct seq_file *m, loff_t *pos)
	__acquires(RCU)
{
	struct bpf_prog_array_item *item;
	struct bpf_prog_array *progs;
	struct bpf_lsm_hook *h;
	struct dentry *dentry;

	/*
	 * rcu_read_lock() must be held before any return statement because the
	 * stop() will always be called and thus call rcu_read_unlock()
	 */
	rcu_read_lock();

	dentry = file_dentry(m->file);
	h = dentry->d_fsdata;
	if (WARN_ON(!h))
		return ERR_PTR(-EFAULT);

	progs = rcu_dereference(h->progs);
	if (!progs)
		return NULL;

	/* Assumes that no &dummy_bpf_prog entries exist */
	if ((*pos) >= bpf_prog_array_length(progs))
		return NULL;

	item = progs->items + *pos;
	if (!item->prog)
		return NULL;

	return item;
}

static void *seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct bpf_prog_array_item *item = v;

	item++;
	++*pos;

	if (!item->prog)
		return NULL;

	return item;
}

static void seq_stop(struct seq_file *m, void *v)
	__releases(RCU)
{
	rcu_read_unlock();
}

static int show_prog(struct seq_file *m, void *v)
{
	struct bpf_prog_array_item *item = v;

	seq_printf(m, "%s\n", item->prog->aux->name);
	return 0;
}

static const struct seq_operations hook_seq_ops = {
	.show	= show_prog,
	.start	= seq_start,
	.next	= seq_next,
	.stop	= seq_stop,
};

static int hook_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &hook_seq_ops);
}

static const struct file_operations hook_ops = {
	.open		= hook_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

int bpf_lsm_fs_initialized;

bool is_bpf_lsm_hook_file(struct file *f)
{
	return f->f_op == &hook_ops;
}

static void __init free_hook(struct bpf_lsm_hook *h)
{
	struct bpf_prog_array_item *item;
	/*
	 * This function is __init so we are guaranteed that there will be
	 * no concurrent access.
	 */
	struct bpf_prog_array *progs = rcu_dereference_raw(h->progs);

	if (progs) {
		for (item = progs->items; item->prog; item++)
			bpf_prog_put(item->prog);
		bpf_prog_array_free(progs);
	}

	securityfs_remove(h->h_dentry);
	h->h_dentry = NULL;
}

static int __init init_hook(struct bpf_lsm_hook *h, struct dentry *parent)
{
	struct dentry *h_dentry;

	h_dentry = securityfs_create_file(h->name, 0600,
					  parent, NULL, &hook_ops);
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
