// SPDX-License-Identifier: GPL-2.0

#include <linux/err.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/seq_file.h>
#include <linux/bpf.h>
#include <linux/security.h>

#include "krsi_fs.h"
#include "krsi_init.h"

extern struct krsi_hook krsi_hooks_list[];

static struct dentry *krsi_dir;

static void *seq_start(struct seq_file *m, loff_t *pos)
	__acquires(rcu)
{
	struct krsi_hook *h;
	struct dentry *dentry;
	struct bpf_prog_array *progs;
	struct bpf_prog_array_item *item;

	/*
	 * rcu_read_lock() must be held before any return statement
	 * because the stop() will always be called and thus call
	 * rcu_read_unlock()
	 */
	rcu_read_lock();

	dentry = file_dentry(m->file);
	h = dentry->d_fsdata;
	if (WARN_ON(!h))
		return ERR_PTR(-EFAULT);

	progs = rcu_dereference(h->progs);
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
	__releases(rcu)
{
	rcu_read_unlock();
}

static int show_prog(struct seq_file *m, void *v)
{
	struct bpf_prog_array_item *item = v;

	seq_printf(m, "%s\n", item->prog->aux->name);
	return 0;
}

static const struct seq_operations seq_ops = {
	.show	= show_prog,
	.start	= seq_start,
	.next	= seq_next,
	.stop	= seq_stop,
};

static int hook_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &seq_ops);
}

static const struct file_operations krsi_hook_ops = {
	.open		= hook_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

int krsi_fs_initialized;

bool is_krsi_hook_file(struct file *f)
{
	return f->f_op == &krsi_hook_ops;
}

static void __init krsi_free_hook(struct krsi_hook *h)
{
	struct bpf_prog_array_item *item;
	/*
	 * This function is __init so we are guarranteed that there will be
	 * no concurrent access.
	 */
	struct bpf_prog_array *progs = rcu_dereference_raw(h->progs);

	if (progs) {
		item = progs->items;
		while (item->prog) {
			bpf_prog_put(item->prog);
			item++;
		}
		bpf_prog_array_free(progs);
	}

	securityfs_remove(h->h_dentry);
	h->h_dentry = NULL;
}

static int __init krsi_init_hook(struct krsi_hook *h, struct dentry *parent)
{
	struct bpf_prog_array __rcu     *progs;
	struct dentry *h_dentry;
	int ret;

	h_dentry = securityfs_create_file(h->name, 0600, parent,
			NULL, &krsi_hook_ops);

	if (IS_ERR(h_dentry))
		return PTR_ERR(h_dentry);

	mutex_init(&h->mutex);
	progs = bpf_prog_array_alloc(0, GFP_KERNEL);
	if (!progs) {
		ret = -ENOMEM;
		goto error;
	}

	RCU_INIT_POINTER(h->progs, progs);
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
