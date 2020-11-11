// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2020 Google LLC.
 */

#include <linux/err.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/seq_file.h>
#include <linux/bpf.h>
#include <linux/security.h>
#include <linux/bpf_lsm.h>
#include <linux/bpf_lsm_stats.h>

struct bpf_lsm_hook_stats bpf_lsm_hook_stats_list[] = {
	#define LSM_HOOK(S, RET, DEFAULT, NAME, ...) \
		[NAME##_type] = { 		     \
			.name = #NAME,		     \
			.calls = ATOMIC_INIT(0),     \
		},
	#include <linux/lsm_hook_defs.h>
	#undef LSM_HOOK
};

static void *seq_start(struct seq_file *m, loff_t *pos)
{

	if (*pos == __MAX_BPF_LSM_HOOK_TYPE)
		return NULL;

	return &bpf_lsm_hook_stats_list[*pos];
}

static void *seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;

	if (*pos == __MAX_BPF_LSM_HOOK_TYPE)
		return NULL;

	return &bpf_lsm_hook_stats_list[*pos];
}
static int show_prog(struct seq_file *m, void *v)
{
	struct bpf_lsm_hook_stats *item = v;
	
	if (!item)
		return 0;

	seq_printf(m, "%s %d\n", item->name, atomic_read(&item->calls));
	return 0;
}

static void seq_stop(struct seq_file *m, void *v)
{
}

static const struct seq_operations stat_file_seq_ops = {
	.show	= show_prog,
	.start	= seq_start,
	.stop	= seq_stop,
	.next	= seq_next,
};

static int stat_file_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &stat_file_seq_ops);
}

static const struct file_operations stat_file_ops = {
	.open		= stat_file_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init bpf_lsm_stats_init(void)
{
	struct dentry *base, *stats_file;

	base = securityfs_create_dir("bpf", NULL);
	if (IS_ERR(base))
		return PTR_ERR(base);

	stats_file = securityfs_create_file("hook_stats", 0600, base, NULL, &stat_file_ops);
	if (IS_ERR(stats_file))
		return PTR_ERR(stats_file);

	return 0;
}

late_initcall(bpf_lsm_stats_init);