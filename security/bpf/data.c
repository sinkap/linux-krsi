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
#include <linux/binfmts.h>

#include "data.h"

static void bpf_lsm_task_to_inode(struct task_struct *t, struct inode *i)
{
	struct bpf_lsm_inode_blob *data = get_bpf_lsm_inode_blob(i);

	data->proc_pid = get_task_pid(t, PIDTYPE_PID);
	if (!data->proc_pid)
		pr_err("unable to determine pid in inode task hook\n");
}

static int bpf_lsm_inode_alloc_security(struct inode *inode)
{
	struct bpf_lsm_inode_blob *data = get_bpf_lsm_inode_blob(inode);

	INIT_LIST_HEAD(&data->executors);
	spin_lock_init(&data->executors_lock);
	return 0;
}

static int bpf_lsm_bprm_set_creds(struct linux_binprm *bprm)
{
	struct bpf_lsm_task_blob *tsec;
	struct bpf_lsm_inode_blob *isec;
	struct executor *exec;
	struct inode *inode;
	struct pid *pid;

	tsec = get_bpf_lsm_task_blob(bprm->cred);
	if (unlikely(!tsec))
		return 0;

	/*
	 * Store the data of the executing process in the inode of the task.
	 */
	if (bprm->file && current) {
		inode = file_inode(bprm->file);
		isec = get_bpf_lsm_inode_blob(inode);

		pid = get_task_pid(current, PIDTYPE_PID);
		if (!pid) {
			// TODO: Why does this happen?
			pr_err("unable to determine pid in proc exec hook\n");
			return 0;
		}
		tsec->pid = pid;

		spin_lock(&inode->i_lock);
		__iget(inode);
		spin_unlock(&inode->i_lock);
		tsec->exec_inode = inode;

		exec = init_executor(pid);
		if (!exec)
			return PTR_ERR(exec);
		exec->pid = pid;

		spin_lock(&isec->executors_lock);
		list_add_tail_rcu(&exec->list, &isec->executors);
		spin_unlock(&isec->executors_lock);
		synchronize_rcu();
	}
	return 0;
}

static void bpf_lsm_task_free(struct task_struct *task)
{
	struct bpf_lsm_task_blob *tsec;
	struct bpf_lsm_inode_blob *isec;
	struct executor *exec;
	unsigned long flags;

	tsec = get_bpf_lsm_task_blob(task->cred);
	if (unlikely(!tsec))
		return;

	/*
	 * There are tasks like kernel threads which
	 * won't have an associated inode in their creds as there is
	 * no executable.
	 */
	if (!tsec->exec_inode) {
		return;
	}

	isec = get_bpf_lsm_inode_blob(tsec->exec_inode);
	if (unlikely(!isec))
			return;

	spin_lock_irqsave(&isec->executors_lock, flags);
	list_for_each_entry(exec, &isec->executors, list) {
		if (exec->pid && exec->pid == tsec->pid) {
			list_del_rcu(&exec->list);
			free_executor(exec);
		}
	}
	spin_unlock_irqrestore(&isec->executors_lock, flags);
}

static struct security_hook_list data_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(task_to_inode, bpf_lsm_task_to_inode),
	LSM_HOOK_INIT(bprm_set_creds, bpf_lsm_bprm_set_creds),
	LSM_HOOK_INIT(task_free, bpf_lsm_task_free),
	LSM_HOOK_INIT(inode_alloc_security, bpf_lsm_inode_alloc_security),
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
