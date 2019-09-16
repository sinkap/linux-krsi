#include <linux/cred.h>
#include <linux/lsm_hooks.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/bpf.h>

#include "krsi_data.h"

static void krsi_task_to_inode(struct task_struct *t, struct inode *i)
{
	struct krsi_inode_data *data = get_krsi_inode_data(i);

	data->pid = get_task_pid(t, PIDTYPE_PID);
	if (!data->pid)
		pr_err("unable to determine pid in inode task hook\n");
}

static struct security_hook_list data_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(task_to_inode, krsi_task_to_inode),
};

struct lsm_blob_sizes krsi_blob_sizes __lsm_ro_after_init = {
	.lbs_inode = sizeof(struct krsi_inode_data),
};

int __init krsi_data_init(void)
{
	security_add_hooks(data_hooks, ARRAY_SIZE(data_hooks), "krsi");
	return 0;
}
