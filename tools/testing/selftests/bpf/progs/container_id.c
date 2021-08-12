// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2020 Google LLC.
 */

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

#define OVERLAYFS_SUPER_MAGIC 0x794c7630
extern const void init_pid_ns __ksym;

struct task_blob {
	int is_container;
	int container_id;
};

__u64 global_container_id = 1;

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_blob);
} task_storage_map SEC(".maps");

static inline bool is_overlayfs_mounted(struct file *file)
{
	struct super_block *mnt_sb;
	struct vfsmount *mnt;

	mnt = file->f_path.mnt;
	if (mnt == NULL)
		return false;

	mnt_sb = mnt->mnt_sb;
	if (mnt_sb == NULL)
		return false;

	if (mnt_sb->s_magic != OVERLAYFS_SUPER_MAGIC) {
		return false;
	}

	return true;
}

static inline int is_init_pid_ns(struct pid *pid) 
{
	struct pid_namespace *ns;
	struct upid *up;
	
	up = &pid->numbers[pid->level];
	ns = BPF_CORE_READ(up, ns); 

	if (ns == &init_pid_ns)
		return 1;

	return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(alloc, struct task_struct *task, unsigned long clone_flags)
{
	struct task_blob *cur_tsec, *new_tsec;

	cur_tsec = bpf_task_storage_get(&task_storage_map,
					bpf_get_current_task_btf(), 0,
					BPF_LOCAL_STORAGE_GET_F_CREATE);

	if (cur_tsec && cur_tsec->is_container) {
		new_tsec = bpf_task_storage_get(&task_storage_map, task, 0,
						BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (!new_tsec)
			return 0;

		new_tsec->is_container = 1;
		new_tsec->container_id = cur_tsec->container_id;
	}

	return 0;
}

SEC("lsm/bprm_committed_creds")
void BPF_PROG(exec, struct linux_binprm *bprm)
{
	struct task_struct *current = bpf_get_current_task_btf();
	struct task_blob *tsec;
	int is_init;

	char fmt[] = "exec inherited=%d container_id=%d cmd=%s";

	// We are already in a container. Just log the execution.
	tsec = bpf_task_storage_get(&task_storage_map, current, 0, 0);
	if (tsec && tsec->is_container) {
		bpf_trace_printk(fmt, sizeof(fmt), 1, tsec->container_id,
				 bprm->file->f_path.dentry->d_name.name);
		return;
	}

	// Check if the process is not in the init namespace.
	if (!is_init_pid_ns(current->thread_pid) &&
	    is_overlayfs_mounted(bprm->file)) {
		tsec = bpf_task_storage_get(&task_storage_map, current, 0,
					    BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (tsec) {
			tsec->is_container = 1;
			tsec->container_id =
				__sync_fetch_and_add(&global_container_id, 1);

			bpf_trace_printk(
				fmt, sizeof(fmt), 0, tsec->container_id,
				bprm->file->f_path.dentry->d_name.name);
		}
	}
}
