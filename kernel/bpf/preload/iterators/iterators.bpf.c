// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <sys/types.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
 #include <errno.h>


#define BPF_SECURITY 1
#define XATTR_SECURITY 2

 struct local_storage {
	int domain;
};

#define SECURITY_XATTR_NAME "security.domain"
#define XATTR_SETTER_DOMAIN "xset"
#define BPF_SECURITY_DOMAIN "bpf"

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct local_storage);
} task_storage_map SEC(".maps");

#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)

struct user_namespace;
struct vfsmount {
	struct user_namespace *mnt_userns;
};

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};
struct file {
	struct path f_path;
};

struct linux_binprm {
	struct file *file;
};

struct bpf_prog {
	enum bpf_prog_type type;
};

#pragma clang attribute pop

int enabled = 1;

SEC("lsm/task_alloc")
int BPF_PROG(s_task_alloc, struct task_struct *task, unsigned long clone_flags) 
{
	struct local_storage *storage, *new_storage;

	storage = bpf_task_storage_get(&task_storage_map,
				       bpf_get_current_task_btf(), 0, 0);

	if (!storage)
		return 0;

	if (!storage->domain)
		return 0;

	new_storage = bpf_task_storage_get(&task_storage_map, task, 0, 0);
	if (!new_storage)
		return 0;

	return 0;
}

SEC("lsm.s/inode_setxattr")
int BPF_PROG(s_xattr, struct user_namespace *mnt_userns,
	 struct dentry *dentry, const char *name, const void *value,
	 size_t size, int flags)
{
	struct local_storage *storage;

	storage = bpf_task_storage_get(&task_storage_map,
				       bpf_get_current_task_btf(), 0, 0);

	if (!storage || storage->domain != XATTR_SECURITY)
		goto err;

	return 0;
err:
	bpf_printk("would have been denied upon enforcement");
	return enabled ? -EPERM : 0;
}

SEC("lsm.s/bpf_prog")
int BPF_PROG(s_bpf, struct bpf_prog *prog)
{
	struct local_storage *storage;

	storage = bpf_task_storage_get(&task_storage_map,
				       bpf_get_current_task_btf(), 0, 0);

	if (!storage || storage->domain != BPF_SECURITY)
		goto err;

	return 0;
err:
	bpf_printk("would have been denied upon enforcement");
	return enabled ? -EPERM : 0;
}

SEC("lsm.s/bprm_committed_creds")
void BPF_PROG(bprm_exec, struct linux_binprm *bprm)
{
	int xattr_sz;
	struct local_storage *storage;
	char dir_xattr_value[256];

	xattr_sz = bpf_getxattr(bprm->file->f_path.mnt->mnt_userns,
				bprm->file->f_path.dentry, SECURITY_XATTR_NAME,
				dir_xattr_value, 256);

	if (xattr_sz  <= 0)
		return;

	storage = bpf_task_storage_get(&task_storage_map,
					 bpf_get_current_task_btf(), 0,
					 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!storage) 
		return;

	/* This is not one of the files contained by borglet */
	if (bpf_strncmp(dir_xattr_value, sizeof(XATTR_SETTER_DOMAIN), XATTR_SETTER_DOMAIN))
		storage->domain = XATTR_SECURITY;

	/* This is not one of the files contained by borglet */
	if (bpf_strncmp(dir_xattr_value, sizeof(BPF_SECURITY_DOMAIN),
			BPF_SECURITY_DOMAIN))
		storage->domain = BPF_SECURITY;
}

char LICENSE[] SEC("license") = "GPL";
