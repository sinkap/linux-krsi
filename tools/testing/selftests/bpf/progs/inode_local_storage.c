// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2020 Google LLC.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include  <errno.h>

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;

#define DUMMY_STORAGE_VALUE 0xdeadbeef

int monitored_pid = 0;
bool test_result = false;

struct inode_storage {
	__u32 value;
};

struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct inode_storage);
} inode_storage_map SEC(".maps");

SEC("lsm/inode_unlink")
int BPF_PROG(unlink_hook, struct inode *dir, struct dentry *victim)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct inode_storage *storage;

	if (pid != monitored_pid)
		return 0;

	storage = bpf_inode_storage_get(&inode_storage_map, victim->d_inode, 0,
				     BPF_SK_STORAGE_GET_F_CREATE);
	if (!storage)
		return 0;

	if (storage->value == DUMMY_STORAGE_VALUE)
		test_result = true;

	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(test_int_hook, struct file *file)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct inode_storage *storage;

	if (pid != monitored_pid)
		return 0;

	if (!file->f_inode)
		return 0;

	storage = bpf_inode_storage_get(&inode_storage_map, file->f_inode, 0,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!storage)
		return 0;

	storage->value = DUMMY_STORAGE_VALUE;
	return 0;
}
