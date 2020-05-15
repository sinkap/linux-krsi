// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2020 Google LLC.
 */

#include <errno.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;

#define DUMMY_STORAGE_VALUE 0xdeadbeef

int monitored_pid = 0;
bool inode_storage_result = false;
bool sk_storage_result = false;

struct dummy_storage {
	__u32 value;
};

struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct dummy_storage);
} inode_storage_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_CLONE);
	__type(key, int);
	__type(value, struct dummy_storage);
} sk_storage_map SEC(".maps");

/* Using vmlinux.h causes the generated BTF to be so big that the object
 * load fails at btf__load.
 */
struct sock {} __attribute__((preserve_access_index));
struct sockaddr {} __attribute__((preserve_access_index));
struct socket {
	struct sock *sk;
} __attribute__((preserve_access_index));

struct inode {} __attribute__((preserve_access_index));
struct dentry {
	struct inode *d_inode;
} __attribute__((preserve_access_index));
struct file {
	struct inode *f_inode;
} __attribute__((preserve_access_index));


SEC("lsm/inode_unlink")
int BPF_PROG(unlink_hook, struct inode *dir, struct dentry *victim)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct dummy_storage *storage;

	if (pid != monitored_pid)
		return 0;

	storage = bpf_inode_storage_get(&inode_storage_map, victim->d_inode, 0,
				     BPF_SK_STORAGE_GET_F_CREATE);
	if (!storage)
		return 0;

	if (storage->value == DUMMY_STORAGE_VALUE)
		inode_storage_result = true;

	return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(socket_bind, struct socket *sock, struct sockaddr *address,
	     int addrlen)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct dummy_storage *storage;

	if (pid != monitored_pid)
		return 0;

	storage = bpf_sk_storage_get(&sk_storage_map, sock->sk, 0,
				     BPF_SK_STORAGE_GET_F_CREATE);
	if (!storage)
		return 0;

	if (storage->value == DUMMY_STORAGE_VALUE)
		sk_storage_result = true;

	return 0;
}

SEC("lsm/socket_post_create")
int BPF_PROG(socket_post_create, struct socket *sock, int family, int type,
	     int protocol, int kern)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct dummy_storage *storage;

	if (pid != monitored_pid)
		return 0;

	storage = bpf_sk_storage_get(&sk_storage_map, sock->sk, 0,
				     BPF_SK_STORAGE_GET_F_CREATE);
	if (!storage)
		return 0;

	storage->value = DUMMY_STORAGE_VALUE;

	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(test_int_hook, struct file *file)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct dummy_storage *storage;

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
