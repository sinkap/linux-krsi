// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf_lsm_event.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(u32));
} perf_map SEC(".maps");

#define _(P) (__builtin_preserve_access_index(P))

struct inode;

struct dentry {
	struct inode *d_inode;
};

struct args {
	struct inode *inode;
	struct dentry *dentry;
};

SEC("lsm/inode_unlink")
int detect_exec_unlink(struct args *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct dentry *dentry = ctx->dentry;
	struct unlink_event event = {
		.header = {
			.magic = BPF_LSM_MAGIC,
			.type = LSM_DETECT_EXEC_UNLINK,
		},

	};

	event.pid = __UPPER(pid_tgid);
	event.type  = bpf_lsm_is_executable_unlink(_(dentry->d_inode));

	if (event.type)
		bpf_lsm_event_output(&perf_map, BPF_F_CURRENT_CPU, &event,
				     sizeof(struct unlink_event));
	return 0;
}

char _license[] SEC("license") = "GPL";
