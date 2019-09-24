// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <uapi/linux/errno.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf_lsm_event.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct procfs_event));
	__uint(max_entries, 1);
} procfs_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(u32));
} perf_map SEC(".maps");

struct args {
	struct file *file;
};

SEC("lsm/file_open")
int procfs_audit(struct args *ctx)
{
	__u64 gid_uid = bpf_get_current_uid_gid();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct procfs_event *pfs;
	u32 ret, map_id = 0;
	char *map_value;

	pfs = bpf_map_lookup_elem(&procfs_map, &map_id);
	if (!pfs)
		return -ENOMEM;

	ret = bpf_lsm_is_procfs_file_op(ctx->file, pfs->filename,
					PROCFS_FILENAME_MAX_LEN, 1);
	if (ret < 0)
		return ret;

	if (ret) {
		pfs->uid = __LOWER(gid_uid);
		pfs->gid = __UPPER(gid_uid);
		pfs->pid = __UPPER(pid_tgid);
		pfs->file_pid = ret;

		bpf_lsm_event_output(&perf_map, BPF_F_CURRENT_CPU, pfs,
				     sizeof(struct procfs_event));
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
