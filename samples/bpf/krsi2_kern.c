// SPDX-License-Identifier: GPL-2.0

#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/ip.h>
#include "bpf_helpers.h"
#include "krsi_audit.h"

#define MAX_CPUS 128

struct bpf_map_def SEC("maps") procfs_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct krsi_procfs),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") perf_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(u32),
	.max_entries = MAX_CPUS,
};

SEC("krsi/file_open")
int procfs_audit(void *ctx)
{
	u32 ret;
	u32 map_id = 0;
	char *map_value;
	struct krsi_procfs *pfs;
	__u64 gid_uid = bpf_get_current_uid_gid();
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	pfs = bpf_map_lookup_elem(&procfs_map, &map_id);
	if (!pfs)
		return -ENOMEM;

	ret = krsi_is_procfs_file_op(ctx, pfs->filename,
				     PROCFS_FILENAME_MAX_LEN, 1);
	if (ret < 0)
		return ret;

	if (ret) {
		pfs->uid = __LOWER(gid_uid);
		pfs->gid = __UPPER(gid_uid);
		pfs->pid = __UPPER(pid_tgid);
		pfs->file_pid = ret;

		bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, pfs,
				      sizeof(struct krsi_procfs));
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
