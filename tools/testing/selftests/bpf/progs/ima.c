// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2020 Google LLC.
 */

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

u32 monitored_pid = 0;

struct buf_sample {
	u64 ima_hash;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12);
} ringbuf SEC(".maps");

char _license[] SEC("license") = "GPL";

SEC("lsm.s/bprm_committed_creds")
void BPF_PROG(ima, struct linux_binprm *bprm)
{

	struct buf_sample *sample;
	u64 ima_hash = 0;
	int ret;
	u32 pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid == monitored_pid) {
		ret = bpf_ima_inode_hash(bprm->file->f_inode, &ima_hash,
					 sizeof(ima_hash));
		if (ret < 0 || ima_hash == 0)
			return;

		sample = bpf_ringbuf_reserve(&ringbuf, sizeof(*sample), 0);
		if (!sample)
			return;

		sample->ima_hash = ima_hash;
		bpf_ringbuf_submit(sample, BPF_RB_FORCE_WAKEUP);
	}

	return;
}
