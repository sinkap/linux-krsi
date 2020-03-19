// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2020 Google LLC.
 */

#include <linux/bpf.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include  <errno.h>
#include "lsm_helpers.h"

char _license[] SEC("license") = "GPL";

struct lsm_prog_result result = {
	.monitored_pid = 0,
	.count = 0,
};

/*
 * Define some of the structs used in the BPF program.
 * Only the field names and their sizes need to be the
 * same as the kernel type, the order is irrelevant.
 */
struct linux_binprm {
	const char *filename;
} __attribute__((preserve_access_index));

SEC("lsm/bprm_committed_creds")
int BPF_PROG(test_void_hook, struct linux_binprm *bprm)
{
	__u32 pid = bpf_get_current_pid_tgid();
	char fmt[] = "lsm(bprm_committed_creds): process executed %s\n";

	bpf_trace_printk(fmt, sizeof(fmt), bprm->filename);
	if (result.monitored_pid == pid)
		result.count++;

	return 0;
}
