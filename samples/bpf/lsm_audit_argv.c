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

struct linux_binprm;

struct args {
	struct linux_binprm *bprm;
};

SEC("lsm/bprm_check_security")
int arg_dumper(struct args *ctx)
{
	struct lsm_event_header header = {
		.magic = BPF_LSM_MAGIC,
		.type = LSM_AUDIT_ARGS,
	};

	bpf_lsm_output_argv(ctx->bprm, &perf_map, BPF_F_CURRENT_CPU, &header,
			    sizeof(struct lsm_event_header));

	return 0;
}

char _license[] SEC("license") = "GPL";
