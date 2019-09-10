// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/btf.h>

BPF_CALL_4(bpf_lsm_event_output,
	   struct bpf_map *, map, u64, flags, void *, data, u64, size)
{
	if (unlikely(flags & ~(BPF_F_INDEX_MASK)))
		return -EINVAL;

	return bpf_event_output(map, flags, data, size, NULL, 0, NULL);
}

static const struct bpf_func_proto bpf_lsm_event_output_proto =  {
	.func		= bpf_lsm_event_output,
	.gpl_only       = true,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_CONST_MAP_PTR,
	.arg2_type      = ARG_ANYTHING,
	.arg3_type      = ARG_PTR_TO_MEM,
	.arg4_type      = ARG_CONST_SIZE_OR_ZERO,
};

static const struct bpf_func_proto *get_bpf_func_proto(enum bpf_func_id
		func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_get_current_pid_tgid:
		return &bpf_get_current_pid_tgid_proto;
	case BPF_FUNC_lsm_event_output:
		return &bpf_lsm_event_output_proto;
	default:
		return NULL;
	}
}

const struct bpf_prog_ops lsm_prog_ops = {
};

const struct bpf_verifier_ops lsm_verifier_ops = {
	.get_func_proto = get_bpf_func_proto,
	.is_valid_access = btf_ctx_access,
};
