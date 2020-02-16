// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/bpf_lsm.h>

/* For every LSM hook  that allows attachment of BPF programs, declare a NOP
 * function where a BPF program can be attached as an fexit trampoline.
 */
#define LSM_HOOK(RET, NAME, ...) LSM_HOOK_##RET(NAME, __VA_ARGS__)
#define LSM_HOOK_int(NAME, ...) __weak int bpf_lsm_##NAME(__VA_ARGS__)	\
{									\
	return 0;							\
}

#define LSM_HOOK_void(NAME, ...) __weak void bpf_lsm_##NAME(__VA_ARGS__) {}

#include <linux/lsm_hook_names.h>
#undef LSM_HOOK

const struct bpf_prog_ops lsm_prog_ops = {
};

const struct bpf_verifier_ops lsm_verifier_ops = {
	.get_func_proto = bpf_tracing_func_proto,
	.is_valid_access = btf_ctx_access,
};
