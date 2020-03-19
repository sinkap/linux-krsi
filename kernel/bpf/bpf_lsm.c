// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2020 Google LLC.
 */

#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/lsm_hooks.h>
#include <linux/bpf_lsm.h>
#include <linux/jump_label.h>
#include <linux/kallsyms.h>
#include <linux/bpf_verifier.h>

/* For every LSM hook  that allows attachment of BPF programs, declare a NOP
 * function where a BPF program can be attached as an fexit trampoline.
 */
#define LSM_HOOK(RET, NAME, ...) LSM_HOOK_##RET(NAME, __VA_ARGS__)

#define LSM_HOOK_int(NAME, ...)			\
noinline __weak int bpf_lsm_##NAME(__VA_ARGS__)	\
{						\
	return 0;				\
}

#define LSM_HOOK_void(NAME, ...) \
noinline __weak void bpf_lsm_##NAME(__VA_ARGS__) {}

#include <linux/lsm_hook_names.h>
#undef LSM_HOOK

#define BPF_LSM_SYM_PREFX  "bpf_lsm_"

int bpf_lsm_verify_prog(struct bpf_verifier_log *vlog,
			const struct bpf_prog *prog)
{
	/* Only CAP_MAC_ADMIN users are allowed to make changes to LSM hooks
	 */
	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;

	if (!prog->gpl_compatible) {
		bpf_log(vlog,
			"LSM programs must have a GPL compatible license\n");
		return -EINVAL;
	}

	if (strncmp(BPF_LSM_SYM_PREFX, prog->aux->attach_func_name,
		    strlen(BPF_LSM_SYM_PREFX))) {
		bpf_log(vlog, "attach_btf_id %u points to wrong type name %s\n",
			prog->aux->attach_btf_id, prog->aux->attach_func_name);
		return -EINVAL;
	}

	return 0;
}

const struct bpf_prog_ops lsm_prog_ops = {
};

const struct bpf_verifier_ops lsm_verifier_ops = {
	.get_func_proto = bpf_tracing_func_proto,
	.is_valid_access = btf_ctx_access,
};
