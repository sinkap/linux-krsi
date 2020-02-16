// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/bpf_lsm.h>
#include <linux/jump_label.h>
#include <linux/kallsyms.h>

#define LSM_HOOK(RET, NAME, ...)					\
	DEFINE_STATIC_KEY_FALSE(bpf_lsm_key_##NAME);			\
	void bpf_lsm_##NAME##_set_enabled(bool value)			\
	{								\
		if (value)						\
			static_branch_enable(&bpf_lsm_key_##NAME);	\
		else							\
			static_branch_disable(&bpf_lsm_key_##NAME);	\
	}
#include <linux/lsm_hook_names.h>
#undef LSM_HOOK

/* For every LSM hook  that allows attachment of BPF programs, declare a NOP
 * function where a BPF program can be attached as an fexit trampoline.
 */
#define LSM_HOOK(RET, NAME, ...) LSM_HOOK_##RET(NAME, __VA_ARGS__)
#define LSM_HOOK_int(NAME, ...) noinline int bpf_lsm_##NAME(__VA_ARGS__)  \
{									  \
	return 0;							  \
}

#define LSM_HOOK_void(NAME, ...) \
	noinline void bpf_lsm_##NAME(__VA_ARGS__) {}

#include <linux/lsm_hook_names.h>
#undef LSM_HOOK

int bpf_lsm_set_enabled(const char *name, bool value)
{
	char toggle_fn_name[KSYM_NAME_LEN];
	void (*toggle_fn)(bool value);

	snprintf(toggle_fn_name, KSYM_NAME_LEN, "%s_set_enabled", name);
	toggle_fn = (void *)kallsyms_lookup_name(toggle_fn_name);
	if (!toggle_fn)
		return -ESRCH;

	toggle_fn(value);
	return 0;
}

const struct bpf_prog_ops lsm_prog_ops = {
};

const struct bpf_verifier_ops lsm_verifier_ops = {
	.get_func_proto = bpf_tracing_func_proto,
	.is_valid_access = btf_ctx_access,
};
