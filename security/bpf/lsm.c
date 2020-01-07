// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <linux/lsm_hooks.h>

#include "bpf_lsm.h"

/* This is only for internal hooks, always statically shipped as part of the
 * BPF LSM. Statically defined hooks are appended to the security_hook_heads
 * which is common for LSMs and R/O after init.
 */
static struct security_hook_list bpf_lsm_hooks[] __lsm_ro_after_init = {};

/* eBPF programs that implement security hooks are attached here.
 */
DYNAMIC_HOOKS_INIT(bpf_lsm_dynamic_hooks);

struct bpf_lsm_info bpf_lsm_info;

static __init int bpf_lsm_info_init(void)
{
	const struct btf_type *t;

	if (!btf_vmlinux)
		/* No need to grab any locks because we are still in init */
		btf_vmlinux = btf_parse_vmlinux();

	if (IS_ERR(btf_vmlinux)) {
		pr_err("btf_vmlinux is malformed\n");
		return PTR_ERR(btf_vmlinux);
	}

	t = btf_type_by_name_kind(btf_vmlinux, "security_hook_heads",
				  BTF_KIND_STRUCT);
	if (WARN_ON(IS_ERR(t)))
		return PTR_ERR(t);

	bpf_lsm_info.btf_hook_heads = t;

	t = btf_type_by_name_kind(btf_vmlinux, "security_list_options",
				  BTF_KIND_UNION);
	if (WARN_ON(IS_ERR(t)))
		return PTR_ERR(t);

	bpf_lsm_info.btf_hook_types = t;
	return 0;
}

late_initcall(bpf_lsm_info_init);

static int __init bpf_lsm_init(void)
{
	security_add_hooks(bpf_lsm_hooks, ARRAY_SIZE(bpf_lsm_hooks), "bpf");
	pr_info("LSM support for eBPF active\n");
	return 0;
}

DEFINE_LSM(bpf) = {
	.name = "bpf",
	.init = bpf_lsm_init,
	.order = LSM_ORDER_LAST,
	.dynamic_hook_heads = &bpf_lsm_dynamic_hooks,
};
