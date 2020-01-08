// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <linux/lsm_hooks.h>

/* This is only for internal hooks, always statically shipped as part of the
 * BPF LSM. Statically defined hooks are appended to the security_hook_heads
 * which is common for LSMs and R/O after init.
 */
static struct security_hook_list bpf_lsm_hooks[] __lsm_ro_after_init = {};

/* eBPF programs that implement security hooks are attached here.
 */
DYNAMIC_HOOKS_INIT(bpf_lsm_dynamic_hooks);

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
