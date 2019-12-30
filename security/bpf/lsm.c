// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <linux/bpf_lsm.h>
#include <linux/lsm_hooks.h>

static struct security_hook_list lsm_hooks[] __lsm_ro_after_init = {};

/* Security hooks registered dynamically by the BPF LSM and must be accessed
 * by holding bpf_lsm_srcu_read_lock and bpf_lsm_srcu_read_unlock.
 */
struct security_hook_heads bpf_lsm_hook_heads;

static int __init lsm_init(void)
{
	security_add_hooks(lsm_hooks, ARRAY_SIZE(lsm_hooks), "bpf");
	pr_info("eBPF and LSM are friends now.\n");
	return 0;
}

DEFINE_LSM(bpf) = {
	.name = "bpf",
	.init = lsm_init,
};
