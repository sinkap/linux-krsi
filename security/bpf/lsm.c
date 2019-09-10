// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <linux/lsm_hooks.h>

static struct security_hook_list lsm_hooks[] __lsm_ro_after_init = {};

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
