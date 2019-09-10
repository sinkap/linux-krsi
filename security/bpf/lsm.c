// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <linux/lsm_hooks.h>

static int process_execution(struct linux_binprm *bprm)
{
	return 0;
}

static struct security_hook_list lsm_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(bprm_check_security, process_execution),
};

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
