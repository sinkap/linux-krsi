// SPDX-License-Identifier: GPL-2.0

#include <linux/lsm_hooks.h>

static int krsi_process_execution(struct linux_binprm *bprm)
{
	return 0;
}

static struct security_hook_list krsi_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(bprm_check_security, krsi_process_execution),
};

static int __init krsi_init(void)
{
	security_add_hooks(krsi_hooks, ARRAY_SIZE(krsi_hooks), "krsi");
	pr_info("eBPF and LSM are friends now.\n");
	return 0;
}

DEFINE_LSM(krsi) = {
	.name = "krsi",
	.init = krsi_init,
};
