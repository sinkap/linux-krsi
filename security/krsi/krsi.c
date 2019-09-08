// SPDX-License-Identifier: GPL-2.0

#include <linux/lsm_hooks.h>

#include "krsi_init.h"

struct krsi_hook krsi_hooks_list[] = {
	#define KRSI_HOOK_INIT(TYPE, NAME, H, I) \
		[TYPE] = { \
			.h_type = TYPE, \
			.name = #NAME, \
		},
	#include "hooks.h"
	#undef KRSI_HOOK_INIT
};

static int krsi_process_execution(struct linux_binprm *bprm)
{
	return 0;
}

static struct security_hook_list krsi_hooks[] __lsm_ro_after_init = {
	#define KRSI_HOOK_INIT(T, N, HOOK, IMPL) LSM_HOOK_INIT(HOOK, IMPL),
	#include "hooks.h"
	#undef KRSI_HOOK_INIT
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
