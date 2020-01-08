// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <linux/bpf_lsm.h>
#include <linux/lsm_hooks.h>

#include "bpf_lsm.h"

/* This is only for internal hooks, always statically shipped as part of the
 * BPF LSM. Statically defined hooks are appended to the security_hook_heads
 * which is common for LSMs and R/O after init.
 */
static struct security_hook_list bpf_lsm_hooks[] __lsm_ro_after_init = {};

/* Security hooks registered dynamically by the BPF LSM and must be accessed
 * by holding bpf_lsm_srcu_read_lock and bpf_lsm_srcu_read_unlock. The mutable
 * hooks dynamically allocated by the BPF LSM are appeneded here.
 */
struct security_hook_heads bpf_lsm_hook_heads;

struct bpf_lsm_info bpf_lsm_info;

static __init int bpf_lsm_info_init(void)
{
	int type_id;
	u32 num_hooks;
	int i;

	if (!btf_vmlinux)
		/* No need to grab any locks because we are still in init */
		btf_vmlinux = btf_parse_vmlinux();

	if (IS_ERR(btf_vmlinux)) {
		pr_err("btf_vmlinux is malformed\n");
		return PTR_ERR(btf_vmlinux);
	}

	type_id = btf_find_by_name_kind(btf_vmlinux, "security_hook_heads",
					BTF_KIND_STRUCT);
	if (WARN_ON(type_id < 0))
		return type_id;

	bpf_lsm_info.btf_hook_heads = btf_type_by_id(btf_vmlinux, type_id);
	num_hooks = btf_type_vlen(bpf_lsm_info.btf_hook_heads);

	type_id = btf_find_by_name_kind(btf_vmlinux, "security_list_options",
					BTF_KIND_UNION);
	if (WARN_ON(type_id < 0))
		return type_id;

	bpf_lsm_info.btf_hook_types = btf_type_by_id(btf_vmlinux, type_id);
	bpf_lsm_info.hook_lists = kcalloc(num_hooks,
					  sizeof(struct bpf_lsm_list),
					  GFP_KERNEL);
	if (!bpf_lsm_info.hook_lists)
		return -ENOMEM;

	/* The mutex needs to be initialized at init as it must be held
	 * when mutating the list. The rest of the information in the list
	 * is populated lazily when the first LSM hook callback is appeneded
	 * to the list.
	 */
	for (i = 0; i < num_hooks; i++)
		mutex_init(&bpf_lsm_info.hook_lists[i].mutex);

	bpf_lsm_info.initialized = true;
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
};
