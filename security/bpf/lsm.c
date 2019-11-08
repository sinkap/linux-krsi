// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <linux/lsm_hooks.h>
#include <linux/bpf_lsm.h>

#include "bpf_lsm.h"

/*
 * Run the eBPF programs of the hook indexed by the type t with the arguments
 * packed into an array of u64 integers as the context.
 */
static inline int __run_progs(enum lsm_hook_type t, u64 *args)
{
	struct bpf_lsm_hook *h = &bpf_lsm_hooks_list[t];
	struct bpf_prog_array_item *item;
	struct bpf_prog_array *array;
	int ret, retval = 0;

	/*
	 * Some hooks might get called before the securityFS is initialized,
	 * this will result in a NULL pointer exception.
	 */
	if (!bpf_lsm_fs_initialized)
		return 0;

	preempt_disable();
	rcu_read_lock();

	array = rcu_dereference(h->progs);
	if (!array)
		goto out;

	for (item = array->items; item->prog; item++) {
		ret = BPF_PROG_RUN(item->prog, args);
		if (ret < 0) {
			retval = ret;
			break;
		}
	}
out:
	rcu_read_unlock();
	preempt_enable();
	return IS_ENABLED(CONFIG_SECURITY_BPF_ENFORCE) ? retval : 0;
}

/*
 * This macro creates a bpf_lsm_run_progs_<x> function which accepts a known
 * number of arguments and packs them into an array of u64 integers. The array
 * is used as a context to run the BPF programs attached to the hook.
 */
#define DEFINE_LSM_RUN_PROGS_x(x)					\
	static int bpf_lsm_run_progs##x(enum lsm_hook_type t,		\
				 REPEAT(x, SARG, __DL_COM, __SEQ_0_11))	\
	{								\
		u64 args[x];						\
		REPEAT(x, COPY, __DL_SEM, __SEQ_0_11);			\
		return __run_progs(t, args);				\
	}

/*
 * There are some hooks that have no arguments, so there's nothing to pack and
 * the attached BPF programs get a NULL context.
 */
int bpf_lsm_run_progs0(enum lsm_hook_type t, u64 args)
{
	return __run_progs(t, NULL);
}

/*
 * The largest number of args accepted by an LSM hook is currently 6. Define
 * bpf_lsm_run_progs_1 to bpf_lsm_run_progs_6.
 */
DEFINE_LSM_RUN_PROGS_x(1);
DEFINE_LSM_RUN_PROGS_x(2);
DEFINE_LSM_RUN_PROGS_x(3);
DEFINE_LSM_RUN_PROGS_x(4);
DEFINE_LSM_RUN_PROGS_x(5);
DEFINE_LSM_RUN_PROGS_x(6);

/*
 * This macro calls one of the bpf_lsm_args_<x> functions based on the number of
 * arguments of the variadic macro. Each argument is casted to a u64 bit integer
 * as expected by BTF.
 */
#define LSM_RUN_PROGS(T, args...) \
	CONCATENATE(bpf_lsm_run_progs, COUNT_ARGS(args))(T, CAST_TO_U64(args))

/*
 * The hooks can have an int or void return type, these macros allow having a
 * single implementation of DEFINE_LSM_HOOK irrespective of the return type.
 */
#define LSM_HOOK_RET(ret, x) LSM_HOOK_RET_##ret(x)
#define LSM_HOOK_RET_int(x) x
#define LSM_HOOK_RET_void(x)

/*
 * This macro defines the body of a LSM hook which runs the eBPF programs that
 * are attached to the hook and returns the error code from the eBPF programs if
 * the return type of the hook is int.
 */
#define DEFINE_LSM_HOOK(hook, ret, proto, args)				\
typedef ret (*lsm_btf_##hook)(proto);					\
static ret bpf_lsm_##hook(proto)					\
{									\
	return LSM_HOOK_RET(ret, LSM_RUN_PROGS(hook##_type, args));	\
}

/*
 * Define the body of each of the LSM hooks defined in hooks.h.
 */
#define BPF_LSM_HOOK(hook, ret, args, proto) \
	DEFINE_LSM_HOOK(hook, ret, BPF_LSM_ARGS(args), BPF_LSM_ARGS(proto))
#include "hooks.h"
#undef BPF_LSM_HOOK
#undef DEFINE_LSM_HOOK

/*
 * Initialize the bpf_lsm_hooks_list for each of the hooks defined in hooks.h.
 * The list contains information for each of the hook and can be indexed by the
 * its type to initialize security FS, attach, detach and execute eBPF programs
 * for the hook.
 */
struct bpf_lsm_hook bpf_lsm_hooks_list[] = {
	#define BPF_LSM_HOOK(h, ...)					\
		[h##_type] = {						\
			.h_type = h##_type,				\
			.mutex = __MUTEX_INITIALIZER(			\
				bpf_lsm_hooks_list[h##_type].mutex),	\
			.name = #h,					\
			.btf_hook_func =				\
				(void *)(lsm_btf_##h)(bpf_lsm_##h),	\
		},
	#include "hooks.h"
	#undef BPF_LSM_HOOK
};

/*
 * Initialize the bpf_lsm_hooks_list for each of the hooks defined in hooks.h.
 */
static struct security_hook_list lsm_hooks[] __lsm_ro_after_init = {
	#define BPF_LSM_HOOK(h, ...) LSM_HOOK_INIT(h, bpf_lsm_##h),
	#include "hooks.h"
	#undef BPF_LSM_HOOK
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
