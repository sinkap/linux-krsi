// SPDX-License-Identifier: GPL-2.0

#include <linux/lsm_hooks.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/binfmts.h>
#include <linux/highmem.h>
#include <linux/mm.h>

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

static int pin_arg_pages(struct krsi_bprm_ctx *ctx)
{
	int ret = 0;
	char *kaddr;
	struct page *page;
	unsigned long i, pos, num_arg_pages;
	struct linux_binprm *bprm = ctx->bprm;
	char *buf;

	/*
	 * The bprm->vma_pages does not have the correct count
	 * for execution that is done by a kernel thread using the UMH.
	 * vm_pages is updated in acct_arg_size and bails
	 * out if current->mm is NULL (which is the case for a kernel thread).
	 * It's safer to use vma_pages(struct linux_binprm*) to get the
	 * actual number
	 */
	num_arg_pages = vma_pages(bprm->vma);
	if (!num_arg_pages)
		return -ENOMEM;

	buf = kmalloc_array(num_arg_pages, PAGE_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	for (i = 0; i < num_arg_pages; i++) {
		pos = ALIGN_DOWN(bprm->p, PAGE_SIZE) + i * PAGE_SIZE;
		ret = get_user_pages_remote(current, bprm->mm, pos, 1,
					    FOLL_FORCE, &page, NULL, NULL);
		if (ret <= 0) {
			kfree(buf);
			return -ENOMEM;
		}

		kaddr = kmap(page);
		memcpy(buf + i * PAGE_SIZE, kaddr, PAGE_SIZE);
		kunmap(page);
		put_page(page);
	}

	ctx->arg_pages = buf;
	ctx->num_arg_pages = num_arg_pages;
	ctx->max_arg_offset = num_arg_pages * PAGE_SIZE;

	return 0;
}

static int krsi_process_execution(struct linux_binprm *bprm)
{
	int ret;
	struct krsi_ctx ctx;

	ctx.bprm_ctx = (struct krsi_bprm_ctx) {
		.bprm = bprm,
	};

	ret = pin_arg_pages(&ctx.bprm_ctx);
	if (ret < 0)
		goto out_arg_pages;

	ret = krsi_run_progs(PROCESS_EXECUTION, &ctx);
	kfree(ctx.bprm_ctx.arg_pages);

out_arg_pages:
	return ret;
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
