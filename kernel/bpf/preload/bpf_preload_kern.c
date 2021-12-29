// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/init.h>
#include <linux/module.h>
#include "bpf_preload.h"
#include "iterators/iterators.lskel.h"

static struct bpf_link *talloc_link, *xattr_link, *bprm_link, *bpf_link;
static struct iterators_bpf *skel;

static void free_links_and_skel(void)
{
	if (!IS_ERR_OR_NULL(talloc_link))
		bpf_link_put(talloc_link);	
	if (!IS_ERR_OR_NULL(xattr_link))
		bpf_link_put(xattr_link);
	if (!IS_ERR_OR_NULL(bprm_link))
		bpf_link_put(bprm_link);
	if (!IS_ERR_OR_NULL(bpf_link))
		bpf_link_put(bpf_link);
	iterators_bpf__destroy(skel);
}

static int preload(struct bpf_preload_info *obj)
{
	strlcpy(obj[0].link_name, "s_task_alloc", sizeof(obj[0].link_name));
	obj[0].link = talloc_link;
	strlcpy(obj[0].link_name, "s_xattr", sizeof(obj[0].link_name));
	obj[0].link = xattr_link;
	strlcpy(obj[1].link_name, "s_bprm", sizeof(obj[1].link_name));
	obj[1].link = bprm_link;
	strlcpy(obj[1].link_name, "s_bpf", sizeof(obj[1].link_name));
	obj[2].link = bpf_link;
	return 0;
}

static struct bpf_preload_ops ops = {
	.preload = preload,
	.owner = THIS_MODULE,
};

static int load_skel(void)
{
	int err;

	skel = iterators_bpf__open();
	if (!skel)
		return -ENOMEM;

	err = iterators_bpf__load(skel);
	if (err)
		goto out;
	err = iterators_bpf__attach(skel);
	if (err)
		goto out;
	talloc_link = bpf_link_get_from_fd(skel->links.s_task_alloc_fd);
	if (IS_ERR(talloc_link)) {
		err = PTR_ERR(talloc_link);
		goto out;
	}
	xattr_link = bpf_link_get_from_fd(skel->links.s_xattr_fd);
	if (IS_ERR(xattr_link)) {
		err = PTR_ERR(xattr_link);
		goto out;
	}
	bprm_link = bpf_link_get_from_fd(skel->links.bprm_exec_fd);
	if (IS_ERR(bprm_link)) {
		err = PTR_ERR(bprm_link);
		goto out;
	}
	bpf_link = bpf_link_get_from_fd(skel->links.s_bpf_fd);
	if (IS_ERR(bpf_link)) {
		err = PTR_ERR(bpf_link);
		goto out;
	}


	/* Avoid taking over stdin/stdout/stderr of init process. Zeroing out
	 * makes skel_closenz() a no-op later in iterators_bpf__destroy().
	 */
	close_fd(skel->links.s_task_alloc_fd);
	skel->links.s_task_alloc_fd = 0;
	close_fd(skel->links.s_xattr_fd);
	skel->links.s_xattr_fd = 0;
	close_fd(skel->links.bprm_exec_fd);
	skel->links.bprm_exec_fd = 0;
	close_fd(skel->links.s_bpf_fd);
	skel->links.s_bpf_fd = 0;
	return 0;
out:
	free_links_and_skel();
	return err;
}

static int __init load(void)
{
	int err;

	err = load_skel();
	if (err)
		return err;
	bpf_preload_ops = &ops;
	return err;
}

static void __exit fini(void)
{
	bpf_preload_ops = NULL;
	free_links_and_skel();
}
late_initcall(load);
module_exit(fini);
MODULE_LICENSE("GPL");
