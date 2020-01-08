// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <linux/bpf_lsm.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/srcu.h>

#include "bpf_lsm.h"

#define SECURITY_LIST_HEAD(x) ((void *)&bpf_lsm_info.dynamic_hooks->heads + x)

static inline int validate_hlist_head(struct btf *btf,
				      const struct btf_member *member)
{
	const struct btf_type *t;

	t = btf_type_by_id(btf, member->type);
	if (unlikely(!t))
		return -EINVAL;

	if (BTF_INFO_KIND(t->info) != BTF_KIND_STRUCT)
		return -EINVAL;

	if (t->size != sizeof(struct hlist_head))
		return -EINVAL;

	return 0;
}

int bpf_lsm_verify_prog(const struct bpf_prog *prog)
{
	u32 num_hooks = btf_type_vlen(bpf_lsm_info.btf_hook_heads);
	u32 idx = prog->aux->lsm_hook_idx;
	struct bpf_verifier_log log = {};

	if (!prog->gpl_compatible) {
		bpf_log(&log,
			"LSM programs must have a GPL compatible license\n");
		return -EINVAL;
	}

	if (idx >= num_hooks) {
		bpf_log(&log, "lsm_hook_idx should be between 0 and %u\n",
			num_hooks - 1);
		return -EINVAL;
	}

	return 0;
}

/* Find the BTF representation of the security_hook_heads member for a member
 * with a given index in struct security_hook_heads.
 */
const struct btf_member *bpf_lsm_head_by_idx(struct btf *btf, u32 idx)
{
	const struct btf_member *member;
	int ret;

	if (idx >= btf_type_vlen(bpf_lsm_info.btf_hook_heads))
		return ERR_PTR(-EINVAL);

	member = btf_type_member(bpf_lsm_info.btf_hook_heads) + idx;
	ret = validate_hlist_head(btf, member);
	if (ret < 0)
		return ERR_PTR(ret);

	return member;
}

/* Given an index of a member in security_hook_heads return the
 * corresponding type for the LSM hook. The members of the union
 * security_list_options have the same name as the security_hook_heads which
 * is ensured by the LSM_HOOK_INIT macro defined in include/linux/lsm_hooks.h
 */
const struct btf_type *bpf_lsm_type_by_idx(struct btf *btf, u32 idx)
{
	const struct btf_member *member, *hook_head = NULL;
	const struct btf_type *t;
	u32 i;

	hook_head = bpf_lsm_head_by_idx(btf, idx);
	if (IS_ERR(hook_head))
		return ERR_PTR(PTR_ERR(hook_head));

	for_each_member(i, bpf_lsm_info.btf_hook_types, member) {
		if (hook_head->name_off == member->name_off) {
			t = btf_type_by_id(btf, member->type);
			if (unlikely(!t))
				return ERR_PTR(-EINVAL);

			if (!btf_type_is_ptr(t))
				return ERR_PTR(-EINVAL);

			t = btf_type_by_id(btf, t->type);
			if (unlikely(!t))
				return ERR_PTR(-EINVAL);
			return t;
		}
	}

	return ERR_PTR(-ESRCH);
}

static void *bpf_lsm_get_func_addr(struct security_hook_list *s,
				   const char *name)
{
	const struct btf_member *member;
	s32 i;

	for_each_member(i, bpf_lsm_info.btf_hook_types, member)
		if (!strncmp(btf_name_by_offset(btf_vmlinux, member->name_off),
			     name, strlen(name) + 1))
			return (void *)&s->hook + member->offset / 8;

	return ERR_PTR(-ESRCH);
}

static struct bpf_lsm_list *bpf_lsm_list_lookup(struct bpf_prog *prog)
{
	struct bpf_verifier_log bpf_log = {};
	u32 idx = prog->aux->lsm_hook_idx;
	const struct btf_member *head;
	struct bpf_lsm_list *list;
	int ret = 0;

	list = &bpf_lsm_info.hook_lists[idx];

	mutex_lock(&list->mutex);

	if (list->initialized)
		goto unlock;

	list->attach_type = prog->aux->attach_func_proto;

	ret = btf_distill_func_proto(&bpf_log, btf_vmlinux, list->attach_type,
				     prog->aux->attach_func_name,
				     &list->func_model);
	if (ret)
		goto unlock;

	head = bpf_lsm_head_by_idx(btf_vmlinux, idx);
	if (IS_ERR(head)) {
		ret = PTR_ERR(head);
		goto unlock;
	}

	list->security_list_head = SECURITY_LIST_HEAD(head->offset / 8);
	list->initialized = true;
unlock:
	mutex_unlock(&list->mutex);
	if (ret)
		return ERR_PTR(ret);
	return list;
}

static struct bpf_lsm_hook *bpf_lsm_hook_alloc(struct bpf_lsm_list *list,
					       struct bpf_prog *prog)
{
	struct bpf_lsm_hook *hook;
	void *image;
	int ret = 0;

	image = bpf_jit_alloc_exec(PAGE_SIZE);
	if (!image)
		return ERR_PTR(-ENOMEM);

	set_vm_flush_reset_perms(image);

	ret = arch_prepare_bpf_trampoline(image, image + PAGE_SIZE,
		&list->func_model, 0, &prog, 1, NULL, 0, NULL);
	if (ret < 0) {
		ret = -EINVAL;
		goto error;
	}

	/* First make the page read-only, and only then make it executable to
	 * prevent it from being W+X in between.
	 */
	set_memory_ro((unsigned long)image, 1);
	/* More checks can be done here to ensure that nothing was changed
	 * between arch_prepare_bpf_trampoline and set_memory_ro.
	 */
	set_memory_x((unsigned long)image, 1);

	hook = kzalloc(sizeof(struct bpf_lsm_hook), GFP_KERNEL);
	if (!hook) {
		ret = -ENOMEM;
		goto error;
	}

	hook->image = image;
	hook->prog = prog;
	bpf_prog_inc(prog);
	return hook;
error:
	bpf_jit_free_exec(image);
	return ERR_PTR(ret);
}

static void bpf_lsm_hook_free(struct bpf_lsm_hook *tr)
{
	if (!tr)
		return;

	if (tr->prog)
		bpf_prog_put(tr->prog);

	bpf_jit_free_exec(tr->image);
	kfree(tr);
}

int bpf_lsm_attach(struct bpf_prog *prog)
{
	struct bpf_lsm_hook *hook;
	struct bpf_lsm_list *list;
	void **addr;
	int ret = 0;

	/* Only CAP_MAC_ADMIN users are allowed to make changes to LSM hooks
	 */
	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;

	if (!bpf_lsm_info.initialized)
		return -EBUSY;

	list = bpf_lsm_list_lookup(prog);
	if (IS_ERR(list))
		return PTR_ERR(list);

	hook = bpf_lsm_hook_alloc(list, prog);
	if (IS_ERR(hook))
		return PTR_ERR(hook);

	hook->sec_hook.head = list->security_list_head;
	addr = bpf_lsm_get_func_addr(&hook->sec_hook,
				     prog->aux->attach_func_name);
	if (IS_ERR(addr)) {
		ret = PTR_ERR(addr);
		goto error;
	}

	*addr = hook->image;

	mutex_lock(&list->mutex);
	hlist_add_tail_rcu(&hook->sec_hook.list, hook->sec_hook.head);
	mutex_unlock(&list->mutex);
	return 0;

error:
	bpf_lsm_hook_free(hook);
	return ret;
}

int bpf_lsm_detach(struct bpf_prog *prog)
{
	struct security_hook_list *sec_hook;
	struct bpf_lsm_hook *hook = NULL;
	struct bpf_lsm_list *list;
	struct hlist_node *n;

	/* Only CAP_MAC_ADMIN users are allowed to make changes to LSM hooks
	 */
	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;

	if (!bpf_lsm_info.initialized)
		return -EBUSY;

	list = &bpf_lsm_info.hook_lists[prog->aux->lsm_hook_idx];

	mutex_lock(&list->mutex);
	hlist_for_each_entry_safe(sec_hook, n, list->security_list_head, list) {
		hook = container_of(sec_hook, struct bpf_lsm_hook, sec_hook);
		if (hook->prog == prog) {
			hlist_del_rcu(&hook->sec_hook.list);
			break;
		}
	}
	mutex_unlock(&list->mutex);
	/* call_rcu is not used directly as module_memfree cannot run from an
	 * softirq context. The best way would be to schedule this on a work
	 * queue.
	 */
	synchronize_srcu(bpf_lsm_info.dynamic_hooks->srcu);
	bpf_lsm_hook_free(hook);
	return 0;
}
