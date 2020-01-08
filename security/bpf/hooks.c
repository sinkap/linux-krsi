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

#define SECURITY_LIST_HEAD(off) ((void *)&bpf_lsm_hook_heads + off)

DEFINE_STATIC_SRCU(security_hook_srcu);

int bpf_lsm_srcu_read_lock(void)
{
	return srcu_read_lock(&security_hook_srcu);
}

void bpf_lsm_srcu_read_unlock(int idx)
{
	return srcu_read_unlock(&security_hook_srcu, idx);
}

static inline int validate_hlist_head(struct btf *btf, u32 type_id)
{
	s32 hlist_id;

	hlist_id = btf_find_by_name_kind(btf, "hlist_head", BTF_KIND_STRUCT);
	if (hlist_id < 0 || hlist_id != type_id)
		return -EINVAL;

	return 0;
}

/* Find the BTF representation of the security_hook_heads member for a member
 * with a given index in struct security_hook_heads.
 */
const struct btf_member *bpf_lsm_head_by_index(struct btf *btf, u32 index)
{
	const struct btf_member *member;
	u32 off, i;
	int ret;

	for_each_member(i, bpf_lsm_info.btf_hook_heads, member) {
		/* We've found the id requested and need to check the
		 * the following:
		 *
		 * - Is it at a valid alignment for struct hlist_head?
		 *
		 * - Is it a valid hlist_head struct?
		 */
		if (index == i) {
			off = btf_member_bit_offset(
				bpf_lsm_info.btf_hook_heads, member);
			if (off % 8)
				/* valid c code cannot generate such btf */
				return ERR_PTR(-EINVAL);
			off /= 8;

			if (off % __alignof__(struct hlist_head))
				return ERR_PTR(-EINVAL);

			ret = validate_hlist_head(btf, member->type);
			if (ret < 0)
				return ERR_PTR(ret);

			return member;
		}
	}

	return ERR_PTR(-ENOENT);
}

/* Given an index of a member in security_hook_heads return the
 * corresponding type for the LSM hook. The members of the union
 * security_list_options have the same name as the security_hook_heads which
 * is ensured by the LSM_HOOK_INIT macro defined in include/linux/lsm_hooks.h
 */
const struct btf_type *bpf_lsm_type_by_index(struct btf *btf, u32 index)
{
	const struct btf_member *member, *hook_head = NULL;
	const struct btf_type *t, *hook_type = NULL;
	u32 i;

	hook_head = bpf_lsm_head_by_index(btf, index);
	if (IS_ERR(hook_head))
		return ERR_PTR(PTR_ERR(hook_head));

	for_each_member(i, bpf_lsm_info.btf_hook_types, member) {
		if (hook_head->name_off == member->name_off) {
			/* There should be only one member with the same name
			 * as the LSM hook. This should never really happen
			 * and either indicates malformed BTF or someone trying
			 * trick the LSM.
			 */
			if (WARN_ON(hook_type))
				return ERR_PTR(-EINVAL);

			hook_type = btf_type_by_id(btf, member->type);
			if (unlikely(!hook_type))
				return ERR_PTR(-EINVAL);

			if (!btf_type_is_ptr(hook_type))
				return ERR_PTR(-EINVAL);
		}
	}

	if (!hook_type)
		return ERR_PTR(-ENOENT);

	t = btf_type_by_id(btf, hook_type->type);
	if (unlikely(!t))
		return ERR_PTR(-EINVAL);

	return t;
}

/* This can be made much simpler by either of the following:
 *
 *	- Assume that the offset will always be 0 as security_list_options
 *	  is a union!
 *	- Add a new member to the union eg. bpf_lsm_callback and use its offset.
 */
static void *bpf_lsm_get_func_addr(struct security_hook_list *s,
				   const char *name)
{
	const struct btf_member *member;
	void *addr = NULL;
	s32 i;

	for_each_member(i, bpf_lsm_info.btf_hook_types, member) {
		if (!strncmp(btf_name_by_offset(btf_vmlinux, member->name_off),
				name, strlen(name) + 1)) {
			/* There should be only one member with the same name
			 * as the LSM hook.
			 */
			if (WARN_ON(addr))
				return ERR_PTR(-EINVAL);
			addr = (void *)&s->hook + member->offset;
		}
	}

	if (!addr)
		return ERR_PTR(-ENOENT);
	return addr;
}

static struct bpf_lsm_list *bpf_lsm_list_lookup(struct bpf_prog *prog)
{
	struct bpf_verifier_log bpf_log = {};
	const struct btf_member *head;
	struct bpf_lsm_list *list;
	int ret = 0;

	if (prog->aux->attach_btf_id >= bpf_lsm_info.num_hooks)
		return ERR_PTR(-EINVAL);

	list = &bpf_lsm_info.hook_lists[prog->aux->attach_btf_id];

	mutex_lock(&list->mutex);

	if (list->initialized)
		goto unlock;

	list->attach_type = prog->aux->attach_func_proto;

	ret = btf_distill_func_proto(&bpf_log, btf_vmlinux, list->attach_type,
				     prog->aux->attach_func_name,
				     &list->func_model);
	if (ret)
		goto unlock;

	head = bpf_lsm_head_by_index(btf_vmlinux, prog->aux->attach_btf_id);
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

static struct bpf_lsm_hook *bpf_lsm_hook_alloc(
	struct bpf_lsm_list *list, struct bpf_prog *prog)
{
	struct bpf_lsm_hook *hook;
	void *image;
	int ret = 0;

	image = bpf_jit_alloc_exec(PAGE_SIZE);
	if (!image)
		return ERR_PTR(-ENOMEM);

	set_vm_flush_reset_perms(image);

	ret = arch_prepare_bpf_trampoline(image,
		&list->func_model, 0, &prog, 1, NULL, 0, NULL);
	if (ret < 0) {
		ret = -EINVAL;
		goto error;
	}

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

	/*
	 * Only CAP_MAC_ADMIN users are allowed to make changes to LSM hooks
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

	/*
	 * Only CAP_MAC_ADMIN users are allowed to make changes to LSM hooks
	 */
	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;

	if (!bpf_lsm_info.initialized)
		return -EBUSY;

	if (prog->aux->attach_btf_id >= bpf_lsm_info.num_hooks)
		return -EINVAL;

	list = &bpf_lsm_info.hook_lists[prog->aux->attach_btf_id];

	mutex_lock(&list->mutex);
	hlist_for_each_entry(sec_hook, list->security_list_head, list) {
		hook = container_of(sec_hook, struct bpf_lsm_hook, sec_hook);
		if (hook->prog == prog) {
			hlist_del_rcu(&hook->sec_hook.list);
			break;
		}
	}
	mutex_unlock(&list->mutex);
	/* call_rcu is not used directly as module_memfree cannot run from an
	 * interrupt context. The best way is to schedule this on a work queue.
	 */
	synchronize_srcu(&security_hook_srcu);
	bpf_lsm_hook_free(hook);
	return 0;
}
