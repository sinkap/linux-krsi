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

extern struct btf *btf_vmlinux;

DEFINE_STATIC_SRCU(security_hook_srcu);

/* There are ~200 LSM hooks */
#define BPF_LSM_HASH_BITS 8
#define BPF_LSM_HT_SIZE  (1 << BPF_LSM_HASH_BITS)

static struct bpf_lsm_list hash_table[BPF_LSM_HT_SIZE];

#define BPF_LSM_HT_ENTRY(off) (&hash_table[hash_64(off, BPF_LSM_HASH_BITS)])
#define SECURITY_LIST_HEAD(off) ((void *)&bpf_lsm_hook_heads + off)

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
	const struct btf_type *t;

	t = btf_type_by_id(btf, type_id);
	if (!t)
		return -ENOENT;

	if (t->size != sizeof(struct hlist_head))
		return -EINVAL;

	if (strncmp(btf_name_by_offset(btf, t->name_off),
		     "hlist_head", 11))
		return -EINVAL;

	return 0;
}

static const struct btf_member *security_head_by_offset(
		struct btf *btf, u32 offset)
{
	const struct btf_member *member, *hook_head = NULL;
	const struct btf_type *t;
	s32 type_id;
	u32 off, i;
	int ret;

	type_id = btf_find_by_name_kind(btf, "security_hook_heads",
					BTF_KIND_STRUCT);
	if (type_id < 0) {
		pr_err("Cannot find BTF type info for security_hook_heads\n");
		return ERR_PTR(-EINVAL);
	}

	t = btf_type_by_id(btf, type_id);

	for_each_member(i, t, member) {
		off = btf_member_bit_offset(t, member);
		if (off % 8)
			/* valid C code cannot generate such BTF */
			return ERR_PTR(-EINVAL);
		off /= 8;

		/* We've found the offset requested and need to check the
		 * the following:
		 *
		 * - Are there multiple types at the same offset? This should
		 *   never happen in a vailid security_hook_heads struct.
		 *
		 * - Is it at the valid alignment for struct hlist_head?
		 *
		 * - Is it a valid hlist_head struct?
		 */
		if (off == offset) {
			/* There should be only one member with the same name
			 * as the LSM hook.
			 */
			if (WARN_ON(hook_head))
				return ERR_PTR(-EINVAL);

			if (off % __alignof__(struct hlist_head))
				return ERR_PTR(-EINVAL);
			hook_head = member;

			ret = validate_hlist_head(btf, hook_head->type);
			if (ret < 0)
				return ERR_PTR(ret);
		}
	}

	if (!hook_head)
		return ERR_PTR(-ENOENT);

	return hook_head;
}

const char *bpf_lsm_name_by_offset(
	struct btf *btf, u32 offset)
{
	const struct btf_member *hook_head = NULL;

	hook_head = security_head_by_offset(btf, offset);
	if (IS_ERR(hook_head))
		return NULL;

	return btf_name_by_offset(btf_vmlinux, hook_head->name_off);
}

/* Given an offset of a member in security_hook_heads return the
 * corresponding func_proto for the LSM hook. The members of the union
 * security_list_options have the same name as the security_hook_heads which
 * is ensured by the LSM_HOOK_INIT macro defined in include/linux/lsm_hooks.h
 */
s32 bpf_lsm_type_by_offset(struct btf *btf, u32 offset)
{
	const struct btf_member *member, *hook_head = NULL;
	const struct btf_type *t, *hook_type = NULL;
	s32 type_id;
	u32 i;

	hook_head = security_head_by_offset(btf, offset);
	if (IS_ERR(hook_head))
		return PTR_ERR(hook_head);

	type_id = btf_find_by_name_kind(btf, "security_list_options",
					BTF_KIND_UNION);
	if (type_id < 0)
		return type_id;

	t = btf_type_by_id(btf, type_id);
	if (unlikely(!t))
		return -EINVAL;

	for_each_member(i, t, member) {
		if (hook_head->name_off == member->name_off) {
			/* There should be only one member with the same name
			 * as the LSM hook.
			 */
			if (WARN_ON(hook_type))
				return -EINVAL;
			hook_type = btf_type_by_id(btf, member->type);
			if (unlikely(!hook_type))
				return -EINVAL;

			if (!btf_type_is_ptr(hook_type))
				return -EINVAL;

		}
	}

	if (!hook_type)
		return -ENOENT;

	return hook_type->type;
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
	const struct btf_type *t;
	void *addr = NULL;
	s32 type_id, i;

	type_id = btf_find_by_name_kind(btf_vmlinux, "security_list_options",
					BTF_KIND_UNION);
	if (type_id < 0)
		return ERR_PTR(type_id);

	t = btf_type_by_id(btf_vmlinux, type_id);
	if (unlikely(!t))
		return ERR_PTR(-EINVAL);

	for_each_member(i, t, member) {
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
	struct bpf_lsm_list *list;
	int ret;

	list = BPF_LSM_HT_ENTRY(prog->aux->attach_btf_id);
	if (list->initialized)
		return list;

	list->name = prog->aux->attach_func_name;
	list->attach_type = prog->aux->attach_func_proto;
	mutex_init(&list->mutex);

	ret = btf_distill_func_proto(&bpf_log, btf_vmlinux, list->attach_type,
				     list->name, &list->func_model);
	if (ret)
		return ERR_PTR(ret);

	list->security_list_head = SECURITY_LIST_HEAD(prog->aux->attach_btf_id);
	list->initialized = true;
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
	set_memory_x((long)image, 1);

	ret = arch_prepare_bpf_trampoline(image,
		&list->func_model, 0, &prog, 1, NULL, 0, NULL);
	if (ret < 0) {
		ret = -EINVAL;
		goto error;
	}

	hook = kmalloc(sizeof(struct bpf_lsm_hook), GFP_KERNEL);
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
	if (tr)
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

	list = bpf_lsm_list_lookup(prog);
	if (IS_ERR(list))
		return PTR_ERR(list);

	/*
	 * Only CAP_MAC_ADMIN users are allowed to make changes to LSM hooks
	 */
	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;

	hook = bpf_lsm_hook_alloc(list, prog);
	if (IS_ERR(hook))
		return PTR_ERR(hook);

	hook->sec_hook.head = list->security_list_head;
	addr = bpf_lsm_get_func_addr(&hook->sec_hook, list->name);
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

void bpf_lsm_detach(struct bpf_prog *prog)
{
	struct security_hook_list *sec_hook;
	struct bpf_lsm_hook *hook = NULL;
	struct bpf_lsm_list *list;

	list = BPF_LSM_HT_ENTRY(prog->aux->attach_btf_id);
	mutex_lock(&list->mutex);
	hlist_for_each_entry(sec_hook, list->security_list_head, list) {
		hook = container_of(sec_hook, struct bpf_lsm_hook, sec_hook);
		if (hook->prog == prog) {
			hlist_del_rcu(&hook->sec_hook.list);
			break;
		}
	}
	mutex_unlock(&list->mutex);
	synchronize_srcu(&security_hook_srcu);
	bpf_lsm_hook_free(hook);
}
