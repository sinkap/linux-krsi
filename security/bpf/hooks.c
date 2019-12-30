// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <linux/bpf_lsm.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/srcu.h>

extern struct btf *btf_vmlinux;

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
