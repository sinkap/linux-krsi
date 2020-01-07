// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <linux/bpf_lsm.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/srcu.h>

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
	const struct btf_type *t;
	u32 off, i;
	int ret;

	t = btf_type_by_name_kind(btf, "security_hook_heads", BTF_KIND_STRUCT);
	if (WARN_ON_ONCE(IS_ERR(t)))
		return ERR_CAST(t);

	for_each_member(i, t, member) {
		/* We've found the id requested and need to check the
		 * the following:
		 *
		 * - Is it at a valid alignment for struct hlist_head?
		 *
		 * - Is it a valid hlist_head struct?
		 */
		if (index == i) {
			off = btf_member_bit_offset(t, member);
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

	t = btf_type_by_name_kind(btf, "security_list_options", BTF_KIND_UNION);
	if (WARN_ON_ONCE(IS_ERR(t)))
		return ERR_CAST(t);

	for_each_member(i, t, member) {
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
