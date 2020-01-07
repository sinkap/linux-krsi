// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <linux/bpf_lsm.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/srcu.h>

#include "bpf_lsm.h"

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
