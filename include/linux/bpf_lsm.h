/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright 2019 Google LLC.
 */

#ifndef _LINUX_BPF_LSM_H
#define _LINUX_BPF_LSM_H

#include <linux/bpf.h>

#ifdef CONFIG_SECURITY_BPF

const struct btf_type *bpf_lsm_type_by_idx(struct btf *btf, u32 offset);
const struct btf_member *bpf_lsm_head_by_idx(struct btf *btf, u32 idx);

#else /* !CONFIG_SECURITY_BPF */

static inline const struct btf_type *bpf_lsm_type_by_idx(
	struct btf *btf, u32 idx)
{
	return ERR_PTR(-EOPNOTSUPP);
}
static inline const struct btf_member *bpf_lsm_head_by_idx(
	struct btf *btf, u32 idx)
{
	return ERR_PTR(-EOPNOTSUPP);
}

#endif /* CONFIG_SECURITY_BPF */

#endif /* _LINUX_BPF_LSM_H */
