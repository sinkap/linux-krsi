/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_BPF_LSM_H
#define _LINUX_BPF_LSM_H

#include <linux/bpf.h>

#ifdef CONFIG_SECURITY_BPF
extern int bpf_lsm_fs_initialized;
int bpf_lsm_attach(const union bpf_attr *attr, struct bpf_prog *prog);
int bpf_lsm_detach(const union bpf_attr *attr);
#else
static inline int bpf_lsm_attach(const union bpf_attr *attr,
				 struct bpf_prog *prog)
{
	return -EINVAL;
}

static inline int bpf_lsm_detach(const union bpf_attr *attr)
{
	return -EINVAL;
}
#endif /* CONFIG_SECURITY_BPF */

#endif /* _LINUX_BPF_LSM_H */
