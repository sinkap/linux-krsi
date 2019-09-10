/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _KRSI_H
#define _KRSI_H

#include <linux/bpf.h>

#ifdef CONFIG_SECURITY_KRSI
int krsi_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog);
extern const struct bpf_func_proto krsi_get_env_var_proto;
#else
static inline int krsi_prog_attach(const union bpf_attr *attr,
				   struct bpf_prog *prog)
{
	return -EINVAL;
}
#endif /* CONFIG_SECURITY_KRSI */

#endif /* _KRSI_H */
