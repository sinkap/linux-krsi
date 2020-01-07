/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _BPF_LSM_H
#define _BPF_LSM_H

#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/btf.h>

struct bpf_lsm_info {
	/* BTF type for security_hook_heads populated at init.
	 */
	const struct btf_type *btf_hook_heads;
	/* BTF type for security_list_options populated at init.
	 */
	const struct btf_type *btf_hook_types;
};

extern struct bpf_lsm_info bpf_lsm_info;

#endif /* _BPF_LSM_H */
