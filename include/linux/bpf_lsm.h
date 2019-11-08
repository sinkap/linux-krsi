/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_BPF_LSM_H
#define _LINUX_BPF_LSM_H

#include <linux/bpf.h>

#ifdef CONFIG_SECURITY_BPF
extern int bpf_lsm_fs_initialized;
#endif /* CONFIG_SECURITY_BPF */

#endif /* _LINUX_BPF_LSM_H */
