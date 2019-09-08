/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _KRSI_FS_H
#define _KRSI_FS_H

#include <linux/bpf.h>
#include <linux/fs.h>
#include <linux/types.h>

bool is_krsi_hook_file(struct file *f);

/*
 * The name of the directory created in securityfs
 *
 *	/sys/kernel/security/<dir_name>
 */
#define KRSI_SFS_NAME "krsi"

#endif /* _KRSI_FS_H */
