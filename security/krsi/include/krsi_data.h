/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __KRSI_DATA_H
#define __KRSI_DATA_H

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/lsm_hooks.h>
#include <linux/spinlock.h>

int krsi_data_init(void) __init;

extern struct lsm_blob_sizes krsi_blob_sizes __lsm_ro_after_init;

struct krsi_inode_data {
	struct pid *pid;
};

static inline struct krsi_inode_data *get_krsi_inode_data(
						const struct inode *inode)
{
	if (unlikely(!inode->i_security))
		return NULL;
	return inode->i_security + krsi_blob_sizes.lbs_inode;
}

#endif /* __KRSI_DATA_H */
