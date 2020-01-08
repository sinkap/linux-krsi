// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <linux/bpf_lsm.h>
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
