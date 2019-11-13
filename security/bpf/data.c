// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <linux/cred.h>
#include <linux/lsm_hooks.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/bpf.h>

#include "data.h"

struct lsm_blob_sizes bpf_lsm_blob_sizes __lsm_ro_after_init = {
	.lbs_cred = sizeof(struct bpf_lsm_task_blob),
};

