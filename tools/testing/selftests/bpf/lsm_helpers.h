// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */
#ifndef _LSM_HELPERS_H
#define _LSM_HELPERS_H

struct lsm_mprotect_audit_result {
	__u32 monitored_pid;
	__u32 count;
};

#endif /* _LSM_HELPERS_H */