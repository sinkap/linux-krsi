// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */
#ifndef _LSM_HELPERS_H
#define _LSM_HELPERS_H

struct lsm_mprotect_audit_result {
	/* This ensures that the LSM Hook only monitors the PID requested
	 * by the loader
	 */
	__u32 monitored_pid;
	/* The number of mprotect calls for the monitored PID.
	 */
	__u32 mprotect_count;
};

#endif /* _LSM_HELPERS_H */