/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2020 Google LLC.
 */
#ifndef _LSM_HELPERS_H
#define _LSM_HELPERS_H

struct lsm_prog_result {
	/* This ensures that the LSM Hook only monitors the PID requested
	 * by the loader
	 */
	__u32 monitored_pid;
	/* The number of calls to the prog for the monitored PID.
	 */
	__u32 count;
};

#endif /* _LSM_HELPERS_H */
