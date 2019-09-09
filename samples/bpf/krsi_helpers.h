/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _KRSI_HELPERS_H
#define _KRSI_HELPERS_H

#define __bpf_percpu_val_align __aligned(8)

#define ENV_VAR_NAME_MAX_LEN 48
#define ENV_VAR_VAL_MAX_LEN 4096

#define MAX_CPUS 128

#define __LOWER(x) (x & 0xffffffff)
#define __UPPER(x) (x >> 32)

struct krsi_env_value {
	// The name of the environment variable.
	char name[ENV_VAR_NAME_MAX_LEN];
	// The value of the environment variable (if set).
	char value[ENV_VAR_VAL_MAX_LEN];
	// Indicates if an overflow occurred while reading the value of the
	// of the environment variable. This means that an -E2BIG was received
	// from the krsi_get_env_var helper.
	bool overflow;
	// The number of times the environment variable was set.
	__u32 times;
	// The PID of the parent process.
	__u32 p_pid;
} __bpf_percpu_val_align;

#endif // _KRSI_HELPERS_H
