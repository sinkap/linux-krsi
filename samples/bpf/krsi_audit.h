/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _KRSI_AUDIT_H
#define _KRSI_AUDIT_H

#define __bpf_percpu_val_align __aligned(8)

#define ENV_VAR_NAME_MAX_LEN 48
#define ENV_VAR_VAL_MAX_LEN 4096

#define TASK_COMM_MAX_LEN 4096
#define PATH_MAX_LEN 4096

#define MAX_CPUS 128

#define __LOWER(x) (x & 0xffffffff)
#define __UPPER(x) (x >> 32)

/*
 * The first field of the krsi_header is magic to identify whether the given
 * PERF_EVENT_RAW comes from KRSI.
 */
#define KRSI_MAGIC 0x6006

enum krsi_audit_event_type {
	KRSI_AUDIT_ENV_VAR,
};

struct krsi_audit_header {
	__u16 magic;
	enum krsi_audit_event_type type;
} __bpf_percpu_val_align;

struct krsi_env_value {
	struct krsi_audit_header header;
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
	// The comm of the parent process.
	char p_comm[TASK_COMM_MAX_LEN];
	// The file being executed.
	char exec_file[PATH_MAX_LEN];
	// The interpreter (generally the same as the task).
	char exec_interp[PATH_MAX_LEN];
	// The PID of the parent process.
	__u32 p_pid;
	// The UID of the parent process.
	__u32 p_uid;
	// The GID of the parent process.
	__u32 p_gid;
} __bpf_percpu_val_align;

#endif // _KRSI_AUDIT_H
