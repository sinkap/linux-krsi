/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright 2019 Google LLC.
 */

#ifndef _BPF_LSM_EVENT_H
#define _BPF_LSM_EVENT_H

#define __bpf_percpu_val_align __aligned(8)

#define ENV_VAR_NAME_MAX_LEN 48
#define ENV_VAR_VAL_MAX_LEN 4096

#define TASK_COMM_MAX_LEN 4096
#define PATH_MAX_LEN 4096
#define PROCFS_FILENAME_MAX_LEN PATH_MAX_LEN

#define MAX_CPUS 128

#define __LOWER(x) (x & 0xffffffff)
#define __UPPER(x) (x >> 32)

/*
 * The first field of the header is magic to identify whether the given
 * PERF_EVENT_RAW comes from a BPF LSM Event.
 */
#define BPF_LSM_MAGIC 0x6006

enum lsm_event_type {
	LSM_AUDIT_ENV_VAR,
	LSM_AUDIT_PROCFS,
	LSM_AUDIT_ARGS,
	LSM_DETECT_EXEC_UNLINK,
};

struct lsm_event_header {
	__u16 magic;
	enum lsm_event_type type;
} __bpf_percpu_val_align;

struct env_value {
	struct lsm_event_header header;
	// The name of the environment variable.
	char name[ENV_VAR_NAME_MAX_LEN];
	// The value of the environment variable (if set).
	char value[ENV_VAR_VAL_MAX_LEN];
	// Indicates if an overflow occurred while reading the value of the
	// environment variable. This means that an -E2BIG was received
	// from the bpf_lsm_get_env_var helper.
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

struct procfs_event {
	struct lsm_event_header header;
	// The name of the file to monitor in procfs.
	char filename[PROCFS_FILENAME_MAX_LEN];
	// The UID of the process.
	__u32 uid;
	// The GID of the process.
	__u32 gid;
	// The PID of the process.
	__u32 pid;
	// The PID of the process whose procfs file is being accessed.
	__u32 file_pid;
} __bpf_percpu_val_align;

struct argv_output_header {
	__u64 argc;
	__u64 envc;
} __bpf_percpu_val_align;

struct unlink_event {
	struct lsm_event_header header;
	__u32 pid;
	__u32 type;
} __bpf_percpu_val_align;

#endif // _BPF_LSM_EVENT_H
