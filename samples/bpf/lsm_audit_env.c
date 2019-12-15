// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <uapi/linux/errno.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf_lsm_event.h"

#define _(P) (__builtin_preserve_access_index(P))

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct env_value));
	__uint(max_entries, 1);
} env_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(u32));
} perf_map SEC(".maps");

struct linux_binprm {
	const char *filename;
	const char *interp;
};

struct args {
	struct linux_binprm *bprm;
};

SEC("lsm/bprm_check_security")
int env_dumper(struct args *ctx)
{
	u64 times_ret;
	s32 ret;
	u32 map_id = 0;
	char *map_value;
	struct linux_binprm *bprm = ctx->bprm;
	const char *filename, *interp;
	struct env_value *env;
	__u64 gid_uid = bpf_get_current_uid_gid();
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	env = bpf_map_lookup_elem(&env_map, &map_id);
	if (!env)
		return -ENOMEM;

	times_ret = bpf_lsm_get_env_var(bprm, env->name,
					ENV_VAR_NAME_MAX_LEN, env->value,
					ENV_VAR_VAL_MAX_LEN);
	ret = __LOWER(times_ret);
	if (ret == -E2BIG)
		env->overflow = true;
	else if (ret < 0)
		return ret;

	env->times = __UPPER(times_ret);
	env->p_uid = __LOWER(gid_uid);
	env->p_gid = __UPPER(gid_uid);
	env->p_pid = __UPPER(pid_tgid);

	bpf_probe_read_kernel_str(env->exec_file, PATH_MAX_LEN,
				  _(bprm->filename));
	bpf_probe_read_kernel_str(env->exec_interp, PATH_MAX_LEN,
				  _(bprm->interp));

	bpf_get_current_comm(env->p_comm, TASK_COMM_MAX_LEN);
	bpf_lsm_event_output(&perf_map, BPF_F_CURRENT_CPU, env,
			     sizeof(struct env_value));

	return 0;
}

char _license[] SEC("license") = "GPL";
