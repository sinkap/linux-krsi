// SPDX-License-Identifier: GPL-2.0

#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/ip.h>
#include "bpf_helpers.h"
#include "krsi_audit.h"

#define MAX_CPUS 128

struct bpf_map_def SEC("maps") env_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct krsi_env_value),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") perf_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(u32),
	.max_entries = MAX_CPUS,
};

SEC("krsi")
int env_dumper(void *ctx)
{
	u64 times_ret;
	s32 ret;
	u32 map_id = 0;
	char *map_value;
	struct krsi_env_value *env;
	__u64 gid_uid = bpf_get_current_uid_gid();
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	env = bpf_map_lookup_elem(&env_map, &map_id);
	if (!env)
		return -ENOMEM;

	times_ret = krsi_get_env_var(ctx, env->name, ENV_VAR_NAME_MAX_LEN,
				     env->value, ENV_VAR_VAL_MAX_LEN);
	ret = __LOWER(times_ret);
	if (ret == -E2BIG)
		env->overflow = true;
	else if (ret < 0)
		return ret;

	env->times = __UPPER(times_ret);
	env->p_uid = __LOWER(gid_uid);
	env->p_gid = __UPPER(gid_uid);
	env->p_pid = __UPPER(pid_tgid);

	krsi_exec_file(ctx, env->exec_file, PATH_MAX_LEN);
	krsi_exec_interp(ctx, env->exec_interp, PATH_MAX_LEN);

	bpf_get_current_comm(env->p_comm, TASK_COMM_MAX_LEN);
	bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, env,
			      sizeof(struct krsi_env_value));

	return 0;
}

char _license[] SEC("license") = "GPL";
