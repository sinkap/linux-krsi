// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <assert.h>
#include <linux/limits.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include "bpf/libbpf.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/resource.h>

#include "perf-sys.h"
#include "trace_helpers.h"
#include "krsi_helpers.h"

#define LSM_HOOK_PATH "/sys/kernel/security/krsi/process_execution"

static int pmu_fds[MAX_CPUS];
static struct perf_event_mmap_page *headers[MAX_CPUS];

static int print_env(void *d, int size)
{
	struct krsi_env_value *env = d;
	int times = env->times;
	char *next = env->value;
	size_t total = 0;

	if (env->times > 1)
		printf("[p_pid=%u] WARNING! %s is set %u times\n",
			env->p_pid, env->name, env->times);

	/*
	 * krsi_get_env_var ensures that even overflows
	 * are null terminated. Incase of an overflow,
	 * this logic tries to print as much information
	 * that was gathered.
	 */
	while (times && total < ENV_VAR_NAME_MAX_LEN) {
		next += total;
		if (env->overflow)
			printf("[p_pid=%u] OVERFLOW! %s=%s\n",
			       env->p_pid, env->name, next);
		else
			printf("[p_pid=%u] %s=%s\n",
			       env->p_pid, env->name, next);
		times--;
		total += strlen(next) + 1;
	}

	if (!env->times)
		printf("p_pid=%u] %s is not set\n",
		       env->p_pid, env->name);

	return LIBBPF_PERF_EVENT_CONT;
}

static int open_perf_events(int map_fd, int num)
{
	int i;
	struct perf_event_attr attr = {
		.sample_type = PERF_SAMPLE_RAW,
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_BPF_OUTPUT,
		.wakeup_events = 1, /* get an fd notification for every event */
	};

	for (i = 0; i < num; i++) {
		int key = i;
		int ret;

		ret = sys_perf_event_open(&attr, -1 /*pid*/, i/*cpu*/,
					 -1/*group_fd*/, 0);
		if (ret < 0)
			return ret;
		pmu_fds[i] = ret;
		ret = bpf_map_update_elem(map_fd, &key, &pmu_fds[i], BPF_ANY);
		if (ret < 0)
			return ret;
		ioctl(pmu_fds[i], PERF_EVENT_IOC_ENABLE, 0);
	}
	return 0;
}

static int update_env_map(struct bpf_object *prog_obj, const char *env_var_name,
			  int numcpus)
{
	struct bpf_map *map;
	struct krsi_env_value *env;
	int map_fd;
	int key = 0, ret = 0, i;

	map = bpf_object__find_map_by_name(prog_obj, "env_map");
	if (!map)
		return -EINVAL;

	map_fd = bpf_map__fd(map);
	if (map_fd < 0)
		return map_fd;

	env = malloc(numcpus * sizeof(struct krsi_env_value));
	if (!env) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < numcpus; i++)
		strcpy(env[i].name, env_var_name);

	ret = bpf_map_update_elem(map_fd, &key, env, BPF_ANY);
	if (ret < 0)
		goto out;

out:
	free(env);
	return ret;
}

int main(int argc, char **argv)
{
	struct bpf_object *prog_obj;
	const char *env_var_name;
	struct bpf_prog_load_attr attr;
	int prog_fd, target_fd, map_fd;
	int ret, i, numcpus;
	struct bpf_map *map;
	char filename[PATH_MAX];
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};


	if (argc != 2)
		errx(EXIT_FAILURE, "Usage %s env_var_name\n", argv[0]);

	env_var_name = argv[1];
	if (strlen(env_var_name) > ENV_VAR_NAME_MAX_LEN - 1)
		errx(EXIT_FAILURE,
		     "<env_var_name> cannot be more than %d in length",
		     ENV_VAR_NAME_MAX_LEN - 1);


	setrlimit(RLIMIT_MEMLOCK, &r);
	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	memset(&attr, 0, sizeof(struct bpf_prog_load_attr));
	attr.prog_type = BPF_PROG_TYPE_KRSI;
	attr.expected_attach_type = BPF_KRSI;
	attr.file = filename;

	/* Attach the BPF program to the given hook */
	target_fd = open(LSM_HOOK_PATH, O_RDWR);
	if (target_fd < 0)
		err(EXIT_FAILURE, "Failed to open target file");

	if (bpf_prog_load_xattr(&attr, &prog_obj, &prog_fd))
		err(EXIT_FAILURE, "Failed to load eBPF program");

	numcpus = get_nprocs();
	if (numcpus > MAX_CPUS)
		numcpus = MAX_CPUS;

	ret = update_env_map(prog_obj, env_var_name, numcpus);
	if (ret < 0)
		err(EXIT_FAILURE, "Failed to update env map");

	map = bpf_object__find_map_by_name(prog_obj, "perf_map");
	if (!map)
		err(EXIT_FAILURE,
		    "Finding the perf event map in obj file failed");

	map_fd = bpf_map__fd(map);
	if (map_fd < 0)
		err(EXIT_FAILURE, "Failed to get fd for perf events map");

	ret = bpf_prog_attach(prog_fd, target_fd, BPF_KRSI,
			      BPF_F_ALLOW_OVERRIDE);
	if (ret < 0)
		err(EXIT_FAILURE, "Failed to attach prog to LSM hook");

	ret = open_perf_events(map_fd, numcpus);
	if (ret < 0)
		err(EXIT_FAILURE, "Failed to open perf events handler");

	for (i = 0; i < numcpus; i++) {
		ret = perf_event_mmap_header(pmu_fds[i], &headers[i]);
		if (ret < 0)
			err(EXIT_FAILURE, "perf_event_mmap_header");
	}

	ret = perf_event_poller_multi(pmu_fds, headers, numcpus, print_env);
	if (ret < 0)
		err(EXIT_FAILURE, "Failed to poll perf events");

	return EXIT_SUCCESS;
}
