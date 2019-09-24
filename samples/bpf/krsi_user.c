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
#include <linux/perf_event.h>
#include <krsi/libkrsi.h>

#include "perf-sys.h"
#include "trace_helpers.h"
#include "krsi_audit.h"

#define PERF_BUFFER_PAGE_COUNT 32
#define PERF_POLL_TIMEOUT_MS 1000


static void print_procfs_audit(struct krsi_procfs *pfs)
{
	printf("/prod/%d/%s accessed\n", pfs->pid, pfs->filename);
}

static void print_env_var(struct krsi_env_value *env)
{
	int times = env->times;
	char *next = env->value;
	size_t total = 0;

	if (env->times > 1)
		printf("[p_pid=%u] [p_comm=%s] [p_uid=%u] [p_gid=%u] [exec_file=%s] [exec_interp=%s] WARNING! %s is set %d times\n",
			env->p_pid, env->p_comm, env->p_uid,
			env->p_gid, env->exec_file,
			env->exec_interp, env->name, env->times);
	/*
	 * krsi_get_env_var ensures that even overflows
	 * are null terminated. Incase of an overflow,
	 * this logic tries to print as much information
	 * that was gathered.
	 */
	while (times && total < ENV_VAR_NAME_MAX_LEN) {
		next += total;
		if (env->overflow)
			printf("[p_pid=%u] [p_comm=%s] [p_uid=%u] [p_gid=%u] [exec_file=%s] [exec_interp=%s]  OVERFLOW! %s=%s\n",
				env->p_pid, env->p_comm, env->p_uid,
				env->p_gid, env->exec_file,
				env->exec_interp, env->name, next);
		else
			printf("[p_pid=%u] [p_comm=%s] [p_uid=%u] [p_gid=%u] [exec_file=%s] [exec_interp=%s] %s=%s\n",
				env->p_pid, env->p_comm, env->p_uid,
				env->p_gid, env->exec_file,
				env->exec_interp, env->name, next);

		times--;
		total += strlen(next) + 1;
	}

	if (!env->times)
		printf("[p_pid=%u] [p_comm=%s] [p_uid=%u] [p_gid=%u] [exec_file=%s] [exec_interp=%s] %s is not set\n",
			env->p_pid, env->p_comm, env->p_uid,
			env->p_gid, env->exec_file,
			env->exec_interp, env->name);
}

static void perf_event_handler(void *ctx, int cpu, void *data, __u32 size)
{
	struct krsi_audit_header *header = data;

	if (header->magic != KRSI_MAGIC)
		return;

	switch (header->type) {
	case KRSI_AUDIT_ENV_VAR:
		print_env_var(data);
		return;
	case KRSI_AUDIT_PROCFS:
		print_procfs_audit(data);
		return;
	default:
		printf("unknown event\n");
	}
}

static int krsi_update_percpu_array(struct bpf_map *map,
				    void *data, size_t size)
{
	int numcpus = get_nprocs();
	int key = 0, ret = 0;
	void *array;
	int map_fd, i;

	map_fd = bpf_map__fd(map);
	if (map_fd < 0)
		return map_fd;

	array = malloc(numcpus * size);
	if (!array) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < numcpus; i++)
		memcpy(array + i * size, data, size);

	ret = bpf_map_update_elem(map_fd, &key, array, BPF_ANY);
	if (ret < 0)
		goto out;

out:
	free(array);
	return ret;
}

static int load_procfs_audit(const char *filename, int perf_fd)
{
	struct krsi_procfs event;
	struct bpf_object *prog_obj;
	struct bpf_map *map;
	struct krsi_attach_attr attr = {};
	int ret = 0;

	attr.filename = filename;
	attr.perf_fd = perf_fd;

	ret = krsi_attach_xattr(&attr, &prog_obj);
	if (ret < 0)
		return ret;

	event.header.type = KRSI_AUDIT_PROCFS;
	event.header.magic = KRSI_MAGIC;
	strcpy(event.filename, "mem");

	map = bpf_object__find_map_by_name(prog_obj, "procfs_map");
	if (!map)
		return -EINVAL;

	ret = krsi_update_percpu_array(map, &event,
		sizeof(struct krsi_procfs));
	if (ret < 0)
		err(EXIT_FAILURE, "Failed to update env map");

	return 0;
}

static int load_env_dumper(const char *filename,
			   const char *env_var_name,
			   int perf_fd)
{
	struct krsi_env_value event;
	struct bpf_map *map;
	struct bpf_object *prog_obj;
	struct krsi_attach_attr attr = {};
	int ret = 0;

	attr.filename = filename;
	attr.perf_fd = perf_fd;

	ret = krsi_attach_xattr(&attr, &prog_obj);
	if (ret < 0)
		return ret;

	event.header.magic = KRSI_MAGIC;
	event.header.type = KRSI_AUDIT_ENV_VAR;
	strcpy(event.name, env_var_name);

	map = bpf_object__find_map_by_name(prog_obj, "env_map");
	if (!map)
		return -EINVAL;

	ret = krsi_update_percpu_array(map, &event,
		sizeof(struct krsi_env_value));
	if (ret < 0)
		err(EXIT_FAILURE, "Failed to update env map");

	return 0;
}

int main(int argc, char **argv)
{
	const char *env_var_name;
	struct perf_buffer_opts pb_opts = {};
	struct perf_buffer *pb;
	char filename[PATH_MAX];
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	int map_fd, ret = 0;

	setrlimit(RLIMIT_MEMLOCK, &r);

	map_fd = krsi_create_perf_map();
	if (map_fd < 0)
		errx(EXIT_FAILURE, "Unable to create perf map %d", errno);

	if (argc != 2)
		errx(EXIT_FAILURE, "Usage %s env_var_name\n", argv[0]);

	env_var_name = argv[1];
	if (strlen(env_var_name) > ENV_VAR_NAME_MAX_LEN - 1)
		errx(EXIT_FAILURE,
		     "<env_var_name> cannot be more than %d in length",
		     ENV_VAR_NAME_MAX_LEN - 1);


	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	ret = load_env_dumper(filename, env_var_name, map_fd);
	if (ret < 0)
		errx(EXIT_FAILURE,
		     "Failed to load env_dumper");

	snprintf(filename, sizeof(filename), "%s2_kern.o", argv[0]);
	ret = load_procfs_audit(filename, map_fd);
	if (ret < 0)
		errx(EXIT_FAILURE,
		     "Failed to load procfs_audit");

	pb_opts.sample_cb = perf_event_handler;
	pb = perf_buffer__new(map_fd, PERF_BUFFER_PAGE_COUNT, &pb_opts);
	ret = libbpf_get_error(pb);
	if (ret) {
		perror("perf_buffer setup failed");
		return 1;
	}

	while ((ret = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS)) >= 0) {
	}

	return EXIT_SUCCESS;
}
