// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2020 Google LLC.
 */

#include <asm-generic/errno-base.h>
#include <sys/stat.h>
#include <test_progs.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/xattr.h>

#include "confine.skel.h"
#include "network_helpers.h"

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif

static inline int sys_pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

static unsigned int duration;

#define IS_BORGLET 0xb0261e7
#define BORGLET_XATTR "borglet"

struct storage {
	void *inode;
	unsigned int value;
};


/* This needs to be a privileged operation that only allows the allow-listed
 * borglet binary to set this blob on itself.
 */
static bool set_borglet(int map_fd, int obj_fd)
{
	struct storage val = { .value = IS_BORGLET },
		       lookup_val = { .value = 0 };
	int err;

	/* Looking up an existing element should fail initially */
	err = bpf_map_lookup_elem_flags(map_fd, &obj_fd, &lookup_val, 0);
	if (CHECK(!err || errno != ENOENT, "bpf_map_lookup_elem",
		  "err:%d errno:%d\n val:%d", err, errno, lookup_val.value))
		return false;

	/* Create a new element */
	err = bpf_map_update_elem(map_fd, &obj_fd, &val, BPF_NOEXIST);
	if (CHECK(err < 0, "bpf_map_update_elem", "err:%d errno:%d\n", err,
		  errno))
		return false;

	/* Lookup the newly created element */
	err = bpf_map_lookup_elem_flags(map_fd, &obj_fd, &lookup_val, 0);
	if (CHECK(err < 0, "bpf_map_lookup_elem", "err:%d errno:%d", err,
		  errno))
		return false;

	/* Check the value of the newly created element */
	if (CHECK(lookup_val.value != val.value, "bpf_map_lookup_elem",
		  "value got = %x errno:%d", lookup_val.value, val.value))
		return false;

	return true;
}

void test_confine(void)
{
	/* Simulate a privileged credential that only the process tree of the
	 * the borglet can access.
	 */
	char tmp_dir_path[] = "/root/cred/local_storage_credXXXXXX";
	int err, sig, task_fd = -1;
	struct confine *skel = NULL;
	char task_cred_path[64];
	char cmd[256];
	sigset_t wset;

	skel = confine__open_and_load();
	if (CHECK(!skel, "skel_load", "lsm skeleton failed\n"))
		goto close_prog;

	err = confine__attach(skel);
	if (CHECK(err, "attach", "lsm attach failed: %d\n", err))
		goto close_prog;

	task_fd = sys_pidfd_open(getpid(), 0);
	if (CHECK(task_fd < 0, "pidfd_open",
		  "failed to get pidfd err:%d, errno:%d", task_fd, errno))
		goto close_prog;


	/* This setxattr call will be on the directory before the confining
	 * program is actually started, so we should ideally not be setting
	 * state on the blobs here. Think of this as an equivalent of the
	 * assd which is setting the state of the system */
	if (CHECK(!mkdtemp(tmp_dir_path), "mkdtemp",
		  "unable to create tmpdir: %d\n", errno))
		goto close_prog;

	err = setxattr(tmp_dir_path, "security.cred", BORGLET_XATTR,
		       sizeof(BORGLET_XATTR), XATTR_CREATE);
	if (CHECK(err < 0,  "setxattr", "failed to setxattr %d\n", errno))
		goto close_prog;

	if (!set_borglet(bpf_map__fd(skel->maps.task_storage_map),
				      task_fd))
		goto close_prog;

	snprintf(task_cred_path, sizeof(task_cred_path), "%s/task_cred",
		 tmp_dir_path);

	printf("Credential file created at %s\n", task_cred_path);
	snprintf(cmd, sizeof(cmd), "cp /bin/rm %s", task_cred_path);
	if (CHECK_FAIL(system(cmd)))
		goto close_prog_rmdir;

	// Keep running till a SIGHUP, SIGINT or SIGTERM is recieved.
	sigemptyset(&wset);
	sigaddset(&wset, SIGHUP);
	sigaddset(&wset, SIGINT);
	sigaddset(&wset, SIGTERM);
	sigwait(&wset, &sig);

close_prog_rmdir:
close_prog:
	close(task_fd);
	confine__destroy(skel);
}
