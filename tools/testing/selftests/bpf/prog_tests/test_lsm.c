// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2020 Google LLC.
 */

#include <test_progs.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <malloc.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/limits.h>

#include "lsm.skel.h"
#include "trace_helpers.h"

char *CMD_ARGS[] = {"true", NULL};

#define GET_PAGE_ADDR(ADDR, PAGE_SIZE)					\
	(char *)(((unsigned long) (ADDR + PAGE_SIZE)) & ~(PAGE_SIZE-1))

int stack_mprotect(void)
{
	void *buf;
	long sz;
	int ret;

	sz = sysconf(_SC_PAGESIZE);
	if (sz < 0)
		return sz;

	buf = alloca(sz * 3);
	ret = mprotect(GET_PAGE_ADDR(buf, sz), sz,
		       PROT_READ | PROT_WRITE | PROT_EXEC);
	return ret;
}

int exec_cmd(int *monitored_pid)
{
	int child_pid, child_status;

	child_pid = fork();
	if (child_pid == 0) {
		*monitored_pid = getpid();
		execvp(CMD_ARGS[0], CMD_ARGS);
		return -EINVAL;
	} else if (child_pid > 0) {
		waitpid(child_pid, &child_status, 0);
		return child_status;
	}

	return -EINVAL;
}

#define IMA_POLICY "measure func=BPRM_CHECK"
#define IMA_SYSFS_POLICY_FILE "/sys/kernel/security/ima/policy"

static int update_ima_policy(void)
{
	int fd, ret = 0;

	fd = open(IMA_SYSFS_POLICY_FILE, O_WRONLY);
	if (fd < 0)
		return -errno;

	if (write(fd, IMA_POLICY, sizeof(IMA_POLICY)) == -1)
		ret = -errno;

	close(fd);
	return ret;
}

void test_test_lsm(void)
{
	char ima_policy_backup[PATH_MAX] = "/tmp/ima_policy_bupXXXXXX";
	struct lsm *skel = NULL;
	int err, duration = 0;
	int buf = 1234;

	skel = lsm__open_and_load();
	if (CHECK(!skel, "skel_load", "lsm skeleton failed\n"))
		goto close_prog;

	err = lsm__attach(skel);
	if (CHECK(err, "attach", "lsm attach failed: %d\n", err))
		goto close_prog;

	err = copy_file_temp(IMA_SYSFS_POLICY_FILE, ima_policy_backup);
	if (CHECK(err, "ima_policy_backup", "ima_policy_backup failed: %d\n",
		  err))
		goto close_prog;

	err = update_ima_policy();
	if (CHECK(err != 0, "update_ima_policy", "error = %d\n", err))
		goto close_prog;

	err = exec_cmd(&skel->bss->monitored_pid);
	CHECK(err < 0, "exec_cmd", "err %d errno %d\n", err, errno);

	err = copy_file(ima_policy_backup, IMA_SYSFS_POLICY_FILE);
	CHECK(err, "ima_policy_restore", "ima_policy_restore err = %d\n", err);

	err = unlink(ima_policy_backup);
	CHECK(err, "cleanup ima backup", "unlink(%s) err = %d\n",
	      ima_policy_backup, err);

	CHECK(skel->bss->bprm_count != 1, "bprm_count", "bprm_count = %d\n",
	      skel->bss->bprm_count);

	skel->bss->monitored_pid = getpid();

	err = stack_mprotect();
	if (CHECK(errno != EPERM, "stack_mprotect", "want err=EPERM, got %d\n",
		  errno))
		goto close_prog;

	CHECK(skel->bss->mprotect_count != 1, "mprotect_count",
	      "mprotect_count = %d\n", skel->bss->mprotect_count);

	CHECK(skel->data->ima_hash_ret < 0, "ima_hash_ret",
	      "ima_hash_ret = %d\n", skel->data->ima_hash_ret);

	CHECK(skel->bss->ima_hash == 0, "ima_hash",
	      "ima_hash = %lu\n", skel->bss->ima_hash);

	syscall(__NR_setdomainname, &buf, -2L);
	syscall(__NR_setdomainname, 0, -3L);
	syscall(__NR_setdomainname, ~0L, -4L);

	CHECK(skel->bss->copy_test != 3, "copy_test",
	      "copy_test = %d\n", skel->bss->copy_test);

close_prog:
	lsm__destroy(skel);
}
