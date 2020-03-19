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

#include "lsm_helpers.h"
#include "lsm_void_hook.skel.h"
#include "lsm_int_hook.skel.h"

char *LS_ARGS[] = {"true", NULL};

int heap_mprotect(void)
{
	void *buf;
	long sz;

	sz = sysconf(_SC_PAGESIZE);
	if (sz < 0)
		return sz;

	buf = memalign(sz, 2 * sz);
	if (buf == NULL)
		return -ENOMEM;

	return mprotect(buf, sz, PROT_READ | PROT_EXEC);
}

int exec_ls(struct lsm_prog_result *result)
{
	int child_pid;

	child_pid = fork();
	if (child_pid == 0) {
		result->monitored_pid = getpid();
		execvp(LS_ARGS[0], LS_ARGS);
		return -EINVAL;
	} else if (child_pid > 0)
		return wait(NULL);

	return -EINVAL;
}

void test_lsm_void_hook(void)
{
	struct lsm_prog_result *result;
	struct lsm_void_hook *skel = NULL;
	int err, duration = 0;

	skel = lsm_void_hook__open_and_load();
	if (CHECK(!skel, "skel_load", "lsm_void_hook skeleton failed\n"))
		goto close_prog;

	err = lsm_void_hook__attach(skel);
	if (CHECK(err, "attach", "lsm_void_hook attach failed: %d\n", err))
		goto close_prog;

	result = &skel->bss->result;

	err = exec_ls(result);
	if (CHECK(err < 0, "exec_ls", "err %d errno %d\n", err, errno))
		goto close_prog;

	if (CHECK(result->count != 1, "count", "count = %d", result->count))
		goto close_prog;

	CHECK_FAIL(result->count != 1);

close_prog:
	lsm_void_hook__destroy(skel);
}

void test_lsm_int_hook(void)
{
	struct lsm_prog_result *result;
	struct lsm_int_hook *skel = NULL;
	int err, duration = 0;

	skel = lsm_int_hook__open_and_load();
	if (CHECK(!skel, "skel_load", "lsm_int_hook skeleton failed\n"))
		goto close_prog;

	err = lsm_int_hook__attach(skel);
	if (CHECK(err, "attach", "lsm_int_hook attach failed: %d\n", err))
		goto close_prog;

	result = &skel->bss->result;
	result->monitored_pid = getpid();

	err = heap_mprotect();
	if (CHECK(errno != EPERM, "heap_mprotect", "want errno=EPERM, got %d\n",
		  errno))
		goto close_prog;

	CHECK_FAIL(result->count != 1);

close_prog:
	lsm_int_hook__destroy(skel);
}

void test_lsm_test(void)
{
	test_lsm_void_hook();
	test_lsm_int_hook();
}
