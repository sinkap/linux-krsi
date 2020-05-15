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

#include "inode_local_storage.skel.h"

int create_and_unlink_file()
{
	char fname[4096] = "/tmp/fileXXXXXX";
	int fd;

	fd = mkstemp(fname);
	if (fd < 0)
		return fd;

	close(fd);
	unlink(fname);
	return 0;
}

void test_test_inode_local_storage(void)
{
	struct inode_local_storage *skel = NULL;
	int err, duration = 0;

	skel = inode_local_storage__open_and_load();
	if (CHECK(!skel, "skel_load", "lsm skeleton failed\n"))
		goto close_prog;

	err = inode_local_storage__attach(skel);
	if (CHECK(err, "attach", "lsm attach failed: %d\n", err))
		goto close_prog;

	skel->bss->monitored_pid = getpid();

	err = create_and_unlink_file();
	if (CHECK(err < 0, "exec_cmd", "err %d errno %d\n", err, errno))
		goto close_prog;

	CHECK(!skel->bss->test_result, "test_result",
	      "inode_local_storage not set");

close_prog:
	inode_local_storage__destroy(skel);
}
