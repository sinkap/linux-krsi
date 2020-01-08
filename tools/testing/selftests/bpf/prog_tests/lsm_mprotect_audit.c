// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <test_progs.h>
#include <sys/mman.h>
#include <unistd.h>
#include <malloc.h>
#include "lsm_helpers.h"
#include "lsm_mprotect_audit.skel.h"

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

void test_lsm_mprotect_audit(void)
{
	struct lsm_mprotect_audit_result *result;
	struct lsm_mprotect_audit *skel = NULL;
	int err, duration = 0;

	skel = lsm_mprotect_audit__open_and_load();
	if (CHECK(!skel, "skel_load", "lsm_mprotect_audit skeleton failed\n"))
		goto close_prog;

	err = lsm_mprotect_audit__attach(skel);
	if (CHECK(err, "attach", "lsm_mprotect_audit attach failed: %d\n", err))
		goto close_prog;

	result = &skel->bss->result;
	result->monitored_pid = getpid();

	err = heap_mprotect();
	if (CHECK(err < 0, "heap_mprotect", "err %d errno %d\n", err, errno))
		goto close_prog;

	/* Make sure mprotect_audit program was triggered
	 * and detected an mprotect on the heap.
	 */
	CHECK_FAIL(result->mprotect_count != 1);

close_prog:
	lsm_mprotect_audit__destroy(skel);
	return;
}
