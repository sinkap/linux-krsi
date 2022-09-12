// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022 Google LLC.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <endian.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <linux/keyctl.h>
#include <test_progs.h>
#include <signal.h>

#include "bpf_sign.skel.h"
#include "fexit_sleep.lskel.h"

#define MAX_DATA_SIZE (1024 * 1024)
#define MAX_SIG_SIZE 1024

struct data {
	u8 data[MAX_DATA_SIZE];
	u32 data_len;
	u8 sig[MAX_SIG_SIZE];
	u32 sig_len;
};

#define VERIFY_USE_SECONDARY_KEYRING (1UL)

void test_bpf_sign(void)
{
	struct bpf_sign *skel = NULL;
	struct fexit_sleep_lskel *fexit_lskel = NULL;
	int ret = 0;

	skel = bpf_sign__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bpf_sign_sig__open"))
		goto close_prog;


	if (!ASSERT_OK(ret, "bpf_sign_sig__load"))
		goto close_prog;

	ret = bpf_sign__attach(skel);
	if (!ASSERT_OK(ret, "bpf_sign_sig__attach"))
		goto close_prog;

	skel->bss->monitored_pid = getpid();

	/* Test signature verification with system keyrings. */
	skel->bss->system_keyring_id = VERIFY_USE_SECONDARY_KEYRING;

	fexit_lskel = fexit_sleep_lskel__open_and_load();
	if (!ASSERT_OK_PTR(fexit_lskel, "fexit_skel_load"))
		goto close_prog;

	ret = fexit_sleep_lskel__attach(fexit_lskel);
	if (!ASSERT_OK(ret, "fexit_attach"))
		goto close_prog;

	ASSERT_EQ(skel->bss->num_successful_sigs, 1, "num_successful_sigs");

close_prog:
	bpf_sign__destroy(skel);
	fexit_sleep_lskel__destroy(fexit_lskel);
}
