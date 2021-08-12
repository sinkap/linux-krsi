// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2020 Google LLC.
 */

#include <asm-generic/errno-base.h>
#include <sys/stat.h>
#include <test_progs.h>
#include <linux/limits.h>

#include "container_id.skel.h"


void test_container_id(void)
{
	int err, sig, duration = 0;
	struct container_id *skel = NULL;
 	sigset_t wset;                                                                
                                                                                

	skel = container_id__open_and_load();
	if (CHECK(!skel, "skel_load", "lsm skeleton failed\n"))
		goto close_prog;

	err = container_id__attach(skel);
	if (CHECK(err, "attach", "lsm attach failed: %d\n", err))
		goto close_prog;

	// Keep running till a SIGHUP, SIGINT or SIGTERM is recieved.
 	sigemptyset(&wset);
 	sigaddset(&wset,SIGHUP);
 	sigaddset(&wset,SIGINT);
 	sigaddset(&wset,SIGTERM);
 	sigwait(&wset,&sig);                                               
 
close_prog:
	container_id__destroy(skel);
}
