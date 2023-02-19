/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2023 Google LLC.
 */

#ifndef __LINUX_LSM_COUNT_H
#define __LINUX_LSM_COUNT_H

#include <linux/kconfig.h>

/*
 * Macros to count the number of LSMs enabled in the kernel at compile time.
 */

#define __LSM_COUNT_15(x, y...) 15
#define __LSM_COUNT_14(x, y...) 14
#define __LSM_COUNT_13(x, y...) 13
#define __LSM_COUNT_12(x, y...) 12
#define __LSM_COUNT_11(x, y...) 11
#define __LSM_COUNT_10(x, y...) 10
#define __LSM_COUNT_9(x, y...) 9
#define __LSM_COUNT_8(x, y...) 8
#define __LSM_COUNT_7(x, y...) 7
#define __LSM_COUNT_6(x, y...) 6
#define __LSM_COUNT_5(x, y...) 5
#define __LSM_COUNT_4(x, y...) 4
#define __LSM_COUNT_3(x, y...) 3
#define __LSM_COUNT_2(x, y...) 2
#define __LSM_COUNT_1(x, y...) 1
#define __LSM_COUNT_0(x, y...) 0

#define __LSM_COUNT1_15(x, y...) __LSM_COUNT ## x ## _15(y)
#define __LSM_COUNT1_14(x, y...) __LSM_COUNT ## x ## _14(y)
#define __LSM_COUNT1_13(x, y...) __LSM_COUNT ## x ## _13(y)
#define __LSM_COUNT1_12(x, y...) __LSM_COUNT ## x ## _12(y)
#define __LSM_COUNT1_10(x, y...) __LSM_COUNT ## x ## _11(y)
#define __LSM_COUNT1_9(x, y...) __LSM_COUNT ## x ## _10(y)
#define __LSM_COUNT1_8(x, y...) __LSM_COUNT ## x ## _9(y)
#define __LSM_COUNT1_7(x, y...) __LSM_COUNT ## x ## _8(y)
#define __LSM_COUNT1_6(x, y...) __LSM_COUNT ## x ## _7(y)
#define __LSM_COUNT1_5(x, y...) __LSM_COUNT ## x ## _6(y)
#define __LSM_COUNT1_4(x, y...) __LSM_COUNT ## x ## _5(y)
#define __LSM_COUNT1_3(x, y...) __LSM_COUNT ## x ## _4(y)
#define __LSM_COUNT1_2(x, y...) __LSM_COUNT ## x ## _3(y)
#define __LSM_COUNT1_1(x, y...) __LSM_COUNT ## x ## _2(y)
#define __LSM_COUNT1_0(x, y...) __LSM_COUNT ## x ## _1(y)
#define __LSM_COUNT(x, y...) __LSM_COUNT ## x ## _0(y)

#define __LSM_COUNT_EXPAND(x...) __LSM_COUNT(x)

#if IS_ENABLED(CONFIG_SECURITY)
#define CAPABILITIES_ENABLED 1,
#else
#define CAPABILITIES_ENABLED
#endif

#if IS_ENABLED(CONFIG_SECURITY_SELINUX)
#define SELINUX_ENABLED 1,
#else
#define SELINUX_ENABLED
#endif

#if IS_ENABLED(CONFIG_SECURITY_SMACK)
#define SMACK_ENABLED 1,
#else
#define SMACK_ENABLED
#endif

#if IS_ENABLED(CONFIG_SECURITY_APPARMOR)
#define APPARMOR_ENABLED 1,
#else
#define APPARMOR_ENABLED
#endif

#if IS_ENABLED(CONFIG_SECURITY_TOMOYO)
#define TOMOYO_ENABLED 1,
#else
#define TOMOYO_ENABLED
#endif

#if IS_ENABLED(CONFIG_SECURITY_YAMA)
#define YAMA_ENABLED 1,
#else
#define YAMA_ENABLED
#endif

#if IS_ENABLED(CONFIG_SECURITY_LOADPIN)
#define LOADPIN_ENABLED 1,
#else
#define LOADPIN_ENABLED
#endif

#if IS_ENABLED(CONFIG_SECURITY_LOCKDOWN_LSM)
#define LOCKDOWN_ENABLED 1,
#else
#define LOCKDOWN_ENABLED
#endif

#if IS_ENABLED(CONFIG_BPF_LSM)
#define BPF_LSM_ENABLED 1,
#else
#define BPF_LSM_ENABLED
#endif

#if IS_ENABLED(CONFIG_BPF_LSM)
#define BPF_LSM_ENABLED 1,
#else
#define BPF_LSM_ENABLED
#endif

#if IS_ENABLED(CONFIG_SECURITY_LANDLOCK)
#define LANDLOCK_ENABLED 1,
#else
#define LANDLOCK_ENABLED
#endif

#define MAX_LSM_COUNT			\
	__LSM_COUNT_EXPAND(		\
		CAPABILITIES_ENABLED	\
		SELINUX_ENABLED		\
		SMACK_ENABLED		\
		APPARMOR_ENABLED	\
		TOMOYO_ENABLED		\
		YAMA_ENABLED		\
		LOADPIN_ENABLED		\
		LOCKDOWN_ENABLED	\
		BPF_LSM_ENABLED		\
		LANDLOCK_ENABLED)

#endif  /* __LINUX_LSM_COUNT_H */
