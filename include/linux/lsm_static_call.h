/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2020 Google LLC.
 */

#ifndef __LINUX_LSM_STATIC_CALL_H
#define __LINUX_LSM_STATIC_CALL_H

/*
 * Static slots are used in security/security.c to avoid costly
 * indirect calls by replacing them with static calls.
 * The number of static calls for each LSM hook is fixed.
 */
#define SECURITY_STATIC_SLOT_COUNT 12

#define SECURITY_HOOK_ENABLED_KEY(HOOK, IDX) security_enabled_key_##HOOK##_##IDX

/*
 * Identifier for the LSM static slots.
 * HOOK is an LSM hook as defined in linux/lsm_hookdefs.h
 * IDX is the index of the slot. 0 <= NUM < SECURITY_STATIC_SLOT_COUNT
 */
#define SECURITY_STATIC_SLOT(HOOK, IDX) security_static_slot_##HOOK##_##IDX

/*
 * Call the macro M for each LSM hook slot.
 * M should take as first argument the index and then
 * the same __VA_ARGS__
 * Essentially, this will expand to:
 *	M(0, ...)
 *	M(1, ...)
 *	M(2, ...)
 *	...
 * Note that no trailing semicolon is placed so M should be defined
 * accordingly.
 * This adapts to a change to SECURITY_STATIC_SLOT_COUNT.
 */
#define SECURITY_FOREACH_STATIC_SLOT(M, ...)		\
	UNROLL_MACRO_LOOP(SECURITY_STATIC_SLOT_COUNT, M, __VA_ARGS__)

/*
 * Intermediate macros to expand SECURITY_STATIC_SLOT_COUNT
 */
#define UNROLL_MACRO_LOOP(N, MACRO, ...)		\
	_UNROLL_MACRO_LOOP(N, MACRO, __VA_ARGS__)

#define _UNROLL_MACRO_LOOP(N, MACRO, ...)		\
	__UNROLL_MACRO_LOOP(N, MACRO, __VA_ARGS__)

#define __UNROLL_MACRO_LOOP(N, MACRO, ...)		\
	__UNROLL_MACRO_LOOP_##N(MACRO, __VA_ARGS__)

#define __UNROLL_MACRO_LOOP_0(MACRO, ...)

#define __UNROLL_MACRO_LOOP_1(MACRO, ...)		\
	__UNROLL_MACRO_LOOP_0(MACRO, __VA_ARGS__)	\
	MACRO(0, __VA_ARGS__)

#define __UNROLL_MACRO_LOOP_2(MACRO, ...)		\
	__UNROLL_MACRO_LOOP_1(MACRO, __VA_ARGS__)	\
	MACRO(1, __VA_ARGS__)

#define __UNROLL_MACRO_LOOP_3(MACRO, ...)		\
	__UNROLL_MACRO_LOOP_2(MACRO, __VA_ARGS__)	\
	MACRO(2, __VA_ARGS__)

#define __UNROLL_MACRO_LOOP_4(MACRO, ...)		\
	__UNROLL_MACRO_LOOP_3(MACRO, __VA_ARGS__)	\
	MACRO(3, __VA_ARGS__)

#define __UNROLL_MACRO_LOOP_5(MACRO, ...)		\
	__UNROLL_MACRO_LOOP_4(MACRO, __VA_ARGS__)	\
	MACRO(4, __VA_ARGS__)

#define __UNROLL_MACRO_LOOP_6(MACRO, ...)		\
	__UNROLL_MACRO_LOOP_5(MACRO, __VA_ARGS__)	\
	MACRO(5, __VA_ARGS__)

#define __UNROLL_MACRO_LOOP_7(MACRO, ...)		\
	__UNROLL_MACRO_LOOP_6(MACRO, __VA_ARGS__)	\
	MACRO(6, __VA_ARGS__)

#define __UNROLL_MACRO_LOOP_8(MACRO, ...)		\
	__UNROLL_MACRO_LOOP_7(MACRO, __VA_ARGS__)	\
	MACRO(7, __VA_ARGS__)

#define __UNROLL_MACRO_LOOP_9(MACRO, ...)		\
	__UNROLL_MACRO_LOOP_8(MACRO, __VA_ARGS__)	\
	MACRO(8, __VA_ARGS__)

#define __UNROLL_MACRO_LOOP_10(MACRO, ...)		\
	__UNROLL_MACRO_LOOP_9(MACRO, __VA_ARGS__)	\
	MACRO(9, __VA_ARGS__)

#define __UNROLL_MACRO_LOOP_11(MACRO, ...)		\
	__UNROLL_MACRO_LOOP_10(MACRO, __VA_ARGS__)	\
	MACRO(10, __VA_ARGS__)

#define __UNROLL_MACRO_LOOP_12(MACRO, ...)		\
	__UNROLL_MACRO_LOOP_11(MACRO, __VA_ARGS__)	\
	MACRO(11, __VA_ARGS__)

#define __UNROLL_MACRO_LOOP_13(MACRO, ...)		\
	__UNROLL_MACRO_LOOP_12(MACRO, __VA_ARGS__)	\
	MACRO(12, __VA_ARGS__)

#define __UNROLL_MACRO_LOOP_14(MACRO, ...)		\
	__UNROLL_MACRO_LOOP_13(MACRO, __VA_ARGS__)	\
	MACRO(13, __VA_ARGS__)

#define __UNROLL_MACRO_LOOP_15(MACRO, ...)		\
	__UNROLL_MACRO_LOOP_14(MACRO, __VA_ARGS__)	\
	MACRO(14, __VA_ARGS__)

#define __UNROLL_MACRO_LOOP_16(MACRO, ...)		\
	__UNROLL_MACRO_LOOP_15(MACRO, __VA_ARGS__)	\
	MACRO(15, __VA_ARGS__)

#define __UNROLL_MACRO_LOOP_17(MACRO, ...)		\
	__UNROLL_MACRO_LOOP_16(MACRO, __VA_ARGS__)	\
	MACRO(16, __VA_ARGS__)

#define __UNROLL_MACRO_LOOP_18(MACRO, ...)		\
	__UNROLL_MACRO_LOOP_17(MACRO, __VA_ARGS__)	\
	MACRO(17, __VA_ARGS__)

#define __UNROLL_MACRO_LOOP_19(MACRO, ...)		\
	__UNROLL_MACRO_LOOP_18(MACRO, __VA_ARGS__)	\
	MACRO(18, __VA_ARGS__)

#define __UNROLL_MACRO_LOOP_20(MACRO, ...)		\
	__UNROLL_MACRO_LOOP_19(MACRO, __VA_ARGS__)	\
	MACRO(19, __VA_ARGS__)

#endif /* __LINUX_LSM_STATIC_CALL_H */
