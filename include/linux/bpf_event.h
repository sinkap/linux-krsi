/* SPDX-License-Identifier: GPL-2.0 */


/*
 * Copyright (c) 2018 Facebook
 * Copyright 2019 Google LLC.
 */

#ifndef _LINUX_BPF_EVENT_H
#define _LINUX_BPF_EVENT_H

#ifdef CONFIG_BPF_EVENTS

/* cast any integer, pointer, or small struct to u64 */
#define UINTTYPE(size) \
	__typeof__(__builtin_choose_expr(size == 1,  (u8)1, \
		   __builtin_choose_expr(size == 2, (u16)2, \
		   __builtin_choose_expr(size == 4, (u32)3, \
		   __builtin_choose_expr(size == 8, (u64)4, \
					 (void)5)))))
#define __CAST_TO_U64(x) ({ \
	typeof(x) __src = (x); \
	UINTTYPE(sizeof(x)) __dst; \
	memcpy(&__dst, &__src, sizeof(__dst)); \
	(u64)__dst; })

#define __CAST0(...) 0
#define __CAST1(a, ...) __CAST_TO_U64(a)
#define __CAST2(a, ...) __CAST_TO_U64(a), __CAST1(__VA_ARGS__)
#define __CAST3(a, ...) __CAST_TO_U64(a), __CAST2(__VA_ARGS__)
#define __CAST4(a, ...) __CAST_TO_U64(a), __CAST3(__VA_ARGS__)
#define __CAST5(a, ...) __CAST_TO_U64(a), __CAST4(__VA_ARGS__)
#define __CAST6(a, ...) __CAST_TO_U64(a), __CAST5(__VA_ARGS__)
#define __CAST7(a, ...) __CAST_TO_U64(a), __CAST6(__VA_ARGS__)
#define __CAST8(a, ...) __CAST_TO_U64(a), __CAST7(__VA_ARGS__)
#define __CAST9(a, ...) __CAST_TO_U64(a), __CAST8(__VA_ARGS__)
#define __CAST10(a ,...) __CAST_TO_U64(a), __CAST9(__VA_ARGS__)
#define __CAST11(a, ...) __CAST_TO_U64(a), __CAST10(__VA_ARGS__)
#define __CAST12(a, ...) __CAST_TO_U64(a), __CAST11(__VA_ARGS__)
/* tracepoints with more than 12 arguments will hit build error */
#define CAST_TO_U64(...) CONCATENATE(__CAST, COUNT_ARGS(__VA_ARGS__))(__VA_ARGS__)

#define UINTTYPE(size) \
	__typeof__(__builtin_choose_expr(size == 1,  (u8)1, \
		   __builtin_choose_expr(size == 2, (u16)2, \
		   __builtin_choose_expr(size == 4, (u32)3, \
		   __builtin_choose_expr(size == 8, (u64)4, \
					 (void)5)))))

#define UNPACK(...)			__VA_ARGS__
#define REPEAT_1(FN, DL, X, ...)	FN(X)
#define REPEAT_2(FN, DL, X, ...)	FN(X) UNPACK DL REPEAT_1(FN, DL, __VA_ARGS__)
#define REPEAT_3(FN, DL, X, ...)	FN(X) UNPACK DL REPEAT_2(FN, DL, __VA_ARGS__)
#define REPEAT_4(FN, DL, X, ...)	FN(X) UNPACK DL REPEAT_3(FN, DL, __VA_ARGS__)
#define REPEAT_5(FN, DL, X, ...)	FN(X) UNPACK DL REPEAT_4(FN, DL, __VA_ARGS__)
#define REPEAT_6(FN, DL, X, ...)	FN(X) UNPACK DL REPEAT_5(FN, DL, __VA_ARGS__)
#define REPEAT_7(FN, DL, X, ...)	FN(X) UNPACK DL REPEAT_6(FN, DL, __VA_ARGS__)
#define REPEAT_8(FN, DL, X, ...)	FN(X) UNPACK DL REPEAT_7(FN, DL, __VA_ARGS__)
#define REPEAT_9(FN, DL, X, ...)	FN(X) UNPACK DL REPEAT_8(FN, DL, __VA_ARGS__)
#define REPEAT_10(FN, DL, X, ...)	FN(X) UNPACK DL REPEAT_9(FN, DL, __VA_ARGS__)
#define REPEAT_11(FN, DL, X, ...)	FN(X) UNPACK DL REPEAT_10(FN, DL, __VA_ARGS__)
#define REPEAT_12(FN, DL, X, ...)	FN(X) UNPACK DL REPEAT_11(FN, DL, __VA_ARGS__)
#define REPEAT(X, FN, DL, ...)		REPEAT_##X(FN, DL, __VA_ARGS__)

#define SARG(X)		u64 arg##X
#ifdef COPY
#undef COPY
#endif

#define COPY(X)		args[X] = arg##X
#define __DL_COM	(,)
#define __DL_SEM	(;)

#define __SEQ_0_11	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11

#endif
#endif /* _LINUX_BPF_EVENT_H */

