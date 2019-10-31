/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf_event.h>

#undef TRACE_SYSTEM_VAR

#ifdef CONFIG_BPF_EVENTS

#undef __entry
#define __entry entry

#undef __get_dynamic_array
#define __get_dynamic_array(field)	\
		((void *)__entry + (__entry->__data_loc_##field & 0xffff))

#undef __get_dynamic_array_len
#define __get_dynamic_array_len(field)	\
		((__entry->__data_loc_##field >> 16) & 0xffff)

#undef __get_str
#define __get_str(field) ((char *)__get_dynamic_array(field))

#undef __get_bitmask
#define __get_bitmask(field) (char *)__get_dynamic_array(field)

#undef __perf_count
#define __perf_count(c)	(c)

#undef __perf_task
#define __perf_task(t)	(t)

#undef DECLARE_EVENT_CLASS
#define DECLARE_EVENT_CLASS(call, proto, args, tstruct, assign, print)	\
static notrace void							\
__bpf_trace_##call(void *__data, proto)					\
{									\
	struct bpf_prog *prog = __data;					\
	CONCATENATE(bpf_trace_run, COUNT_ARGS(args))(prog, CAST_TO_U64(args));	\
}

/*
 * This part is compiled out, it is only here as a build time check
 * to make sure that if the tracepoint handling changes, the
 * bpf probe will fail to compile unless it too is updated.
 */
#define __DEFINE_EVENT(template, call, proto, args, size)		\
static inline void bpf_test_probe_##call(void)				\
{									\
	check_trace_callback_type_##call(__bpf_trace_##template);	\
}									\
typedef void (*btf_trace_##call)(void *__data, proto);			\
static struct bpf_raw_event_map	__used					\
	__attribute__((section("__bpf_raw_tp_map")))			\
__bpf_trace_tp_map_##call = {						\
	.tp		= &__tracepoint_##call,				\
	.bpf_func	= (void *)(btf_trace_##call)__bpf_trace_##template,	\
	.num_args	= COUNT_ARGS(args),				\
	.writable_size	= size,						\
};

#define FIRST(x, ...) x

#undef DEFINE_EVENT_WRITABLE
#define DEFINE_EVENT_WRITABLE(template, call, proto, args, size)	\
static inline void bpf_test_buffer_##call(void)				\
{									\
	/* BUILD_BUG_ON() is ignored if the code is completely eliminated, but \
	 * BUILD_BUG_ON_ZERO() uses a different mechanism that is not	\
	 * dead-code-eliminated.					\
	 */								\
	FIRST(proto);							\
	(void)BUILD_BUG_ON_ZERO(size != sizeof(*FIRST(args)));		\
}									\
__DEFINE_EVENT(template, call, PARAMS(proto), PARAMS(args), size)

#undef DEFINE_EVENT
#define DEFINE_EVENT(template, call, proto, args)			\
	__DEFINE_EVENT(template, call, PARAMS(proto), PARAMS(args), 0)

#undef DEFINE_EVENT_PRINT
#define DEFINE_EVENT_PRINT(template, name, proto, args, print)	\
	DEFINE_EVENT(template, name, PARAMS(proto), PARAMS(args))

#include TRACE_INCLUDE(TRACE_INCLUDE_FILE)

#undef DEFINE_EVENT_WRITABLE
#undef __DEFINE_EVENT
#undef FIRST

#endif /* CONFIG_BPF_EVENTS */
