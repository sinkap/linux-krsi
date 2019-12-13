// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <linux/bpf.h>
#include <stdbool.h>
#include "bpf_helpers.h"
#include "bpf_trace_helpers.h"

char _license[] SEC("license") = "GPL";
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} perf_buf_map SEC(".maps");

#define MPROTECT_AUDIT_MAGIC 0xDEAD

struct mprotect_audit_log {
	int is_heap, magic;
};

/*
 * Define some of the structs used in the BPF program.
 * Only the field names and their sizes need to be the
 * same as the kernel type, the order is irrelevant.
 */
struct mm_struct {
	unsigned long start_brk, brk, start_stack;
};

struct vm_area_struct {
	unsigned long start_brk, brk, start_stack;
	unsigned long vm_start, vm_end;
	struct mm_struct *vm_mm;
	unsigned long vm_flags;
};

BPF_TRACE_3("lsm/file_mprotect", mprotect_audit,
	    struct vm_area_struct *, vma,
	    unsigned long, reqprot, unsigned long, prot)
{
	struct mprotect_audit_log audit_log = {};
	int is_heap = 0;

	__builtin_preserve_access_index(({
		is_heap = (vma->vm_start >= vma->vm_mm->start_brk &&
				     vma->vm_end <= vma->vm_mm->brk);
	}));

	audit_log.magic = MPROTECT_AUDIT_MAGIC;
	audit_log.is_heap = is_heap;
	bpf_lsm_event_output(&perf_buf_map, BPF_F_CURRENT_CPU, &audit_log,
			     sizeof(audit_log));
	return 0;
}
