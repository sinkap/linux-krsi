// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <linux/bpf.h>
#include <stdbool.h>
#include "bpf_helpers.h"
#include "bpf_trace_helpers.h"
#include "lsm_helpers.h"

char _license[] SEC("license") = "GPL";

struct lsm_mprotect_audit_result result = {
	.count = 0,
	.monitored_pid = 0,
};

/*
 * Define some of the structs used in the BPF program.
 * Only the field names and their sizes need to be the
 * same as the kernel type, the order is irrelevant.
 */
struct mm_struct {
	unsigned long start_brk, brk, start_stack;
} __attribute__((preserve_access_index));

struct vm_area_struct {
	unsigned long start_brk, brk, start_stack;
	unsigned long vm_start, vm_end;
	struct mm_struct *vm_mm;
	unsigned long vm_flags;
} __attribute__((preserve_access_index));

BPF_TRACE_3("lsm/file_mprotect", mprotect_audit,
	    struct vm_area_struct *, vma,
	    unsigned long, reqprot, unsigned long, prot)
{
	__u32 pid = bpf_get_current_pid_tgid();
	int is_heap = 0;

	is_heap = (vma->vm_start >= vma->vm_mm->start_brk &&
		   vma->vm_end <= vma->vm_mm->brk);

	if (is_heap && result.monitored_pid == pid)
		result.count++;

	return 0;
}
