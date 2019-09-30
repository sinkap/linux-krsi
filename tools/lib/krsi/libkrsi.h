/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LIB_KRSI_H
#define _LIB_KRSI_H

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define KRSI_PERF_MAP_NAME "perf_map"

/*
 * krsi_attach_attr allows the loading and attachment of KRSI eBPF programs
 * from a file or a buffer. The name of the hook is determined from the name of
 * ELF section containing the program. For example:
 * SEC("krsi/process_execution") will attach the program to the.
 * "process_execution" hook.
 */
struct krsi_attach_attr {
	// The file from which the programs must be loaded or the name of the
	// the object to be loaded from the buffer.
	union {
		const char *filename;
		const char *obj_name;
	};
	// If obj_buf is not NULL, the object is loaded from the buffer.
	void *obj_buf;
	// The size of the obj_buf.
	size_t obj_buf_sz;
	// The file descriptor of the per-cpu perf arary for receiving
	// the perf events from the KRSI programs.
	int perf_fd;
};

int krsi_create_perf_map(void);
int krsi_attach_xattr(struct krsi_attach_attr *attr,
		      struct bpf_object **prog_obj);
#endif // _LIB_KRSI_H
