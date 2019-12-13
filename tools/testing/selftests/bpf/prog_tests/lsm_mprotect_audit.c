// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <test_progs.h>
#include <sys/mman.h>
#include <unistd.h>
#include <malloc.h>

#define MPROTECT_AUDIT_MAGIC 0xDEAD

struct mprotect_audit_log {
	int is_heap, magic;
};

static void on_sample(void *ctx, int cpu, void *data, __u32 size)
{
	struct mprotect_audit_log *audit_log = data;
	int duration = 0;

	if (audit_log->magic != MPROTECT_AUDIT_MAGIC)
		return;

	if (CHECK(audit_log->is_heap != 1, "mprotect on heap",
		  "is_heap = %d\n", audit_log->is_heap))
		return;

	*(bool *)ctx = true;
}

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
	struct bpf_prog_load_attr attr = {
		.file = "./lsm_mprotect_audit.o",
	};

	struct perf_buffer_opts pb_opts = {};
	struct perf_buffer *pb = NULL;
	struct bpf_link *link = NULL;
	struct bpf_map *perf_buf_map;
	struct bpf_object *prog_obj;
	struct bpf_program *prog;
	int err, prog_fd;
	int duration = 0;
	bool passed = false;

	err = bpf_prog_load_xattr(&attr, &prog_obj, &prog_fd);
	if (CHECK(err, "prog_load lsm/file_mprotect",
		  "err %d errno %d\n", err, errno))
		goto close_prog;

	prog = bpf_object__find_program_by_title(prog_obj, "lsm/file_mprotect");
	if (CHECK(!prog, "find_prog", "lsm/file_mprotect not found\n"))
		goto close_prog;

	link = bpf_program__attach_lsm(prog);
	if (CHECK(IS_ERR(link), "attach_lsm file_mprotect",
				 "err %ld\n", PTR_ERR(link)))
		goto close_prog;

	perf_buf_map = bpf_object__find_map_by_name(prog_obj, "perf_buf_map");
	if (CHECK(!perf_buf_map, "find_perf_buf_map", "not found\n"))
		goto close_prog;

	/* set up perf buffer */
	pb_opts.sample_cb = on_sample;
	pb_opts.ctx = &passed;
	pb = perf_buffer__new(bpf_map__fd(perf_buf_map), 1, &pb_opts);
	if (CHECK(IS_ERR(pb), "perf_buf__new", "err %ld\n", PTR_ERR(pb)))
		goto close_prog;

	err = heap_mprotect();
	if (CHECK(err < 0, "heap_mprotect",
		  "err %d errno %d\n", err, errno))
		goto close_prog;

	/* read perf buffer */
	err = perf_buffer__poll(pb, 100);
	if (CHECK(err < 0, "perf_buffer__poll", "err %d\n", err))
		goto close_prog;

	/*
	 * make sure mprotect_audit program was triggered
	 * and detected an mprotect on the heap
	 */
	CHECK_FAIL(!passed);

close_prog:
	perf_buffer__free(pb);
	if (!IS_ERR_OR_NULL(link))
		bpf_link__destroy(link);
	bpf_object__close(prog_obj);
}
