#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <sys/sysinfo.h>
#include <linux/err.h>
#include <linux/limits.h>
#include <fcntl.h>

#include "libkrsi.h"

#define KRSI_TITLE_PREFIX "krsi/"
#define KRSI_TITLE_PREFIX_LEN 5
#define KRSI_SYSFS_DIR_PREFIX "/sys/kernel/security/krsi/"

static inline bool is_valid_krsi_title(const char *title)
{
	return memcmp(title,
		      KRSI_TITLE_PREFIX, KRSI_TITLE_PREFIX_LEN) == 0;
}

int krsi_create_perf_map(void)
{
	struct bpf_create_map_attr map_attr = {};
	int ncpus;

	ncpus = libbpf_num_possible_cpus();
	if (ncpus < 0)
		return ncpus;

	map_attr.name = KRSI_PERF_MAP_NAME;
	map_attr.map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY;
	map_attr.key_size = sizeof(int);
	map_attr.value_size = sizeof(int);
	map_attr.max_entries = ncpus;

	return bpf_create_map_xattr(&map_attr);
}

int krsi_attach_xattr(struct krsi_attach_attr *attr,
		      struct bpf_object **prog_obj)
{

	struct bpf_object_open_buffer_attr b_attr = {};
	struct bpf_object_open_attr f_attr = {};
	int prog_fd, target_fd, ret = 0;
	struct bpf_program *prog;
	char hook_path[PATH_MAX];
	struct bpf_object *obj;
	struct bpf_map *map;
	const char *title;

	if (!attr || !attr->filename)
		return -EINVAL;

	if (attr->obj_buf) {
		if (attr->obj_buf_sz <= 0)
			return -EINVAL;

		b_attr.obj_name = attr->obj_name;
		b_attr.obj_buf = attr->obj_buf;
		b_attr.obj_buf_sz = attr->obj_buf_sz;
		b_attr.prog_type = BPF_PROG_TYPE_KRSI;

		obj = bpf_object__open_buffer_xattr(&b_attr);
	} else {
		f_attr.file = attr->filename;
		f_attr.prog_type = BPF_PROG_TYPE_KRSI;
		obj = bpf_object__open_xattr(&f_attr);
	}

	if (IS_ERR(obj))
		return PTR_ERR(obj);

	bpf_object__for_each_program(prog, obj) {
		bpf_program__set_type(prog, BPF_PROG_TYPE_KRSI);
		bpf_program__set_expected_attach_type(prog, BPF_KRSI);
	}

	if (attr->perf_fd) {
		map = bpf_object__find_map_by_name(obj, KRSI_PERF_MAP_NAME);
		if (!map) {
			ret = -EINVAL;
			goto error;
		}

		ret = bpf_map__reuse_fd(map, attr->perf_fd);
		if (ret < 0) {
			goto error;
		}
	}

	ret = bpf_object__load(obj);
	if (ret < 0)
		return ret;

	bpf_object__for_each_program(prog, obj) {

		title = bpf_program__title(prog, false);
		if (!title) {
			ret = -EINVAL;
			goto error_unload;
		}

		if (!is_valid_krsi_title(title)) {
			ret = -EINVAL;
			goto error_unload;
		}

		strcpy(hook_path, KRSI_SYSFS_DIR_PREFIX);
		strcat(hook_path, title + KRSI_TITLE_PREFIX_LEN);

		/* Attach the BPF program to the given hook */
		target_fd = open(hook_path, O_RDWR);
		if (target_fd < 0) {
			ret = target_fd;
			goto error_unload;
		}

		prog_fd = bpf_program__fd(prog);
		if (prog_fd < 0) {
			ret = prog_fd;
			close(target_fd);
			goto error_unload;
		}

		ret = bpf_prog_attach(prog_fd, target_fd, BPF_KRSI,
			      BPF_F_ALLOW_OVERRIDE);
		if (ret < 0) {
			close(target_fd);
			goto error_unload;
		}

		close(target_fd);
	}

	*prog_obj = obj;
	return 0;

error_unload:
	bpf_object__unload(obj);
error:
	bpf_object__close(obj);
	return ret;
}
