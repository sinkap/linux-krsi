// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2019 Google LLC.
 */

#include <linux/err.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/security.h>
#include <linux/bpf_lsm.h>

#include "bpf_lsm.h"
#include "fs.h"

static struct bpf_lsm_hook *get_hook_from_fd(int fd)
{
	struct bpf_lsm_hook *h;
	struct fd f;
	int ret;

	/*
	 * Only CAP_MAC_ADMIN users are allowed to make changes to LSM hooks
	 */
	if (!capable(CAP_MAC_ADMIN))
		return ERR_PTR(-EPERM);


	f = fdget(fd);
	if (!f.file)
		return ERR_PTR(-EBADF);


	if (!is_bpf_lsm_hook_file(f.file)) {
		ret = -EINVAL;
		goto error;
	}

	/*
	 * It's wrong to attach the program to the hook if the file is not
	 * opened for a writing. Note that, this is an EBADF and not an EPERM
	 * because the file has been opened with an incorrect mode.
	 */
	if (!(f.file->f_mode & FMODE_WRITE)) {
		ret = -EBADF;
		goto error;
	}

	/*
	 * The securityfs dentry never disappears, so we don't need to take a
	 * reference to it.
	 */
	h = file_dentry(f.file)->d_fsdata;
	if (WARN_ON(!h)) {
		ret = -EINVAL;
		goto error;
	}
	fdput(f);
	return h;

error:
	fdput(f);
	return ERR_PTR(ret);
}

/*
 * match_prog_name matches the name of the program till "__"
 * or the end of the string is encountered. This allows
 * the matched program to be replaced by a newer version.
 *
 * For example:
 *
 *	env_dumper__v1 is matched with env_dumper__v2
 *
 */
static bool match_prog_name(const char *a, const char *b)
{
	size_t m, n;
	char *end;

	end = strstr(a, "__");
	n = end ? end - a : strlen(a);

	end = strstr(b, "__");
	m = end ? end - b : strlen(b);

	if (m != n)
		return false;

	return strncmp(a, b, n) == 0;
}

static struct bpf_prog *find_attached_prog(struct bpf_prog_array *array,
					   struct bpf_prog *prog)
{
	struct bpf_prog_array_item *item = array->items;

	for (; item->prog; item++) {
		if (match_prog_name(item->prog->aux->name, prog->aux->name))
			return item->prog;
	}

	return NULL;
}

int bpf_lsm_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	struct bpf_prog_array *old_array;
	struct bpf_prog_array *new_array;
	struct bpf_lsm_hook *h;
	struct bpf_prog *old_prog = NULL;
	int ret = 0;

	h = get_hook_from_fd(attr->target_fd);
	if (IS_ERR(h))
		return PTR_ERR(h);

	mutex_lock(&h->mutex);
	old_array = rcu_dereference_protected(h->progs,
					      lockdep_is_held(&h->mutex));
	/*
	 * Check if a matching program already exists and replace
	 * the existing program if BPF_F_ALLOW_OVERRIDE is specified in
	 * the attach flags.
	 */
	if (old_array) {
		old_prog = find_attached_prog(old_array, prog);
		if (old_prog && !(attr->attach_flags & BPF_F_ALLOW_OVERRIDE)) {
			ret = -EEXIST;
			goto unlock;
		}
	}

	ret = bpf_prog_array_copy(old_array, old_prog, prog, &new_array);
	if (ret < 0)
		goto unlock;

	rcu_assign_pointer(h->progs, new_array);
	bpf_prog_array_free(old_array);
	if (old_prog)
		bpf_prog_put(old_prog);

unlock:
	mutex_unlock(&h->mutex);
	return ret;
}

int bpf_lsm_detach(const union bpf_attr *attr)
{
	struct bpf_prog_array *old_array, *new_array;
	struct bpf_prog *prog;
	struct bpf_lsm_hook *h;
	int ret = 0;

	if (attr->attach_flags)
		return -EINVAL;

	h = get_hook_from_fd(attr->target_fd);
	if (IS_ERR(h))
		return PTR_ERR(h);

	prog = bpf_prog_get_type(attr->attach_bpf_fd,
				 BPF_PROG_TYPE_LSM);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	mutex_lock(&h->mutex);
	old_array = rcu_dereference_protected(h->progs,
					      lockdep_is_held(&h->mutex));

	ret = bpf_prog_array_copy(old_array, prog, NULL, &new_array);
	if (ret)
		goto unlock;

	rcu_assign_pointer(h->progs, new_array);
	bpf_prog_array_free(old_array);
unlock:
	bpf_prog_put(prog);
	mutex_unlock(&h->mutex);
	return ret;
}

const struct bpf_prog_ops lsm_prog_ops = {
};

BPF_CALL_4(bpf_lsm_event_output,
	   struct bpf_map *, map, u64, flags, void *, data, u64, size)
{
	if (unlikely(flags & ~(BPF_F_INDEX_MASK)))
		return -EINVAL;

	return bpf_event_output(map, flags, data, size, NULL, 0, NULL);
}

static const struct bpf_func_proto bpf_lsm_event_output_proto =  {
	.func		= bpf_lsm_event_output,
	.gpl_only       = true,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_CONST_MAP_PTR,
	.arg2_type      = ARG_ANYTHING,
	.arg3_type      = ARG_PTR_TO_MEM,
	.arg4_type      = ARG_CONST_SIZE_OR_ZERO,
};

static const struct bpf_func_proto *get_bpf_func_proto(enum bpf_func_id
		func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_get_current_pid_tgid:
		return &bpf_get_current_pid_tgid_proto;
	case BPF_FUNC_lsm_event_output:
		return &bpf_lsm_event_output_proto;
	default:
		return NULL;
	}
}

const struct bpf_verifier_ops lsm_verifier_ops = {
	.get_func_proto = get_bpf_func_proto,
	.is_valid_access = btf_ctx_access,
};
