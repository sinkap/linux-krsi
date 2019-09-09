// SPDX-License-Identifier: GPL-2.0

#include <linux/err.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/security.h>
#include <linux/krsi.h>

#include "krsi_init.h"
#include "krsi_fs.h"

extern struct krsi_hook krsi_hooks_list[];

static struct krsi_hook *get_hook_from_fd(int fd)
{
	struct fd f = fdget(fd);
	struct krsi_hook *h;
	int ret;

	if (!f.file) {
		ret = -EBADF;
		goto error;
	}

	/*
	 * Only CAP_MAC_ADMIN users are allowed to make
	 * changes to LSM hooks
	 */
	if (!capable(CAP_MAC_ADMIN)) {
		ret = -EPERM;
		goto error;
	}

	if (!is_krsi_hook_file(f.file)) {
		ret = -EINVAL;
		goto error;
	}

	/*
	 * It's wrong to attach the program to the hook
	 * if the file is not opened for a write. Note that,
	 * this is an EBADF and not an EPERM because the file
	 * has been opened with an incorrect mode.
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
 * a different version of the same program to be loaded.
 *
 * For example:
 *
 *	env_dumper__v1 is matched with env_dumper__v2
 *
 */
static bool match_prog_name(char *a, char *b)
{
	int m, n;
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

int krsi_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	struct bpf_prog_array *old_array;
	struct bpf_prog_array *new_array;
	struct krsi_hook *h;
	struct bpf_prog *old_prog;
	int ret = 0;

	h = get_hook_from_fd(attr->target_fd);
	if (IS_ERR(h))
		return PTR_ERR(h);

	mutex_lock(&h->mutex);
	old_array = rcu_dereference_protected(h->progs,
					      lockdep_is_held(&h->mutex));
	/*
	 * Check if a matching program with already exists and replace
	 * the existing program will be overridden if BPF_F_ALLOW_OVERRIDE
	 * is specified in the attach flags.
	 */
	old_prog = find_attached_prog(old_array, prog);
	if (old_prog && !(attr->attach_flags & BPF_F_ALLOW_OVERRIDE)) {
		ret = -EEXIST;
		goto unlock;
	}

	ret = bpf_prog_array_copy(old_array, old_prog, prog, &new_array);
	if (ret < 0) {
		ret = -ENOMEM;
		goto unlock;
	}

	rcu_assign_pointer(h->progs, new_array);
	bpf_prog_array_free(old_array);

unlock:
	mutex_unlock(&h->mutex);
	return ret;
}

const struct bpf_prog_ops krsi_prog_ops = {
};

static bool krsi_prog_is_valid_access(int off, int size,
				      enum bpf_access_type type,
				      const struct bpf_prog *prog,
				      struct bpf_insn_access_aux *info)
{
	/*
	 * KRSI is conservative about any direct access in eBPF to
	 * prevent the users from depending on the internals of the kernel and
	 * aims at providing a rich eco-system of safe eBPF helpers as an API
	 * for accessing relevant information from the context.
	 */
	return false;
}

BPF_CALL_5(krsi_event_output, void *, log,
	   struct bpf_map *, map, u64, flags, void *, data, u64, size)
{
	if (unlikely(flags & ~(BPF_F_INDEX_MASK)))
		return -EINVAL;

	return bpf_event_output(map, flags, data, size, NULL, 0, NULL);
}

static const struct bpf_func_proto krsi_event_output_proto =  {
	.func		= krsi_event_output,
	.gpl_only       = true,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_CONST_MAP_PTR,
	.arg3_type      = ARG_ANYTHING,
	.arg4_type      = ARG_PTR_TO_MEM,
	.arg5_type      = ARG_CONST_SIZE_OR_ZERO,
};

static const struct bpf_func_proto *krsi_prog_func_proto(enum bpf_func_id
							 func_id,
							 const struct bpf_prog
							 *prog)
{
	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_get_current_pid_tgid:
		return &bpf_get_current_pid_tgid_proto;
	case BPF_FUNC_perf_event_output:
		return &krsi_event_output_proto;
	default:
		return NULL;
	}
}

const struct bpf_verifier_ops krsi_verifier_ops = {
	.get_func_proto = krsi_prog_func_proto,
	.is_valid_access = krsi_prog_is_valid_access,
};
