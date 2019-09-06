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

int krsi_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	struct bpf_prog_array *old_array;
	struct bpf_prog_array *new_array;
	struct krsi_hook *h;
	int ret = 0;

	h = get_hook_from_fd(attr->target_fd);
	if (IS_ERR(h))
		return PTR_ERR(h);

	mutex_lock(&h->mutex);
	old_array = rcu_dereference_protected(h->progs,
					      lockdep_is_held(&h->mutex));

	ret = bpf_prog_array_copy(old_array, NULL, prog, &new_array);
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
	default:
		return NULL;
	}
}

const struct bpf_verifier_ops krsi_verifier_ops = {
	.get_func_proto = krsi_prog_func_proto,
	.is_valid_access = krsi_prog_is_valid_access,
};
