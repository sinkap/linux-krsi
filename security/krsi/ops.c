// SPDX-License-Identifier: GPL-2.0

#include <linux/err.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/security.h>
#include <linux/krsi.h>
#include <linux/binfmts.h>
#include <linux/highmem.h>

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

static char *array_next_entry(char *array, unsigned long *offset,
			      unsigned long end)
{
	char *entry;
	unsigned long current_offset = *offset;

	if (current_offset >= end)
		return NULL;

	/*
	 * iterate on the array till the null byte is encountered
	 * and check for any overflows.
	 */
	entry = array + current_offset;
	while (array[current_offset]) {
		if (unlikely(++current_offset >= end))
			return NULL;
	}

	/*
	 * Point the offset to the next element in the array.
	 */
	*offset = current_offset + 1;

	return entry;
}

static u64 get_env_var(struct krsi_ctx *ctx, char *name, char *dest,
		u32 n_size, u32 size)
{
	s32 ret = 0;
	u32 num_vars = 0;
	int i, name_len;
	struct linux_binprm *bprm = ctx->bprm_ctx.bprm;
	int argc = bprm->argc;
	int envc = bprm->envc;
	unsigned long end = ctx->bprm_ctx.max_arg_offset;
	unsigned long offset = bprm->p % PAGE_SIZE;
	char *buf = ctx->bprm_ctx.arg_pages;
	char *curr_dest = dest;
	char *entry;

	if (unlikely(!buf))
		return -ENOMEM;

	for (i = 0; i < argc; i++) {
		entry = array_next_entry(buf, &offset, end);
		if (!entry)
			return 0;
	}

	name_len = strlen(name);
	for (i = 0; i < envc; i++) {
		entry = array_next_entry(buf, &offset, end);
		if (!entry)
			return 0;

		if (!strncmp(entry, name, name_len)) {
			num_vars++;

			/*
			 * There is no need to do further copying
			 * if the buffer is already full. Just count how many
			 * times the environment variable is set.
			 */
			if (ret == -E2BIG)
				continue;

			if (entry[name_len] != '=')
				continue;

			/*
			 * Move the buf pointer by name_len + 1
			 * (for the "=" sign)
			 */
			entry += name_len + 1;
			ret = strlcpy(curr_dest, entry, size);

			if (ret >= size) {
				ret = -E2BIG;
				continue;
			}

			/*
			 * strlcpy just returns the length of the string copied.
			 * The remaining space needs to account for the added
			 * null character.
			 */
			curr_dest += ret + 1;
			size -= ret + 1;
			/*
			 * Update ret to be the current number of bytes written
			 * to the destination
			 */
			ret = curr_dest - dest;
		}
	}

	return (u64) num_vars << 32 | (u32) ret;
}

BPF_CALL_5(krsi_get_env_var, struct krsi_ctx *, ctx, char *, name, u32, n_size,
	  char *, dest, u32, size)
{
	char *name_end;

	name_end = memchr(name, '\0', n_size);
	if (!name_end)
		return -EINVAL;

	memset(dest, 0, size);
	return get_env_var(ctx, name, dest, n_size, size);
}

static const struct bpf_func_proto krsi_get_env_var_proto = {
	.func = krsi_get_env_var,
	.gpl_only = true,
	.ret_type = RET_INTEGER,
	.arg1_type = ARG_PTR_TO_CTX,
	.arg2_type = ARG_PTR_TO_MEM,
	.arg3_type = ARG_CONST_SIZE_OR_ZERO,
	.arg4_type = ARG_PTR_TO_UNINIT_MEM,
	.arg5_type = ARG_CONST_SIZE_OR_ZERO,
};

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
	case BPF_FUNC_krsi_get_env_var:
		return &krsi_get_env_var_proto;
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
