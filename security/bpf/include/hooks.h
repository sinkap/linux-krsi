/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright 2019 Google LLC.
 *
 * The hooks for the KRSI LSM are declared in this file.
 *
 * This header MUST NOT be included directly and is included inline
 * for generating various data structurs for the hooks using the
 * following pattern:
 *
 * #define BPF_LSM_HOOK RET NAME(PROTO);
 * #include "hooks.h"
 * #undef BPF_LSM_HOOK
 *
 * Format:
 *
 *	BPF_LSM_HOOK(NAME, RET, PROTO, ARGS)
 *
 */
#define BPF_LSM_ARGS(args...) args

BPF_LSM_HOOK(binder_set_context_mgr,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct task_struct *mgr),
	     BPF_LSM_ARGS(mgr))
BPF_LSM_HOOK(binder_transaction,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct task_struct *from, struct task_struct *to),
	     BPF_LSM_ARGS(from, to))
BPF_LSM_HOOK(binder_transfer_binder,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct task_struct *from, struct task_struct *to),
	     BPF_LSM_ARGS(from, to))
BPF_LSM_HOOK(binder_transfer_file,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct task_struct *from, struct task_struct *to,
			  struct file *file),
	     BPF_LSM_ARGS(from, to, file))
BPF_LSM_HOOK(ptrace_access_check,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct task_struct *child, unsigned int mode),
	     BPF_LSM_ARGS(child, mode))
BPF_LSM_HOOK(ptrace_traceme,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct task_struct *parent),
	     BPF_LSM_ARGS(parent))
BPF_LSM_HOOK(capget,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct task_struct *target, kernel_cap_t *effective,
		     kernel_cap_t *inheritable, kernel_cap_t *permitted),
	     BPF_LSM_ARGS(target, effective, inheritable, permitted))
BPF_LSM_HOOK(capset,
	 ATOMIC,
	 int,
	 BPF_LSM_ARGS(struct cred *new, const struct cred *old,
		     const kernel_cap_t *effective,
		     const kernel_cap_t *inheritable,
		     const kernel_cap_t *permitted),
	 BPF_LSM_ARGS(new, old, effective, inheritable, permitted))
BPF_LSM_HOOK(capable,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const struct cred *cred, struct user_namespace *ns,
	      int cap, unsigned int opts),
	     BPF_LSM_ARGS(cred, ns, cap, opts))
BPF_LSM_HOOK(quotactl,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(int cmds, int type, int id, struct super_block *sb),
	     BPF_LSM_ARGS(cmds, type, id, sb))
BPF_LSM_HOOK(quota_on,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry),
	     BPF_LSM_ARGS(dentry))
BPF_LSM_HOOK(syslog,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(int type),
	     BPF_LSM_ARGS(type))
BPF_LSM_HOOK(settime,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const struct timespec64 *ts,
			  const struct timezone *tz),
	     BPF_LSM_ARGS(ts, tz))
BPF_LSM_HOOK(vm_enough_memory,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct mm_struct *mm, long pages),
	     BPF_LSM_ARGS(mm, pages))
BPF_LSM_HOOK(bprm_set_creds,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct linux_binprm *bprm),
	     BPF_LSM_ARGS(bprm))
BPF_LSM_HOOK(bprm_check_security,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct linux_binprm *bprm),
	     BPF_LSM_ARGS(bprm))
BPF_LSM_HOOK(bprm_committing_creds,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct linux_binprm *bprm),
	     BPF_LSM_ARGS(bprm))
BPF_LSM_HOOK(bprm_committed_creds,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct linux_binprm *bprm),
	     BPF_LSM_ARGS(bprm))
BPF_LSM_HOOK(fs_context_dup,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct fs_context *fc, struct fs_context *src_sc),
	     BPF_LSM_ARGS(fc, src_sc))
BPF_LSM_HOOK(fs_context_parse_param,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct fs_context *fc, struct fs_parameter *param),
	     BPF_LSM_ARGS(fc, param))
BPF_LSM_HOOK(sb_alloc_security,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct super_block *sb),
	     BPF_LSM_ARGS(sb))
BPF_LSM_HOOK(sb_free_security,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct super_block *sb),
	     BPF_LSM_ARGS(sb))
BPF_LSM_HOOK(sb_free_mnt_opts,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(void *mnt_opts),
	     BPF_LSM_ARGS(mnt_opts))
BPF_LSM_HOOK(sb_eat_lsm_opts,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(char *orig, void **mnt_opts),
	     BPF_LSM_ARGS(orig, mnt_opts))
BPF_LSM_HOOK(sb_remount,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct super_block *sb, void *mnt_opts),
	     BPF_LSM_ARGS(sb, mnt_opts))
BPF_LSM_HOOK(sb_kern_mount,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct super_block *sb),
	     BPF_LSM_ARGS(sb))
BPF_LSM_HOOK(sb_show_options,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct seq_file *m, struct super_block *sb),
	     BPF_LSM_ARGS(m, sb))
BPF_LSM_HOOK(sb_statfs,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry),
	     BPF_LSM_ARGS(dentry))
BPF_LSM_HOOK(sb_mount,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const char *dev_name, const struct path *path,
		      const char *type, unsigned long flags, void *data),
	     BPF_LSM_ARGS(dev_name, path, type, flags, data))
BPF_LSM_HOOK(sb_umount,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct vfsmount *mnt, int flags),
	     BPF_LSM_ARGS(mnt, flags))
BPF_LSM_HOOK(sb_pivotroot,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const struct path *old_path,
			  const struct path *new_path),
	     BPF_LSM_ARGS(old_path, new_path))
BPF_LSM_HOOK(sb_set_mnt_opts,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct super_block *sb, void *mnt_opts,
		     unsigned long kern_flags, unsigned long *set_kern_flags),
	     BPF_LSM_ARGS(sb, mnt_opts, kern_flags, set_kern_flags))
BPF_LSM_HOOK(sb_clone_mnt_opts,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const struct super_block *oldsb,
			  struct super_block *newsb, unsigned long kern_flags,
			  unsigned long *set_kern_flags),
	     BPF_LSM_ARGS(oldsb, newsb, kern_flags, set_kern_flags))
BPF_LSM_HOOK(sb_add_mnt_opt,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const char *option, const char *val, int len,
		     void **mnt_opts),
	     BPF_LSM_ARGS(option, val, len, mnt_opts))
BPF_LSM_HOOK(move_mount,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const struct path *from_path,
			  const struct path *to_path),
	     BPF_LSM_ARGS(from_path, to_path))
BPF_LSM_HOOK(dentry_init_security,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry, int mode,
			  const struct qstr *name,
		     void **ctx, u32 *ctxlen),
	     BPF_LSM_ARGS(dentry, mode, name, ctx, ctxlen))
BPF_LSM_HOOK(dentry_create_files_as,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry, int mode, struct qstr *name,
		     const struct cred *old, struct cred *new),
	     BPF_LSM_ARGS(dentry, mode, name, old, new))

#ifdef CONFIG_SECURITY_PATH
BPF_LSM_HOOK(path_unlink,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const struct path *dir, struct dentry *dentry),
	     BPF_LSM_ARGS(dir, dentry))
BPF_LSM_HOOK(path_mkdir,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const struct path *dir, struct dentry *dentry,
		     umode_t mode),
	     BPF_LSM_ARGS(dir, dentry, mode))
BPF_LSM_HOOK(path_rmdir,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const struct path *dir, struct dentry *dentry),
	     BPF_LSM_ARGS(dir, dentry))
BPF_LSM_HOOK(path_mknod,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const struct path *dir, struct dentry *dentry,
			  umode_t mode,
		     unsigned int dev),
	     BPF_LSM_ARGS(dir, dentry, mode, dev))
BPF_LSM_HOOK(path_truncate,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const struct path *path),
	     BPF_LSM_ARGS(path))
BPF_LSM_HOOK(path_symlink,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const struct path *dir, struct dentry *dentry,
		     const char *old_name),
	     BPF_LSM_ARGS(dir, dentry, old_name))
BPF_LSM_HOOK(path_link,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct dentry *old_dentry, const struct path *new_dir,
		     struct dentry *new_dentry),
	     BPF_LSM_ARGS(old_dentry, new_dir, new_dentry))
BPF_LSM_HOOK(path_rename,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const struct path *old_dir, struct dentry *old_dentry,
		     const struct path *new_dir, struct dentry *new_dentry),
	     BPF_LSM_ARGS(old_dir, old_dentry, new_dir, new_dentry))
BPF_LSM_HOOK(path_chmod,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const struct path *path, umode_t mode),
	     BPF_LSM_ARGS(path, mode))
BPF_LSM_HOOK(path_chown,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const struct path *path, kuid_t uid, kgid_t gid),
	     BPF_LSM_ARGS(path, uid, gid))
BPF_LSM_HOOK(path_chroot,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const struct path *path),
	     BPF_LSM_ARGS(path))
#endif /* CONFIG_SECURITY_PATH */

BPF_LSM_HOOK(path_notify,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const struct path *path, u64 mask,
			  unsigned int obj_type),
	     BPF_LSM_ARGS(path, mask, obj_type))
BPF_LSM_HOOK(inode_alloc_security,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct inode *inode),
	     BPF_LSM_ARGS(inode))
BPF_LSM_HOOK(inode_free_security,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct inode *inode),
	     BPF_LSM_ARGS(inode))
BPF_LSM_HOOK(inode_init_security,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct inode *inode, struct inode *dir,
		     const struct qstr *qstr, const char **name, void **value,
		     size_t *len),
	     BPF_LSM_ARGS(inode, dir, qstr, name, value, len))
BPF_LSM_HOOK(inode_create,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct inode *dir, struct dentry *dentry,
			  umode_t mode),
	     BPF_LSM_ARGS(dir, dentry, mode))
BPF_LSM_HOOK(inode_link,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct dentry *old_dentry, struct inode *dir,
		     struct dentry *new_dentry),
	     BPF_LSM_ARGS(old_dentry, dir, new_dentry))
BPF_LSM_HOOK(inode_unlink,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct inode *dir, struct dentry *dentry),
	     BPF_LSM_ARGS(dir, dentry))
BPF_LSM_HOOK(inode_symlink,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct inode *dir, struct dentry *dentry,
		     const char *old_name),
	     BPF_LSM_ARGS(dir, dentry, old_name))
BPF_LSM_HOOK(inode_mkdir,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct inode *dir, struct dentry *dentry,
			  umode_t mode),
	     BPF_LSM_ARGS(dir, dentry, mode))
BPF_LSM_HOOK(inode_rmdir,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct inode *dir, struct dentry *dentry),
	     BPF_LSM_ARGS(dir, dentry))
BPF_LSM_HOOK(inode_mknod,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct inode *dir, struct dentry *dentry,
			  umode_t mode,
		     dev_t dev),
	     BPF_LSM_ARGS(dir, dentry, mode, dev))
BPF_LSM_HOOK(inode_rename,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct inode *old_dir, struct dentry *old_dentry,
		     struct inode *new_dir, struct dentry *new_dentry),
	     BPF_LSM_ARGS(old_dir, old_dentry, new_dir, new_dentry))
BPF_LSM_HOOK(inode_readlink,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry),
	     BPF_LSM_ARGS(dentry))
BPF_LSM_HOOK(inode_follow_link,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry, struct inode *inode, bool rcu),
	     BPF_LSM_ARGS(dentry, inode, rcu))
BPF_LSM_HOOK(inode_permission,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct inode *inode, int mask),
	     BPF_LSM_ARGS(inode, mask))
BPF_LSM_HOOK(inode_setattr,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry, struct iattr *attr),
	     BPF_LSM_ARGS(dentry, attr))
BPF_LSM_HOOK(inode_getattr,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const struct path *path),
	     BPF_LSM_ARGS(path))
BPF_LSM_HOOK(inode_setxattr,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry, const char *name,
			  const void *value,
		     size_t size, int flags),
	     BPF_LSM_ARGS(dentry, name, value, size, flags))
BPF_LSM_HOOK(inode_post_setxattr,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct dentry *dentry, const char *name,
			  const void *value,
		     size_t size, int flags),
	     BPF_LSM_ARGS(dentry, name, value, size, flags))
BPF_LSM_HOOK(inode_getxattr,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry, const char *name),
	     BPF_LSM_ARGS(dentry, name))
BPF_LSM_HOOK(inode_listxattr,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry),
	     BPF_LSM_ARGS(dentry))
BPF_LSM_HOOK(inode_removexattr,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry, const char *name),
	     BPF_LSM_ARGS(dentry, name))
BPF_LSM_HOOK(inode_need_killpriv,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry),
	     BPF_LSM_ARGS(dentry))
BPF_LSM_HOOK(inode_killpriv,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry),
	     BPF_LSM_ARGS(dentry))
BPF_LSM_HOOK(inode_getsecurity,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct inode *inode, const char *name, void **buffer,
		     bool alloc),
	     BPF_LSM_ARGS(inode, name, buffer, alloc))
BPF_LSM_HOOK(inode_setsecurity,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct inode *inode, const char *name,
			  const void *value,
		     size_t size, int flags),
	     BPF_LSM_ARGS(inode, name, value, size, flags))
BPF_LSM_HOOK(inode_listsecurity,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct inode *inode, char *buffer,
			  size_t buffer_size),
	     BPF_LSM_ARGS(inode, buffer, buffer_size))
BPF_LSM_HOOK(inode_getsecid,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct inode *inode, u32 *secid),
	     BPF_LSM_ARGS(inode, secid))
BPF_LSM_HOOK(inode_copy_up,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct dentry *src, struct cred **new),
	     BPF_LSM_ARGS(src, new))
BPF_LSM_HOOK(inode_copy_up_xattr,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const char *name),
	     BPF_LSM_ARGS(name))
BPF_LSM_HOOK(kernfs_init_security,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct kernfs_node *kn_dir, struct kernfs_node *kn),
	     BPF_LSM_ARGS(kn_dir, kn))
BPF_LSM_HOOK(file_permission,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct file *file, int mask),
	     BPF_LSM_ARGS(file, mask))
BPF_LSM_HOOK(file_alloc_security,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct file *file),
	     BPF_LSM_ARGS(file))
BPF_LSM_HOOK(file_free_security,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct file *file),
	     BPF_LSM_ARGS(file))
BPF_LSM_HOOK(file_ioctl,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct file *file, unsigned int cmd,
			  unsigned long arg),
	     BPF_LSM_ARGS(file, cmd, arg))
BPF_LSM_HOOK(mmap_addr,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(unsigned long addr),
	     BPF_LSM_ARGS(addr))
BPF_LSM_HOOK(mmap_file,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct file *file, unsigned long reqprot,
		     unsigned long prot, unsigned long flags),
	     BPF_LSM_ARGS(file, reqprot, prot, flags))
BPF_LSM_HOOK(file_mprotect,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct vm_area_struct *vma, unsigned long reqprot,
		     unsigned long prot),
	     BPF_LSM_ARGS(vma, reqprot, prot))
BPF_LSM_HOOK(file_lock,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct file *file, unsigned int cmd),
	     BPF_LSM_ARGS(file, cmd))
BPF_LSM_HOOK(file_fcntl,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct file *file, unsigned int cmd,
			  unsigned long arg),
	     BPF_LSM_ARGS(file, cmd, arg))
BPF_LSM_HOOK(file_set_fowner,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct file *file),
	     BPF_LSM_ARGS(file))
BPF_LSM_HOOK(file_send_sigiotask,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct task_struct *tsk, struct fown_struct *fown,
			  int sig),
	     BPF_LSM_ARGS(tsk, fown, sig))
BPF_LSM_HOOK(file_receive,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct file *file),
	     BPF_LSM_ARGS(file))
BPF_LSM_HOOK(file_open,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct file *file),
	     BPF_LSM_ARGS(file))
BPF_LSM_HOOK(task_alloc,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct task_struct *task, unsigned long clone_flags),
	     BPF_LSM_ARGS(task, clone_flags))
BPF_LSM_HOOK(task_free,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct task_struct *task),
	     BPF_LSM_ARGS(task))
BPF_LSM_HOOK(cred_alloc_blank,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct cred *cred, gfp_t gfp),
	     BPF_LSM_ARGS(cred, gfp))
BPF_LSM_HOOK(cred_free,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct cred *cred),
	     BPF_LSM_ARGS(cred))
BPF_LSM_HOOK(cred_prepare,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct cred *new, const struct cred *old, gfp_t gfp),
	     BPF_LSM_ARGS(new, old, gfp))
BPF_LSM_HOOK(cred_transfer,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct cred *new, const struct cred *old),
	     BPF_LSM_ARGS(new, old))
BPF_LSM_HOOK(cred_getsecid,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(const struct cred *c, u32 *secid),
	     BPF_LSM_ARGS(c, secid))
BPF_LSM_HOOK(kernel_act_as,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct cred *new, u32 secid),
	     BPF_LSM_ARGS(new, secid))
BPF_LSM_HOOK(kernel_create_files_as,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct cred *new, struct inode *inode),
	     BPF_LSM_ARGS(new, inode))
BPF_LSM_HOOK(kernel_module_request,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(char *kmod_name),
	     BPF_LSM_ARGS(kmod_name))
BPF_LSM_HOOK(kernel_load_data,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(enum kernel_load_data_id id),
	     BPF_LSM_ARGS(id))
BPF_LSM_HOOK(kernel_read_file,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct file *file, enum kernel_read_file_id id),
	     BPF_LSM_ARGS(file, id))
BPF_LSM_HOOK(kernel_post_read_file,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct file *file, char *buf, loff_t size,
		     enum kernel_read_file_id id),
	     BPF_LSM_ARGS(file, buf, size, id))
BPF_LSM_HOOK(task_fix_setuid,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct cred *new, const struct cred *old, int flags),
	     BPF_LSM_ARGS(new, old, flags))
BPF_LSM_HOOK(task_setpgid,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p, pid_t pgid),
	     BPF_LSM_ARGS(p, pgid))
BPF_LSM_HOOK(task_getpgid,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p),
	     BPF_LSM_ARGS(p))
BPF_LSM_HOOK(task_getsid,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p),
	     BPF_LSM_ARGS(p))
BPF_LSM_HOOK(task_getsecid,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct task_struct *p, u32 *secid),
	     BPF_LSM_ARGS(p, secid))
BPF_LSM_HOOK(task_setnice,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p, int nice),
	     BPF_LSM_ARGS(p, nice))
BPF_LSM_HOOK(task_setioprio,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p, int ioprio),
	     BPF_LSM_ARGS(p, ioprio))
BPF_LSM_HOOK(task_getioprio,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p),
	     BPF_LSM_ARGS(p))
BPF_LSM_HOOK(task_prlimit,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const struct cred *cred, const struct cred *tcred,
		     unsigned int flags),
	     BPF_LSM_ARGS(cred, tcred, flags))
BPF_LSM_HOOK(task_setrlimit,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p, unsigned int resource,
		     struct rlimit *new_rlim),
	     BPF_LSM_ARGS(p, resource, new_rlim))
BPF_LSM_HOOK(task_setscheduler,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p),
	     BPF_LSM_ARGS(p))
BPF_LSM_HOOK(task_getscheduler,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p),
	     BPF_LSM_ARGS(p))
BPF_LSM_HOOK(task_movememory,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p),
	     BPF_LSM_ARGS(p))
BPF_LSM_HOOK(task_kill,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p, struct kernel_siginfo *info,
			  int sig,
		     const struct cred *cred),
	     BPF_LSM_ARGS(p, info, sig, cred))
BPF_LSM_HOOK(task_prctl,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(int option, unsigned long arg2, unsigned long arg3,
		     unsigned long arg4, unsigned long arg5),
	     BPF_LSM_ARGS(option, arg2, arg3, arg4, arg5))
BPF_LSM_HOOK(task_to_inode,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct task_struct *p, struct inode *inode),
	     BPF_LSM_ARGS(p, inode))
BPF_LSM_HOOK(ipc_permission,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *ipcp, short flag),
	     BPF_LSM_ARGS(ipcp, flag))
BPF_LSM_HOOK(ipc_getsecid,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct kern_ipc_perm *ipcp, u32 *secid),
	     BPF_LSM_ARGS(ipcp, secid))
BPF_LSM_HOOK(msg_msg_alloc_security,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct msg_msg *msg),
	     BPF_LSM_ARGS(msg))
BPF_LSM_HOOK(msg_msg_free_security,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct msg_msg *msg),
	     BPF_LSM_ARGS(msg))
BPF_LSM_HOOK(msg_queue_alloc_security,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm),
	     BPF_LSM_ARGS(perm))
BPF_LSM_HOOK(msg_queue_free_security,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm),
	     BPF_LSM_ARGS(perm))
BPF_LSM_HOOK(msg_queue_associate,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm, int msqflg),
	     BPF_LSM_ARGS(perm, msqflg))
BPF_LSM_HOOK(msg_queue_msgctl,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm, int cmd),
	     BPF_LSM_ARGS(perm, cmd))
BPF_LSM_HOOK(msg_queue_msgsnd,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm, struct msg_msg *msg,
			  int msqflg),
	     BPF_LSM_ARGS(perm, msg, msqflg))
BPF_LSM_HOOK(msg_queue_msgrcv,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm, struct msg_msg *msg,
		     struct task_struct *target, long type, int mode),
	     BPF_LSM_ARGS(perm, msg, target, type, mode))
BPF_LSM_HOOK(shm_alloc_security,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm),
	     BPF_LSM_ARGS(perm))
BPF_LSM_HOOK(shm_free_security,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm),
	     BPF_LSM_ARGS(perm))
BPF_LSM_HOOK(shm_associate,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm, int shmflg),
	     BPF_LSM_ARGS(perm, shmflg))
BPF_LSM_HOOK(shm_shmctl,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm, int cmd),
	     BPF_LSM_ARGS(perm, cmd))
BPF_LSM_HOOK(shm_shmat,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm, char __user *shmaddr,
		     int shmflg),
	     BPF_LSM_ARGS(perm, shmaddr, shmflg))
BPF_LSM_HOOK(sem_alloc_security,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm),
	     BPF_LSM_ARGS(perm))
BPF_LSM_HOOK(sem_free_security,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm),
	     BPF_LSM_ARGS(perm))
BPF_LSM_HOOK(sem_associate,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm, int semflg),
	     BPF_LSM_ARGS(perm, semflg))
BPF_LSM_HOOK(sem_semctl,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm, int cmd),
	     BPF_LSM_ARGS(perm, cmd))
BPF_LSM_HOOK(sem_semop,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm, struct sembuf *sops,
		     unsigned nsops, int alter),
	     BPF_LSM_ARGS(perm, sops, nsops, alter))
BPF_LSM_HOOK(netlink_send,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct sock *sk, struct sk_buff *skb),
	     BPF_LSM_ARGS(sk, skb))
BPF_LSM_HOOK(d_instantiate,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct dentry *dentry, struct inode *inode),
	     BPF_LSM_ARGS(dentry, inode))
BPF_LSM_HOOK(getprocattr,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p, char *name, char **value),
	     BPF_LSM_ARGS(p, name, value))
BPF_LSM_HOOK(setprocattr,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const char *name, void *value, size_t size),
	     BPF_LSM_ARGS(name, value, size))
BPF_LSM_HOOK(ismaclabel,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const char *name),
	     BPF_LSM_ARGS(name))
BPF_LSM_HOOK(secid_to_secctx,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(u32 secid, char **secdata, u32 *seclen),
	     BPF_LSM_ARGS(secid, secdata, seclen))
BPF_LSM_HOOK(secctx_to_secid,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(const char *secdata, u32 seclen, u32 *secid),
	     BPF_LSM_ARGS(secdata, seclen, secid))
BPF_LSM_HOOK(release_secctx,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(char *secdata, u32 seclen),
	     BPF_LSM_ARGS(secdata, seclen))
BPF_LSM_HOOK(inode_invalidate_secctx,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct inode *inode),
	     BPF_LSM_ARGS(inode))
BPF_LSM_HOOK(inode_notifysecctx,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct inode *inode, void *ctx, u32 ctxlen),
	     BPF_LSM_ARGS(inode, ctx, ctxlen))
BPF_LSM_HOOK(inode_setsecctx,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry, void *ctx, u32 ctxlen),
	     BPF_LSM_ARGS(dentry, ctx, ctxlen))
BPF_LSM_HOOK(inode_getsecctx,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct inode *inode, void **ctx, u32 *ctxlen),
	     BPF_LSM_ARGS(inode, ctx, ctxlen))

#ifdef CONFIG_SECURITY_NETWORK
BPF_LSM_HOOK(unix_stream_connect,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct sock *sock, struct sock *other,
			  struct sock *newsk),
	     BPF_LSM_ARGS(sock, other, newsk))
BPF_LSM_HOOK(unix_may_send,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, struct socket *other),
	     BPF_LSM_ARGS(sock, other))
BPF_LSM_HOOK(socket_create,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(int family, int type, int protocol, int kern),
	     BPF_LSM_ARGS(family, type, protocol, kern))
BPF_LSM_HOOK(socket_post_create,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, int family, int type,
			  int protocol,
		     int kern),
	     BPF_LSM_ARGS(sock, family, type, protocol, kern))
BPF_LSM_HOOK(socket_socketpair,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct socket *socka, struct socket *sockb),
	     BPF_LSM_ARGS(socka, sockb))
BPF_LSM_HOOK(socket_bind,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, struct sockaddr *address,
			  int addrlen),
	     BPF_LSM_ARGS(sock, address, addrlen))
BPF_LSM_HOOK(socket_connect,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, struct sockaddr *address,
			  int addrlen),
	     BPF_LSM_ARGS(sock, address, addrlen))
BPF_LSM_HOOK(socket_listen,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, int backlog),
	     BPF_LSM_ARGS(sock, backlog))
BPF_LSM_HOOK(socket_accept,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, struct socket *newsock),
	     BPF_LSM_ARGS(sock, newsock))
BPF_LSM_HOOK(socket_sendmsg,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, struct msghdr *msg, int size),
	     BPF_LSM_ARGS(sock, msg, size))
BPF_LSM_HOOK(socket_recvmsg,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, struct msghdr *msg, int size,
		     int flags),
	     BPF_LSM_ARGS(sock, msg, size, flags))
BPF_LSM_HOOK(socket_getsockname,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct socket *sock),
	     BPF_LSM_ARGS(sock))
BPF_LSM_HOOK(socket_getpeername,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct socket *sock),
	     BPF_LSM_ARGS(sock))
BPF_LSM_HOOK(socket_getsockopt,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, int level, int optname),
	     BPF_LSM_ARGS(sock, level, optname))
BPF_LSM_HOOK(socket_setsockopt,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, int level, int optname),
	     BPF_LSM_ARGS(sock, level, optname))
BPF_LSM_HOOK(socket_shutdown,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, int how),
	     BPF_LSM_ARGS(sock, how))
BPF_LSM_HOOK(socket_sock_rcv_skb,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct sock *sk, struct sk_buff *skb),
	     BPF_LSM_ARGS(sk, skb))
BPF_LSM_HOOK(socket_getpeersec_stream,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, char __user *optval,
		     int __user *optlen, unsigned len),
	     BPF_LSM_ARGS(sock, optval, optlen, len))
BPF_LSM_HOOK(socket_getpeersec_dgram,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, struct sk_buff *skb, u32 *secid),
	     BPF_LSM_ARGS(sock, skb, secid))
BPF_LSM_HOOK(sk_alloc_security,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct sock *sk, int family, gfp_t priority),
	     BPF_LSM_ARGS(sk, family, priority))
BPF_LSM_HOOK(sk_free_security,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct sock *sk),
	     BPF_LSM_ARGS(sk))
BPF_LSM_HOOK(sk_clone_security,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(const struct sock *sk, struct sock *newsk),
	     BPF_LSM_ARGS(sk, newsk))
BPF_LSM_HOOK(sk_getsecid,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct sock *sk, u32 *secid),
	     BPF_LSM_ARGS(sk, secid))
BPF_LSM_HOOK(sock_graft,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct sock *sk, struct socket *parent),
	     BPF_LSM_ARGS(sk, parent))
BPF_LSM_HOOK(inet_conn_request,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct sock *sk, struct sk_buff *skb,
		     struct request_sock *req),
	     BPF_LSM_ARGS(sk, skb, req))
BPF_LSM_HOOK(inet_csk_clone,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct sock *newsk, const struct request_sock *req),
	     BPF_LSM_ARGS(newsk, req))
BPF_LSM_HOOK(inet_conn_established,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct sock *sk, struct sk_buff *skb),
	     BPF_LSM_ARGS(sk, skb))
BPF_LSM_HOOK(secmark_relabel_packet,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(u32 secid),
	     BPF_LSM_ARGS(secid))
BPF_LSM_HOOK(secmark_refcount_inc,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(void),
	     BPF_LSM_ARGS())
BPF_LSM_HOOK(secmark_refcount_dec,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(void),
	     BPF_LSM_ARGS())
BPF_LSM_HOOK(req_classify_flow,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(const struct request_sock *req, struct flowi *fl),
	     BPF_LSM_ARGS(req, fl))
BPF_LSM_HOOK(tun_dev_alloc_security,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(void **security),
	     BPF_LSM_ARGS(security))
BPF_LSM_HOOK(tun_dev_free_security,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(void *security),
	     BPF_LSM_ARGS(security))
BPF_LSM_HOOK(tun_dev_create,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(void),
	     BPF_LSM_ARGS())
BPF_LSM_HOOK(tun_dev_attach_queue,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(void *security),
	     BPF_LSM_ARGS(security))
BPF_LSM_HOOK(tun_dev_attach,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct sock *sk, void *security),
	     BPF_LSM_ARGS(sk, security))
BPF_LSM_HOOK(tun_dev_open,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(void *security),
	     BPF_LSM_ARGS(security))
BPF_LSM_HOOK(sctp_assoc_request,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct sctp_endpoint *ep, struct sk_buff *skb),
	     BPF_LSM_ARGS(ep, skb))
BPF_LSM_HOOK(sctp_bind_connect,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct sock *sk, int optname,
			  struct sockaddr *address,
		     int addrlen),
	     BPF_LSM_ARGS(sk, optname, address, addrlen))
BPF_LSM_HOOK(sctp_sk_clone,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct sctp_endpoint *ep, struct sock *sk,
			  struct sock *newsk),
	     BPF_LSM_ARGS(ep, sk, newsk))
#endif	/* CONFIG_SECURITY_NETWORK */

#ifdef CONFIG_SECURITY_INFINIBAND
BPF_LSM_HOOK(ib_pkey_access,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(void *sec, u64 subnet_prefix, u16 pkey),
	     BPF_LSM_ARGS(sec, subnet_prefix, pkey))
BPF_LSM_HOOK(ib_endport_manage_subnet,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(void *sec, const char *dev_name, u8 port_num),
	     BPF_LSM_ARGS(sec, dev_name, port_num))
BPF_LSM_HOOK(ib_alloc_security,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(void **sec),
	     BPF_LSM_ARGS(sec))
BPF_LSM_HOOK(ib_free_security,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(void *sec),
	     BPF_LSM_ARGS(sec))
#endif	/* CONFIG_SECURITY_INFINIBAND */

#ifdef CONFIG_SECURITY_NETWORK_XFRM
BPF_LSM_HOOK(xfrm_policy_alloc_security,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct xfrm_sec_ctx **ctxp,
		     struct xfrm_user_sec_ctx *sec_ctx, gfp_t gfp),
	     BPF_LSM_ARGS(ctxp, sec_ctx, gfp))
BPF_LSM_HOOK(xfrm_policy_clone_security,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct xfrm_sec_ctx *old_ctx,
			  struct xfrm_sec_ctx **new_ctx),
	     BPF_LSM_ARGS(old_ctx, new_ctx))
BPF_LSM_HOOK(xfrm_policy_free_security,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct xfrm_sec_ctx *ctx),
	     BPF_LSM_ARGS(ctx))
BPF_LSM_HOOK(xfrm_policy_delete_security,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct xfrm_sec_ctx *ctx),
	     BPF_LSM_ARGS(ctx))
BPF_LSM_HOOK(xfrm_state_alloc,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct xfrm_state *x,
			  struct xfrm_user_sec_ctx *sec_ctx),
	     BPF_LSM_ARGS(x, sec_ctx))
BPF_LSM_HOOK(xfrm_state_alloc_acquire,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct xfrm_state *x, struct xfrm_sec_ctx *polsec,
		     u32 secid),
	     BPF_LSM_ARGS(x, polsec, secid))
BPF_LSM_HOOK(xfrm_state_free_security,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct xfrm_state *x),
	     BPF_LSM_ARGS(x))
BPF_LSM_HOOK(xfrm_state_delete_security,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct xfrm_state *x),
	     BPF_LSM_ARGS(x))
BPF_LSM_HOOK(xfrm_policy_lookup,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct xfrm_sec_ctx *ctx, u32 fl_secid, u8 dir),
	     BPF_LSM_ARGS(ctx, fl_secid, dir))
BPF_LSM_HOOK(xfrm_state_pol_flow_match,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct xfrm_state *x, struct xfrm_policy *xp,
		     const struct flowi *fl),
	     BPF_LSM_ARGS(x, xp, fl))
BPF_LSM_HOOK(xfrm_decode_session,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct sk_buff *skb, u32 *secid, int ckall),
	     BPF_LSM_ARGS(skb, secid, ckall))
#endif	/* CONFIG_SECURITY_NETWORK_XFRM */

#ifdef CONFIG_KEYS
BPF_LSM_HOOK(key_alloc,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct key *key, const struct cred *cred,
		     unsigned long flags),
	     BPF_LSM_ARGS(key, cred, flags))
BPF_LSM_HOOK(key_free,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct key *key),
	     BPF_LSM_ARGS(key))
BPF_LSM_HOOK(key_permission,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(key_ref_t key_ref, const struct cred *cred,
			  unsigned perm),
	     BPF_LSM_ARGS(key_ref, cred, perm))
BPF_LSM_HOOK(key_getsecurity,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct key *key, char **_buffer),
	     BPF_LSM_ARGS(key, _buffer))
#endif	/* CONFIG_KEYS */

#ifdef CONFIG_AUDIT
BPF_LSM_HOOK(audit_rule_init,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(u32 field, u32 op, char *rulestr, void **lsmrule),
	     BPF_LSM_ARGS(field, op, rulestr, lsmrule))
BPF_LSM_HOOK(audit_rule_known,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct audit_krule *krule),
	     BPF_LSM_ARGS(krule))
BPF_LSM_HOOK(audit_rule_match,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(u32 secid, u32 field, u32 op, void *lsmrule),
	     BPF_LSM_ARGS(secid, field, op, lsmrule))
BPF_LSM_HOOK(audit_rule_free,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(void *lsmrule),
	     BPF_LSM_ARGS(lsmrule))
#endif /* CONFIG_AUDIT */

#ifdef CONFIG_BPF_SYSCALL
BPF_LSM_HOOK(bpf,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(int cmd, union bpf_attr *attr, unsigned int size),
	     BPF_LSM_ARGS(cmd, attr, size))
BPF_LSM_HOOK(bpf_map,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct bpf_map *map, fmode_t fmode),
	     BPF_LSM_ARGS(map, fmode))
BPF_LSM_HOOK(bpf_prog,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct bpf_prog *prog),
	     BPF_LSM_ARGS(prog))
BPF_LSM_HOOK(bpf_map_alloc_security,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct bpf_map *map),
	     BPF_LSM_ARGS(map))
BPF_LSM_HOOK(bpf_map_free_security,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct bpf_map *map),
	     BPF_LSM_ARGS(map))
BPF_LSM_HOOK(bpf_prog_alloc_security,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(struct bpf_prog_aux *aux),
	     BPF_LSM_ARGS(aux))
BPF_LSM_HOOK(bpf_prog_free_security,
	     ATOMIC,
	     void,
	     BPF_LSM_ARGS(struct bpf_prog_aux *aux),
	     BPF_LSM_ARGS(aux))
#endif /* CONFIG_BPF_SYSCALL */

BPF_LSM_HOOK(locked_down,
	     ATOMIC,
	     int,
	     BPF_LSM_ARGS(enum lockdown_reason what),
	     BPF_LSM_ARGS(what))
