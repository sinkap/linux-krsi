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
	     int,
	     BPF_LSM_ARGS(struct task_struct *mgr),
	     BPF_LSM_ARGS(mgr))
BPF_LSM_HOOK(binder_transaction,
	     int,
	     BPF_LSM_ARGS(struct task_struct *from, struct task_struct *to),
	     BPF_LSM_ARGS(from, to))
BPF_LSM_HOOK(binder_transfer_binder,
	     int,
	     BPF_LSM_ARGS(struct task_struct *from, struct task_struct *to),
	     BPF_LSM_ARGS(from, to))
BPF_LSM_HOOK(binder_transfer_file,
	     int,
	     BPF_LSM_ARGS(struct task_struct *from, struct task_struct *to,
			  struct file *file),
	     BPF_LSM_ARGS(from, to, file))
BPF_LSM_HOOK(ptrace_access_check,
	     int,
	     BPF_LSM_ARGS(struct task_struct *child, unsigned int mode),
	     BPF_LSM_ARGS(child, mode))
BPF_LSM_HOOK(ptrace_traceme,
	     int,
	     BPF_LSM_ARGS(struct task_struct *parent),
	     BPF_LSM_ARGS(parent))
BPF_LSM_HOOK(capget,
	     int,
	     BPF_LSM_ARGS(struct task_struct *target, kernel_cap_t *effective,
		     kernel_cap_t *inheritable, kernel_cap_t *permitted),
	     BPF_LSM_ARGS(target, effective, inheritable, permitted))
BPF_LSM_HOOK(capset,
	 int,
	 BPF_LSM_ARGS(struct cred *new, const struct cred *old,
		     const kernel_cap_t *effective,
		     const kernel_cap_t *inheritable,
		     const kernel_cap_t *permitted),
	 BPF_LSM_ARGS(new, old, effective, inheritable, permitted))
BPF_LSM_HOOK(capable,
	     int,
	     BPF_LSM_ARGS(const struct cred *cred, struct user_namespace *ns,
	      int cap, unsigned int opts),
	     BPF_LSM_ARGS(cred, ns, cap, opts))
BPF_LSM_HOOK(quotactl,
	     int,
	     BPF_LSM_ARGS(int cmds, int type, int id, struct super_block *sb),
	     BPF_LSM_ARGS(cmds, type, id, sb))
BPF_LSM_HOOK(quota_on,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry),
	     BPF_LSM_ARGS(dentry))
BPF_LSM_HOOK(syslog,
	     int,
	     BPF_LSM_ARGS(int type),
	     BPF_LSM_ARGS(type))
BPF_LSM_HOOK(settime,
	     int,
	     BPF_LSM_ARGS(const struct timespec64 *ts,
			  const struct timezone *tz),
	     BPF_LSM_ARGS(ts, tz))
BPF_LSM_HOOK(vm_enough_memory,
	     int,
	     BPF_LSM_ARGS(struct mm_struct *mm, long pages),
	     BPF_LSM_ARGS(mm, pages))
BPF_LSM_HOOK(bprm_set_creds,
	     int,
	     BPF_LSM_ARGS(struct linux_binprm *bprm),
	     BPF_LSM_ARGS(bprm))
BPF_LSM_HOOK(bprm_check_security,
	     int,
	     BPF_LSM_ARGS(struct linux_binprm *bprm),
	     BPF_LSM_ARGS(bprm))
BPF_LSM_HOOK(bprm_committing_creds,
	     void,
	     BPF_LSM_ARGS(struct linux_binprm *bprm),
	     BPF_LSM_ARGS(bprm))
BPF_LSM_HOOK(bprm_committed_creds,
	     void,
	     BPF_LSM_ARGS(struct linux_binprm *bprm),
	     BPF_LSM_ARGS(bprm))
BPF_LSM_HOOK(fs_context_dup,
	     int,
	     BPF_LSM_ARGS(struct fs_context *fc, struct fs_context *src_sc),
	     BPF_LSM_ARGS(fc, src_sc))
BPF_LSM_HOOK(fs_context_parse_param,
	     int,
	     BPF_LSM_ARGS(struct fs_context *fc, struct fs_parameter *param),
	     BPF_LSM_ARGS(fc, param))
BPF_LSM_HOOK(sb_alloc_security,
	     int,
	     BPF_LSM_ARGS(struct super_block *sb),
	     BPF_LSM_ARGS(sb))
BPF_LSM_HOOK(sb_free_security,
	     void,
	     BPF_LSM_ARGS(struct super_block *sb),
	     BPF_LSM_ARGS(sb))
BPF_LSM_HOOK(sb_free_mnt_opts,
	     void,
	     BPF_LSM_ARGS(void *mnt_opts),
	     BPF_LSM_ARGS(mnt_opts))
BPF_LSM_HOOK(sb_eat_lsm_opts,
	     int,
	     BPF_LSM_ARGS(char *orig, void **mnt_opts),
	     BPF_LSM_ARGS(orig, mnt_opts))
BPF_LSM_HOOK(sb_remount,
	     int,
	     BPF_LSM_ARGS(struct super_block *sb, void *mnt_opts),
	     BPF_LSM_ARGS(sb, mnt_opts))
BPF_LSM_HOOK(sb_kern_mount,
	     int,
	     BPF_LSM_ARGS(struct super_block *sb),
	     BPF_LSM_ARGS(sb))
BPF_LSM_HOOK(sb_show_options,
	     int,
	     BPF_LSM_ARGS(struct seq_file *m, struct super_block *sb),
	     BPF_LSM_ARGS(m, sb))
BPF_LSM_HOOK(sb_statfs,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry),
	     BPF_LSM_ARGS(dentry))
BPF_LSM_HOOK(sb_mount,
	     int,
	     BPF_LSM_ARGS(const char *dev_name, const struct path *path,
		      const char *type, unsigned long flags, void *data),
	     BPF_LSM_ARGS(dev_name, path, type, flags, data))
BPF_LSM_HOOK(sb_umount,
	     int,
	     BPF_LSM_ARGS(struct vfsmount *mnt, int flags),
	     BPF_LSM_ARGS(mnt, flags))
BPF_LSM_HOOK(sb_pivotroot,
	     int,
	     BPF_LSM_ARGS(const struct path *old_path,
			  const struct path *new_path),
	     BPF_LSM_ARGS(old_path, new_path))
BPF_LSM_HOOK(sb_set_mnt_opts,
	     int,
	     BPF_LSM_ARGS(struct super_block *sb, void *mnt_opts,
		     unsigned long kern_flags, unsigned long *set_kern_flags),
	     BPF_LSM_ARGS(sb, mnt_opts, kern_flags, set_kern_flags))
BPF_LSM_HOOK(sb_clone_mnt_opts,
	     int,
	     BPF_LSM_ARGS(const struct super_block *oldsb,
			  struct super_block *newsb, unsigned long kern_flags,
			  unsigned long *set_kern_flags),
	     BPF_LSM_ARGS(oldsb, newsb, kern_flags, set_kern_flags))
BPF_LSM_HOOK(sb_add_mnt_opt,
	     int,
	     BPF_LSM_ARGS(const char *option, const char *val, int len,
		     void **mnt_opts),
	     BPF_LSM_ARGS(option, val, len, mnt_opts))
BPF_LSM_HOOK(move_mount,
	     int,
	     BPF_LSM_ARGS(const struct path *from_path,
			  const struct path *to_path),
	     BPF_LSM_ARGS(from_path, to_path))
BPF_LSM_HOOK(dentry_init_security,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry, int mode,
			  const struct qstr *name,
		     void **ctx, u32 *ctxlen),
	     BPF_LSM_ARGS(dentry, mode, name, ctx, ctxlen))
BPF_LSM_HOOK(dentry_create_files_as,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry, int mode, struct qstr *name,
		     const struct cred *old, struct cred *new),
	     BPF_LSM_ARGS(dentry, mode, name, old, new))

#ifdef CONFIG_SECURITY_PATH
BPF_LSM_HOOK(path_unlink,
	     int,
	     BPF_LSM_ARGS(const struct path *dir, struct dentry *dentry),
	     BPF_LSM_ARGS(dir, dentry))
BPF_LSM_HOOK(path_mkdir,
	     int,
	     BPF_LSM_ARGS(const struct path *dir, struct dentry *dentry,
		     umode_t mode),
	     BPF_LSM_ARGS(dir, dentry, mode))
BPF_LSM_HOOK(path_rmdir,
	     int,
	     BPF_LSM_ARGS(const struct path *dir, struct dentry *dentry),
	     BPF_LSM_ARGS(dir, dentry))
BPF_LSM_HOOK(path_mknod,
	     int,
	     BPF_LSM_ARGS(const struct path *dir, struct dentry *dentry,
			  umode_t mode,
		     unsigned int dev),
	     BPF_LSM_ARGS(dir, dentry, mode, dev))
BPF_LSM_HOOK(path_truncate,
	     int,
	     BPF_LSM_ARGS(const struct path *path),
	     BPF_LSM_ARGS(path))
BPF_LSM_HOOK(path_symlink,
	     int,
	     BPF_LSM_ARGS(const struct path *dir, struct dentry *dentry,
		     const char *old_name),
	     BPF_LSM_ARGS(dir, dentry, old_name))
BPF_LSM_HOOK(path_link,
	     int,
	     BPF_LSM_ARGS(struct dentry *old_dentry, const struct path *new_dir,
		     struct dentry *new_dentry),
	     BPF_LSM_ARGS(old_dentry, new_dir, new_dentry))
BPF_LSM_HOOK(path_rename,
	     int,
	     BPF_LSM_ARGS(const struct path *old_dir, struct dentry *old_dentry,
		     const struct path *new_dir, struct dentry *new_dentry),
	     BPF_LSM_ARGS(old_dir, old_dentry, new_dir, new_dentry))
BPF_LSM_HOOK(path_chmod,
	     int,
	     BPF_LSM_ARGS(const struct path *path, umode_t mode),
	     BPF_LSM_ARGS(path, mode))
BPF_LSM_HOOK(path_chown,
	     int,
	     BPF_LSM_ARGS(const struct path *path, kuid_t uid, kgid_t gid),
	     BPF_LSM_ARGS(path, uid, gid))
BPF_LSM_HOOK(path_chroot,
	     int,
	     BPF_LSM_ARGS(const struct path *path),
	     BPF_LSM_ARGS(path))
#endif /* CONFIG_SECURITY_PATH */

BPF_LSM_HOOK(path_notify,
	     int,
	     BPF_LSM_ARGS(const struct path *path, u64 mask,
			  unsigned int obj_type),
	     BPF_LSM_ARGS(path, mask, obj_type))
BPF_LSM_HOOK(inode_alloc_security,
	     int,
	     BPF_LSM_ARGS(struct inode *inode),
	     BPF_LSM_ARGS(inode))
BPF_LSM_HOOK(inode_free_security,
	     void,
	     BPF_LSM_ARGS(struct inode *inode),
	     BPF_LSM_ARGS(inode))
BPF_LSM_HOOK(inode_init_security,
	     int,
	     BPF_LSM_ARGS(struct inode *inode, struct inode *dir,
		     const struct qstr *qstr, const char **name, void **value,
		     size_t *len),
	     BPF_LSM_ARGS(inode, dir, qstr, name, value, len))
BPF_LSM_HOOK(inode_create,
	     int,
	     BPF_LSM_ARGS(struct inode *dir, struct dentry *dentry,
			  umode_t mode),
	     BPF_LSM_ARGS(dir, dentry, mode))
BPF_LSM_HOOK(inode_link,
	     int,
	     BPF_LSM_ARGS(struct dentry *old_dentry, struct inode *dir,
		     struct dentry *new_dentry),
	     BPF_LSM_ARGS(old_dentry, dir, new_dentry))
BPF_LSM_HOOK(inode_unlink,
	     int,
	     BPF_LSM_ARGS(struct inode *dir, struct dentry *dentry),
	     BPF_LSM_ARGS(dir, dentry))
BPF_LSM_HOOK(inode_symlink,
	     int,
	     BPF_LSM_ARGS(struct inode *dir, struct dentry *dentry,
		     const char *old_name),
	     BPF_LSM_ARGS(dir, dentry, old_name))
BPF_LSM_HOOK(inode_mkdir,
	     int,
	     BPF_LSM_ARGS(struct inode *dir, struct dentry *dentry,
			  umode_t mode),
	     BPF_LSM_ARGS(dir, dentry, mode))
BPF_LSM_HOOK(inode_rmdir,
	     int,
	     BPF_LSM_ARGS(struct inode *dir, struct dentry *dentry),
	     BPF_LSM_ARGS(dir, dentry))
BPF_LSM_HOOK(inode_mknod,
	     int,
	     BPF_LSM_ARGS(struct inode *dir, struct dentry *dentry,
			  umode_t mode,
		     dev_t dev),
	     BPF_LSM_ARGS(dir, dentry, mode, dev))
BPF_LSM_HOOK(inode_rename,
	     int,
	     BPF_LSM_ARGS(struct inode *old_dir, struct dentry *old_dentry,
		     struct inode *new_dir, struct dentry *new_dentry),
	     BPF_LSM_ARGS(old_dir, old_dentry, new_dir, new_dentry))
BPF_LSM_HOOK(inode_readlink,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry),
	     BPF_LSM_ARGS(dentry))
BPF_LSM_HOOK(inode_follow_link,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry, struct inode *inode, bool rcu),
	     BPF_LSM_ARGS(dentry, inode, rcu))
BPF_LSM_HOOK(inode_permission,
	     int,
	     BPF_LSM_ARGS(struct inode *inode, int mask),
	     BPF_LSM_ARGS(inode, mask))
BPF_LSM_HOOK(inode_setattr,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry, struct iattr *attr),
	     BPF_LSM_ARGS(dentry, attr))
BPF_LSM_HOOK(inode_getattr,
	     int,
	     BPF_LSM_ARGS(const struct path *path),
	     BPF_LSM_ARGS(path))
BPF_LSM_HOOK(inode_setxattr,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry, const char *name,
			  const void *value,
		     size_t size, int flags),
	     BPF_LSM_ARGS(dentry, name, value, size, flags))
BPF_LSM_HOOK(inode_post_setxattr,
	     void,
	     BPF_LSM_ARGS(struct dentry *dentry, const char *name,
			  const void *value,
		     size_t size, int flags),
	     BPF_LSM_ARGS(dentry, name, value, size, flags))
BPF_LSM_HOOK(inode_getxattr,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry, const char *name),
	     BPF_LSM_ARGS(dentry, name))
BPF_LSM_HOOK(inode_listxattr,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry),
	     BPF_LSM_ARGS(dentry))
BPF_LSM_HOOK(inode_removexattr,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry, const char *name),
	     BPF_LSM_ARGS(dentry, name))
BPF_LSM_HOOK(inode_need_killpriv,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry),
	     BPF_LSM_ARGS(dentry))
BPF_LSM_HOOK(inode_killpriv,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry),
	     BPF_LSM_ARGS(dentry))
BPF_LSM_HOOK(inode_getsecurity,
	     int,
	     BPF_LSM_ARGS(struct inode *inode, const char *name, void **buffer,
		     bool alloc),
	     BPF_LSM_ARGS(inode, name, buffer, alloc))
BPF_LSM_HOOK(inode_setsecurity,
	     int,
	     BPF_LSM_ARGS(struct inode *inode, const char *name,
			  const void *value,
		     size_t size, int flags),
	     BPF_LSM_ARGS(inode, name, value, size, flags))
BPF_LSM_HOOK(inode_listsecurity,
	     int,
	     BPF_LSM_ARGS(struct inode *inode, char *buffer,
			  size_t buffer_size),
	     BPF_LSM_ARGS(inode, buffer, buffer_size))
BPF_LSM_HOOK(inode_getsecid,
	     void,
	     BPF_LSM_ARGS(struct inode *inode, u32 *secid),
	     BPF_LSM_ARGS(inode, secid))
BPF_LSM_HOOK(inode_copy_up,
	     int,
	     BPF_LSM_ARGS(struct dentry *src, struct cred **new),
	     BPF_LSM_ARGS(src, new))
BPF_LSM_HOOK(inode_copy_up_xattr,
	     int,
	     BPF_LSM_ARGS(const char *name),
	     BPF_LSM_ARGS(name))
BPF_LSM_HOOK(kernfs_init_security,
	     int,
	     BPF_LSM_ARGS(struct kernfs_node *kn_dir, struct kernfs_node *kn),
	     BPF_LSM_ARGS(kn_dir, kn))
BPF_LSM_HOOK(file_permission,
	     int,
	     BPF_LSM_ARGS(struct file *file, int mask),
	     BPF_LSM_ARGS(file, mask))
BPF_LSM_HOOK(file_alloc_security,
	     int,
	     BPF_LSM_ARGS(struct file *file),
	     BPF_LSM_ARGS(file))
BPF_LSM_HOOK(file_free_security,
	     void,
	     BPF_LSM_ARGS(struct file *file),
	     BPF_LSM_ARGS(file))
BPF_LSM_HOOK(file_ioctl,
	     int,
	     BPF_LSM_ARGS(struct file *file, unsigned int cmd,
			  unsigned long arg),
	     BPF_LSM_ARGS(file, cmd, arg))
BPF_LSM_HOOK(mmap_addr,
	     int,
	     BPF_LSM_ARGS(unsigned long addr),
	     BPF_LSM_ARGS(addr))
BPF_LSM_HOOK(mmap_file,
	     int,
	     BPF_LSM_ARGS(struct file *file, unsigned long reqprot,
		     unsigned long prot, unsigned long flags),
	     BPF_LSM_ARGS(file, reqprot, prot, flags))
BPF_LSM_HOOK(file_mprotect,
	     int,
	     BPF_LSM_ARGS(struct vm_area_struct *vma, unsigned long reqprot,
		     unsigned long prot),
	     BPF_LSM_ARGS(vma, reqprot, prot))
BPF_LSM_HOOK(file_lock,
	     int,
	     BPF_LSM_ARGS(struct file *file, unsigned int cmd),
	     BPF_LSM_ARGS(file, cmd))
BPF_LSM_HOOK(file_fcntl,
	     int,
	     BPF_LSM_ARGS(struct file *file, unsigned int cmd,
			  unsigned long arg),
	     BPF_LSM_ARGS(file, cmd, arg))
BPF_LSM_HOOK(file_set_fowner,
	     void,
	     BPF_LSM_ARGS(struct file *file),
	     BPF_LSM_ARGS(file))
BPF_LSM_HOOK(file_send_sigiotask,
	     int,
	     BPF_LSM_ARGS(struct task_struct *tsk, struct fown_struct *fown,
			  int sig),
	     BPF_LSM_ARGS(tsk, fown, sig))
BPF_LSM_HOOK(file_receive,
	     int,
	     BPF_LSM_ARGS(struct file *file),
	     BPF_LSM_ARGS(file))
BPF_LSM_HOOK(file_open,
	     int,
	     BPF_LSM_ARGS(struct file *file),
	     BPF_LSM_ARGS(file))
BPF_LSM_HOOK(task_alloc,
	     int,
	     BPF_LSM_ARGS(struct task_struct *task, unsigned long clone_flags),
	     BPF_LSM_ARGS(task, clone_flags))
BPF_LSM_HOOK(task_free,
	     void,
	     BPF_LSM_ARGS(struct task_struct *task),
	     BPF_LSM_ARGS(task))
BPF_LSM_HOOK(cred_alloc_blank,
	     int,
	     BPF_LSM_ARGS(struct cred *cred, gfp_t gfp),
	     BPF_LSM_ARGS(cred, gfp))
BPF_LSM_HOOK(cred_free,
	     void,
	     BPF_LSM_ARGS(struct cred *cred),
	     BPF_LSM_ARGS(cred))
BPF_LSM_HOOK(cred_prepare,
	     int,
	     BPF_LSM_ARGS(struct cred *new, const struct cred *old, gfp_t gfp),
	     BPF_LSM_ARGS(new, old, gfp))
BPF_LSM_HOOK(cred_transfer,
	     void,
	     BPF_LSM_ARGS(struct cred *new, const struct cred *old),
	     BPF_LSM_ARGS(new, old))
BPF_LSM_HOOK(cred_getsecid,
	     void,
	     BPF_LSM_ARGS(const struct cred *c, u32 *secid),
	     BPF_LSM_ARGS(c, secid))
BPF_LSM_HOOK(kernel_act_as,
	     int,
	     BPF_LSM_ARGS(struct cred *new, u32 secid),
	     BPF_LSM_ARGS(new, secid))
BPF_LSM_HOOK(kernel_create_files_as,
	     int,
	     BPF_LSM_ARGS(struct cred *new, struct inode *inode),
	     BPF_LSM_ARGS(new, inode))
BPF_LSM_HOOK(kernel_module_request,
	     int,
	     BPF_LSM_ARGS(char *kmod_name),
	     BPF_LSM_ARGS(kmod_name))
BPF_LSM_HOOK(kernel_load_data,
	     int,
	     BPF_LSM_ARGS(enum kernel_load_data_id id),
	     BPF_LSM_ARGS(id))
BPF_LSM_HOOK(kernel_read_file,
	     int,
	     BPF_LSM_ARGS(struct file *file, enum kernel_read_file_id id),
	     BPF_LSM_ARGS(file, id))
BPF_LSM_HOOK(kernel_post_read_file,
	     int,
	     BPF_LSM_ARGS(struct file *file, char *buf, loff_t size,
		     enum kernel_read_file_id id),
	     BPF_LSM_ARGS(file, buf, size, id))
BPF_LSM_HOOK(task_fix_setuid,
	     int,
	     BPF_LSM_ARGS(struct cred *new, const struct cred *old, int flags),
	     BPF_LSM_ARGS(new, old, flags))
BPF_LSM_HOOK(task_setpgid,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p, pid_t pgid),
	     BPF_LSM_ARGS(p, pgid))
BPF_LSM_HOOK(task_getpgid,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p),
	     BPF_LSM_ARGS(p))
BPF_LSM_HOOK(task_getsid,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p),
	     BPF_LSM_ARGS(p))
BPF_LSM_HOOK(task_getsecid,
	     void,
	     BPF_LSM_ARGS(struct task_struct *p, u32 *secid),
	     BPF_LSM_ARGS(p, secid))
BPF_LSM_HOOK(task_setnice,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p, int nice),
	     BPF_LSM_ARGS(p, nice))
BPF_LSM_HOOK(task_setioprio,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p, int ioprio),
	     BPF_LSM_ARGS(p, ioprio))
BPF_LSM_HOOK(task_getioprio,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p),
	     BPF_LSM_ARGS(p))
BPF_LSM_HOOK(task_prlimit,
	     int,
	     BPF_LSM_ARGS(const struct cred *cred, const struct cred *tcred,
		     unsigned int flags),
	     BPF_LSM_ARGS(cred, tcred, flags))
BPF_LSM_HOOK(task_setrlimit,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p, unsigned int resource,
		     struct rlimit *new_rlim),
	     BPF_LSM_ARGS(p, resource, new_rlim))
BPF_LSM_HOOK(task_setscheduler,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p),
	     BPF_LSM_ARGS(p))
BPF_LSM_HOOK(task_getscheduler,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p),
	     BPF_LSM_ARGS(p))
BPF_LSM_HOOK(task_movememory,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p),
	     BPF_LSM_ARGS(p))
BPF_LSM_HOOK(task_kill,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p, struct kernel_siginfo *info,
			  int sig,
		     const struct cred *cred),
	     BPF_LSM_ARGS(p, info, sig, cred))
BPF_LSM_HOOK(task_prctl,
	     int,
	     BPF_LSM_ARGS(int option, unsigned long arg2, unsigned long arg3,
		     unsigned long arg4, unsigned long arg5),
	     BPF_LSM_ARGS(option, arg2, arg3, arg4, arg5))
BPF_LSM_HOOK(task_to_inode,
	     void,
	     BPF_LSM_ARGS(struct task_struct *p, struct inode *inode),
	     BPF_LSM_ARGS(p, inode))
BPF_LSM_HOOK(ipc_permission,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *ipcp, short flag),
	     BPF_LSM_ARGS(ipcp, flag))
BPF_LSM_HOOK(ipc_getsecid,
	     void,
	     BPF_LSM_ARGS(struct kern_ipc_perm *ipcp, u32 *secid),
	     BPF_LSM_ARGS(ipcp, secid))
BPF_LSM_HOOK(msg_msg_alloc_security,
	     int,
	     BPF_LSM_ARGS(struct msg_msg *msg),
	     BPF_LSM_ARGS(msg))
BPF_LSM_HOOK(msg_msg_free_security,
	     void,
	     BPF_LSM_ARGS(struct msg_msg *msg),
	     BPF_LSM_ARGS(msg))
BPF_LSM_HOOK(msg_queue_alloc_security,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm),
	     BPF_LSM_ARGS(perm))
BPF_LSM_HOOK(msg_queue_free_security,
	     void,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm),
	     BPF_LSM_ARGS(perm))
BPF_LSM_HOOK(msg_queue_associate,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm, int msqflg),
	     BPF_LSM_ARGS(perm, msqflg))
BPF_LSM_HOOK(msg_queue_msgctl,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm, int cmd),
	     BPF_LSM_ARGS(perm, cmd))
BPF_LSM_HOOK(msg_queue_msgsnd,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm, struct msg_msg *msg,
			  int msqflg),
	     BPF_LSM_ARGS(perm, msg, msqflg))
BPF_LSM_HOOK(msg_queue_msgrcv,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm, struct msg_msg *msg,
		     struct task_struct *target, long type, int mode),
	     BPF_LSM_ARGS(perm, msg, target, type, mode))
BPF_LSM_HOOK(shm_alloc_security,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm),
	     BPF_LSM_ARGS(perm))
BPF_LSM_HOOK(shm_free_security,
	     void,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm),
	     BPF_LSM_ARGS(perm))
BPF_LSM_HOOK(shm_associate,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm, int shmflg),
	     BPF_LSM_ARGS(perm, shmflg))
BPF_LSM_HOOK(shm_shmctl,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm, int cmd),
	     BPF_LSM_ARGS(perm, cmd))
BPF_LSM_HOOK(shm_shmat,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm, char __user *shmaddr,
		     int shmflg),
	     BPF_LSM_ARGS(perm, shmaddr, shmflg))
BPF_LSM_HOOK(sem_alloc_security,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm),
	     BPF_LSM_ARGS(perm))
BPF_LSM_HOOK(sem_free_security,
	     void,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm),
	     BPF_LSM_ARGS(perm))
BPF_LSM_HOOK(sem_associate,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm, int semflg),
	     BPF_LSM_ARGS(perm, semflg))
BPF_LSM_HOOK(sem_semctl,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm, int cmd),
	     BPF_LSM_ARGS(perm, cmd))
BPF_LSM_HOOK(sem_semop,
	     int,
	     BPF_LSM_ARGS(struct kern_ipc_perm *perm, struct sembuf *sops,
		     unsigned nsops, int alter),
	     BPF_LSM_ARGS(perm, sops, nsops, alter))
BPF_LSM_HOOK(netlink_send,
	     int,
	     BPF_LSM_ARGS(struct sock *sk, struct sk_buff *skb),
	     BPF_LSM_ARGS(sk, skb))
BPF_LSM_HOOK(d_instantiate,
	     void,
	     BPF_LSM_ARGS(struct dentry *dentry, struct inode *inode),
	     BPF_LSM_ARGS(dentry, inode))
BPF_LSM_HOOK(getprocattr,
	     int,
	     BPF_LSM_ARGS(struct task_struct *p, char *name, char **value),
	     BPF_LSM_ARGS(p, name, value))
BPF_LSM_HOOK(setprocattr,
	     int,
	     BPF_LSM_ARGS(const char *name, void *value, size_t size),
	     BPF_LSM_ARGS(name, value, size))
BPF_LSM_HOOK(ismaclabel,
	     int,
	     BPF_LSM_ARGS(const char *name),
	     BPF_LSM_ARGS(name))
BPF_LSM_HOOK(secid_to_secctx,
	     int,
	     BPF_LSM_ARGS(u32 secid, char **secdata, u32 *seclen),
	     BPF_LSM_ARGS(secid, secdata, seclen))
BPF_LSM_HOOK(secctx_to_secid,
	     int,
	     BPF_LSM_ARGS(const char *secdata, u32 seclen, u32 *secid),
	     BPF_LSM_ARGS(secdata, seclen, secid))
BPF_LSM_HOOK(release_secctx,
	     void,
	     BPF_LSM_ARGS(char *secdata, u32 seclen),
	     BPF_LSM_ARGS(secdata, seclen))
BPF_LSM_HOOK(inode_invalidate_secctx,
	     void,
	     BPF_LSM_ARGS(struct inode *inode),
	     BPF_LSM_ARGS(inode))
BPF_LSM_HOOK(inode_notifysecctx,
	     int,
	     BPF_LSM_ARGS(struct inode *inode, void *ctx, u32 ctxlen),
	     BPF_LSM_ARGS(inode, ctx, ctxlen))
BPF_LSM_HOOK(inode_setsecctx,
	     int,
	     BPF_LSM_ARGS(struct dentry *dentry, void *ctx, u32 ctxlen),
	     BPF_LSM_ARGS(dentry, ctx, ctxlen))
BPF_LSM_HOOK(inode_getsecctx,
	     int,
	     BPF_LSM_ARGS(struct inode *inode, void **ctx, u32 *ctxlen),
	     BPF_LSM_ARGS(inode, ctx, ctxlen))

#ifdef CONFIG_SECURITY_NETWORK
BPF_LSM_HOOK(unix_stream_connect,
	     int,
	     BPF_LSM_ARGS(struct sock *sock, struct sock *other,
			  struct sock *newsk),
	     BPF_LSM_ARGS(sock, other, newsk))
BPF_LSM_HOOK(unix_may_send,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, struct socket *other),
	     BPF_LSM_ARGS(sock, other))
BPF_LSM_HOOK(socket_create,
	     int,
	     BPF_LSM_ARGS(int family, int type, int protocol, int kern),
	     BPF_LSM_ARGS(family, type, protocol, kern))
BPF_LSM_HOOK(socket_post_create,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, int family, int type,
			  int protocol,
		     int kern),
	     BPF_LSM_ARGS(sock, family, type, protocol, kern))
BPF_LSM_HOOK(socket_socketpair,
	     int,
	     BPF_LSM_ARGS(struct socket *socka, struct socket *sockb),
	     BPF_LSM_ARGS(socka, sockb))
BPF_LSM_HOOK(socket_bind,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, struct sockaddr *address,
			  int addrlen),
	     BPF_LSM_ARGS(sock, address, addrlen))
BPF_LSM_HOOK(socket_connect,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, struct sockaddr *address,
			  int addrlen),
	     BPF_LSM_ARGS(sock, address, addrlen))
BPF_LSM_HOOK(socket_listen,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, int backlog),
	     BPF_LSM_ARGS(sock, backlog))
BPF_LSM_HOOK(socket_accept,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, struct socket *newsock),
	     BPF_LSM_ARGS(sock, newsock))
BPF_LSM_HOOK(socket_sendmsg,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, struct msghdr *msg, int size),
	     BPF_LSM_ARGS(sock, msg, size))
BPF_LSM_HOOK(socket_recvmsg,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, struct msghdr *msg, int size,
		     int flags),
	     BPF_LSM_ARGS(sock, msg, size, flags))
BPF_LSM_HOOK(socket_getsockname,
	     int,
	     BPF_LSM_ARGS(struct socket *sock),
	     BPF_LSM_ARGS(sock))
BPF_LSM_HOOK(socket_getpeername,
	     int,
	     BPF_LSM_ARGS(struct socket *sock),
	     BPF_LSM_ARGS(sock))
BPF_LSM_HOOK(socket_getsockopt,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, int level, int optname),
	     BPF_LSM_ARGS(sock, level, optname))
BPF_LSM_HOOK(socket_setsockopt,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, int level, int optname),
	     BPF_LSM_ARGS(sock, level, optname))
BPF_LSM_HOOK(socket_shutdown,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, int how),
	     BPF_LSM_ARGS(sock, how))
BPF_LSM_HOOK(socket_sock_rcv_skb,
	     int,
	     BPF_LSM_ARGS(struct sock *sk, struct sk_buff *skb),
	     BPF_LSM_ARGS(sk, skb))
BPF_LSM_HOOK(socket_getpeersec_stream,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, char __user *optval,
		     int __user *optlen, unsigned len),
	     BPF_LSM_ARGS(sock, optval, optlen, len))
BPF_LSM_HOOK(socket_getpeersec_dgram,
	     int,
	     BPF_LSM_ARGS(struct socket *sock, struct sk_buff *skb, u32 *secid),
	     BPF_LSM_ARGS(sock, skb, secid))
BPF_LSM_HOOK(sk_alloc_security,
	     int,
	     BPF_LSM_ARGS(struct sock *sk, int family, gfp_t priority),
	     BPF_LSM_ARGS(sk, family, priority))
BPF_LSM_HOOK(sk_free_security,
	     void,
	     BPF_LSM_ARGS(struct sock *sk),
	     BPF_LSM_ARGS(sk))
BPF_LSM_HOOK(sk_clone_security,
	     void,
	     BPF_LSM_ARGS(const struct sock *sk, struct sock *newsk),
	     BPF_LSM_ARGS(sk, newsk))
BPF_LSM_HOOK(sk_getsecid,
	     void,
	     BPF_LSM_ARGS(struct sock *sk, u32 *secid),
	     BPF_LSM_ARGS(sk, secid))
BPF_LSM_HOOK(sock_graft,
	     void,
	     BPF_LSM_ARGS(struct sock *sk, struct socket *parent),
	     BPF_LSM_ARGS(sk, parent))
BPF_LSM_HOOK(inet_conn_request,
	     int,
	     BPF_LSM_ARGS(struct sock *sk, struct sk_buff *skb,
		     struct request_sock *req),
	     BPF_LSM_ARGS(sk, skb, req))
BPF_LSM_HOOK(inet_csk_clone,
	     void,
	     BPF_LSM_ARGS(struct sock *newsk, const struct request_sock *req),
	     BPF_LSM_ARGS(newsk, req))
BPF_LSM_HOOK(inet_conn_established,
	     void,
	     BPF_LSM_ARGS(struct sock *sk, struct sk_buff *skb),
	     BPF_LSM_ARGS(sk, skb))
BPF_LSM_HOOK(secmark_relabel_packet,
	     int,
	     BPF_LSM_ARGS(u32 secid),
	     BPF_LSM_ARGS(secid))
BPF_LSM_HOOK(secmark_refcount_inc,
	     void,
	     BPF_LSM_ARGS(void),
	     BPF_LSM_ARGS())
BPF_LSM_HOOK(secmark_refcount_dec,
	     void,
	     BPF_LSM_ARGS(void),
	     BPF_LSM_ARGS())
BPF_LSM_HOOK(req_classify_flow,
	     void,
	     BPF_LSM_ARGS(const struct request_sock *req, struct flowi *fl),
	     BPF_LSM_ARGS(req, fl))
BPF_LSM_HOOK(tun_dev_alloc_security,
	     int,
	     BPF_LSM_ARGS(void **security),
	     BPF_LSM_ARGS(security))
BPF_LSM_HOOK(tun_dev_free_security,
	     void,
	     BPF_LSM_ARGS(void *security),
	     BPF_LSM_ARGS(security))
BPF_LSM_HOOK(tun_dev_create,
	     int,
	     BPF_LSM_ARGS(void),
	     BPF_LSM_ARGS())
BPF_LSM_HOOK(tun_dev_attach_queue,
	     int,
	     BPF_LSM_ARGS(void *security),
	     BPF_LSM_ARGS(security))
BPF_LSM_HOOK(tun_dev_attach,
	     int,
	     BPF_LSM_ARGS(struct sock *sk, void *security),
	     BPF_LSM_ARGS(sk, security))
BPF_LSM_HOOK(tun_dev_open,
	     int,
	     BPF_LSM_ARGS(void *security),
	     BPF_LSM_ARGS(security))
BPF_LSM_HOOK(sctp_assoc_request,
	     int,
	     BPF_LSM_ARGS(struct sctp_endpoint *ep, struct sk_buff *skb),
	     BPF_LSM_ARGS(ep, skb))
BPF_LSM_HOOK(sctp_bind_connect,
	     int,
	     BPF_LSM_ARGS(struct sock *sk, int optname,
			  struct sockaddr *address,
		     int addrlen),
	     BPF_LSM_ARGS(sk, optname, address, addrlen))
BPF_LSM_HOOK(sctp_sk_clone,
	     void,
	     BPF_LSM_ARGS(struct sctp_endpoint *ep, struct sock *sk,
			  struct sock *newsk),
	     BPF_LSM_ARGS(ep, sk, newsk))
#endif	/* CONFIG_SECURITY_NETWORK */

#ifdef CONFIG_SECURITY_INFINIBAND
BPF_LSM_HOOK(ib_pkey_access,
	     int,
	     BPF_LSM_ARGS(void *sec, u64 subnet_prefix, u16 pkey),
	     BPF_LSM_ARGS(sec, subnet_prefix, pkey))
BPF_LSM_HOOK(ib_endport_manage_subnet,
	     int,
	     BPF_LSM_ARGS(void *sec, const char *dev_name, u8 port_num),
	     BPF_LSM_ARGS(sec, dev_name, port_num))
BPF_LSM_HOOK(ib_alloc_security,
	     int,
	     BPF_LSM_ARGS(void **sec),
	     BPF_LSM_ARGS(sec))
BPF_LSM_HOOK(ib_free_security,
	     void,
	     BPF_LSM_ARGS(void *sec),
	     BPF_LSM_ARGS(sec))
#endif	/* CONFIG_SECURITY_INFINIBAND */

#ifdef CONFIG_SECURITY_NETWORK_XFRM
BPF_LSM_HOOK(xfrm_policy_alloc_security,
	     int,
	     BPF_LSM_ARGS(struct xfrm_sec_ctx **ctxp,
		     struct xfrm_user_sec_ctx *sec_ctx, gfp_t gfp),
	     BPF_LSM_ARGS(ctxp, sec_ctx, gfp))
BPF_LSM_HOOK(xfrm_policy_clone_security,
	     int,
	     BPF_LSM_ARGS(struct xfrm_sec_ctx *old_ctx,
			  struct xfrm_sec_ctx **new_ctx),
	     BPF_LSM_ARGS(old_ctx, new_ctx))
BPF_LSM_HOOK(xfrm_policy_free_security,
	     void,
	     BPF_LSM_ARGS(struct xfrm_sec_ctx *ctx),
	     BPF_LSM_ARGS(ctx))
BPF_LSM_HOOK(xfrm_policy_delete_security,
	     int,
	     BPF_LSM_ARGS(struct xfrm_sec_ctx *ctx),
	     BPF_LSM_ARGS(ctx))
BPF_LSM_HOOK(xfrm_state_alloc,
	     int,
	     BPF_LSM_ARGS(struct xfrm_state *x,
			  struct xfrm_user_sec_ctx *sec_ctx),
	     BPF_LSM_ARGS(x, sec_ctx))
BPF_LSM_HOOK(xfrm_state_alloc_acquire,
	     int,
	     BPF_LSM_ARGS(struct xfrm_state *x, struct xfrm_sec_ctx *polsec,
		     u32 secid),
	     BPF_LSM_ARGS(x, polsec, secid))
BPF_LSM_HOOK(xfrm_state_free_security,
	     void,
	     BPF_LSM_ARGS(struct xfrm_state *x),
	     BPF_LSM_ARGS(x))
BPF_LSM_HOOK(xfrm_state_delete_security,
	     int,
	     BPF_LSM_ARGS(struct xfrm_state *x),
	     BPF_LSM_ARGS(x))
BPF_LSM_HOOK(xfrm_policy_lookup,
	     int,
	     BPF_LSM_ARGS(struct xfrm_sec_ctx *ctx, u32 fl_secid, u8 dir),
	     BPF_LSM_ARGS(ctx, fl_secid, dir))
BPF_LSM_HOOK(xfrm_state_pol_flow_match,
	     int,
	     BPF_LSM_ARGS(struct xfrm_state *x, struct xfrm_policy *xp,
		     const struct flowi *fl),
	     BPF_LSM_ARGS(x, xp, fl))
BPF_LSM_HOOK(xfrm_decode_session,
	     int,
	     BPF_LSM_ARGS(struct sk_buff *skb, u32 *secid, int ckall),
	     BPF_LSM_ARGS(skb, secid, ckall))
#endif	/* CONFIG_SECURITY_NETWORK_XFRM */

#ifdef CONFIG_KEYS
BPF_LSM_HOOK(key_alloc,
	     int,
	     BPF_LSM_ARGS(struct key *key, const struct cred *cred,
		     unsigned long flags),
	     BPF_LSM_ARGS(key, cred, flags))
BPF_LSM_HOOK(key_free,
	     void,
	     BPF_LSM_ARGS(struct key *key),
	     BPF_LSM_ARGS(key))
BPF_LSM_HOOK(key_permission,
	     int,
	     BPF_LSM_ARGS(key_ref_t key_ref, const struct cred *cred,
			  unsigned perm),
	     BPF_LSM_ARGS(key_ref, cred, perm))
BPF_LSM_HOOK(key_getsecurity,
	     int,
	     BPF_LSM_ARGS(struct key *key, char **_buffer),
	     BPF_LSM_ARGS(key, _buffer))
#endif	/* CONFIG_KEYS */

#ifdef CONFIG_AUDIT
BPF_LSM_HOOK(audit_rule_init,
	     int,
	     BPF_LSM_ARGS(u32 field, u32 op, char *rulestr, void **lsmrule),
	     BPF_LSM_ARGS(field, op, rulestr, lsmrule))
BPF_LSM_HOOK(audit_rule_known,
	     int,
	     BPF_LSM_ARGS(struct audit_krule *krule),
	     BPF_LSM_ARGS(krule))
BPF_LSM_HOOK(audit_rule_match,
	     int,
	     BPF_LSM_ARGS(u32 secid, u32 field, u32 op, void *lsmrule),
	     BPF_LSM_ARGS(secid, field, op, lsmrule))
BPF_LSM_HOOK(audit_rule_free,
	     void,
	     BPF_LSM_ARGS(void *lsmrule),
	     BPF_LSM_ARGS(lsmrule))
#endif /* CONFIG_AUDIT */

#ifdef CONFIG_BPF_SYSCALL
BPF_LSM_HOOK(bpf,
	     int,
	     BPF_LSM_ARGS(int cmd, union bpf_attr *attr, unsigned int size),
	     BPF_LSM_ARGS(cmd, attr, size))
BPF_LSM_HOOK(bpf_map,
	     int,
	     BPF_LSM_ARGS(struct bpf_map *map, fmode_t fmode),
	     BPF_LSM_ARGS(map, fmode))
BPF_LSM_HOOK(bpf_prog,
	     int,
	     BPF_LSM_ARGS(struct bpf_prog *prog),
	     BPF_LSM_ARGS(prog))
BPF_LSM_HOOK(bpf_map_alloc_security,
	     int,
	     BPF_LSM_ARGS(struct bpf_map *map),
	     BPF_LSM_ARGS(map))
BPF_LSM_HOOK(bpf_map_free_security,
	     void,
	     BPF_LSM_ARGS(struct bpf_map *map),
	     BPF_LSM_ARGS(map))
BPF_LSM_HOOK(bpf_prog_alloc_security,
	     int,
	     BPF_LSM_ARGS(struct bpf_prog_aux *aux),
	     BPF_LSM_ARGS(aux))
BPF_LSM_HOOK(bpf_prog_free_security,
	     void,
	     BPF_LSM_ARGS(struct bpf_prog_aux *aux),
	     BPF_LSM_ARGS(aux))
#endif /* CONFIG_BPF_SYSCALL */

BPF_LSM_HOOK(locked_down,
	     int,
	     BPF_LSM_ARGS(enum lockdown_reason what),
	     BPF_LSM_ARGS(what))
