/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The kernel types minsec-id's BPF programs read, declared with only the
 * fields used. Every record carries preserve_access_index, so field offsets
 * are CO-RE relocations resolved against the running kernel's BTF at load
 * time: these declarations fix names and types, never layout. A field
 * renamed or removed in some kernel makes the load fail loudly.
 */
#ifndef MINSEC_VMLINUX_H
#define MINSEC_VMLINUX_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed int s32;
typedef signed long long s64;
typedef _Bool bool;
#define true 1
#define false 0

typedef u32 dev_t;
typedef u32 fmode_t;
typedef u16 umode_t;
typedef int pid_t;
typedef struct {
	u32 val;
} kuid_t;

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

struct qstr {
	const unsigned char *name;
};

struct super_block {
	dev_t s_dev;
	unsigned long s_magic;
};

struct inode {
	umode_t i_mode;
	struct super_block *i_sb;
	unsigned long i_ino;
	unsigned int i_nlink;
	dev_t i_rdev;
};

struct dentry {
	struct dentry *d_parent;
	struct qstr d_name;
};

struct vfsmount;

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

struct file {
	struct path f_path;
	struct inode *f_inode;
	fmode_t f_mode;
	unsigned int f_flags;
	void *private_data;
};

struct fdtable {
	unsigned int max_fds;
	struct file **fd;
};

struct files_struct {
	struct fdtable *fdt;
};

struct fs_struct {
	struct path root;
};

struct ns_common {
	unsigned int inum;
};

struct mnt_namespace {
	struct ns_common ns;
};

struct nsproxy {
	struct mnt_namespace *mnt_ns;
};

struct cred {
	kuid_t uid;
	kuid_t suid;
	kuid_t euid;
};

struct task_struct {
	unsigned int flags;
	pid_t pid;
	pid_t tgid;
	struct task_struct *real_parent;
	const struct cred *real_cred;
	const struct cred *cred;
	char comm[16];
	struct fs_struct *fs;
	struct files_struct *files;
	struct nsproxy *nsproxy;
};

struct linux_binprm {
	struct file *file;
	const char *filename;
};

struct module {
	char name[56];
	unsigned long taints;
	bool sig_ok;
};

struct sock_common {
	unsigned short skc_family;
};

struct sock {
	struct sock_common __sk_common;
};

struct socket {
	struct sock *sk;
};

struct seq_file;

struct bpf_iter_meta {
	struct seq_file *seq;
};

struct bpf_iter__task {
	struct bpf_iter_meta *meta;
	struct task_struct *task;
};

#pragma clang attribute pop

#endif
