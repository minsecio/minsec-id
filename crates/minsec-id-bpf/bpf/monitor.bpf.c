// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * minsec-id's real-time monitor. Each program does as little as it can in
 * the kernel: cheap filters, then one ring buffer record for userspace to
 * judge. Program names keep the `msid_` prefix, which the scanner's
 * bpf-prog-unknown check recognizes.
 */
#include "vmlinux.h"
#include "helpers.h"
#include "event.h"

/* "GPL" is the kernel's "GPL v2 or later", as this file is. */
char LICENSE[] SEC("license") = "GPL";

/* Set by the loader. */
const volatile u32 self_tgid = 0;
const volatile u32 rules = 0;

#define FMODE_WRITE 0x2
#define __FMODE_EXEC 0x20
#define FMODE_CREATED 0x100000
#define S_IFMT 00170000
#define S_IFSOCK 0140000
#define S_IFREG 0100000
#define S_IFCHR 0020000
#define S_IFDIR 0040000
#define TMPFS_MAGIC 0x01021994
#define RAMFS_MAGIC 0x858458f6
#define PROC_SUPER_MAGIC 0x9fa0
#define AF_INET 2
#define AF_INET6 10
#define MKDEV(ma, mi) (((ma) << 20) | (mi))
#define BPF_PROG_LOAD 5

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512 * 1024);
} events SEC(".maps");

/* Records lost to a full ring buffer. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} dropped SEC(".maps");

struct conf {
	u64 root_dentry; /* the host's root directory (pid 1's) */
	u32 learn;       /* LEARN_*: what the loader's own opens teach */
	u32 pad;
};
#define LEARN_SB 1
#define LEARN_ROOT 2

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct conf);
} conf SEC(".maps");

/* Superblocks whose writes are watched: those of /, /usr, /etc, /boot, … */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, u64);
	__type(value, u8);
} watch_sb SEC(".maps");

struct pathbuf {
	char path[PATH_LEN];
};

/* The first file an execve opened, by thread: the program (or script)
 * itself, before the interpreter and the dynamic loader are opened. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct pathbuf);
} pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct pathbuf);
} scratch SEC(".maps");

struct ino_key {
	u64 ino;
	u32 dev;
	u32 pad;
};

/* Executables userspace has judged unremarkable; their execs are not sent
 * again. Any write-open of the inode removes it. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct ino_key);
	__type(value, u8);
} exec_ok SEC(".maps");

/* Threads between security_bprm_committing_creds and commit_creds. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, u8);
} in_exec SEC(".maps");

/* Per-syscall tracepoint context: common fields, nr, then six arguments. */
struct syscall_ctx {
	u64 common;
	s32 nr;
	u32 pad;
	u64 args[6];
};

static __always_inline void count_drop(void)
{
	u32 zero = 0;
	u64 *n = bpf_map_lookup_elem(&dropped, &zero);
	if (n)
		*n += 1;
}

static __always_inline struct event *reserve(void)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!e)
		count_drop();
	return e;
}

static __always_inline bool host_root(struct task_struct *t)
{
	u32 zero = 0;
	struct conf *c = bpf_map_lookup_elem(&conf, &zero);
	return c && c->root_dentry && (u64)t->fs->root.dentry == c->root_dentry;
}

/* Everything but the path, which callers fill (or clear) themselves. */
static __always_inline void fill(struct event *e, struct task_struct *t, u32 kind)
{
	u64 id = bpf_get_current_pid_tgid();
	e->kind = kind;
	e->flags = host_root(t) ? F_HOST_ROOT : 0;
	e->pid = id >> 32;
	e->tid = (u32)id;
	e->ppid = t->real_parent->tgid;
	e->uid = t->real_cred->uid.val;
	e->euid = t->real_cred->euid.val;
	e->dev = 0;
	e->ino = 0;
	e->mntns = t->nsproxy->mnt_ns->ns.inum;
	e->arg0 = 0;
	e->arg1 = 0;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_probe_read_kernel_str(e->pcomm, sizeof(e->pcomm), t->real_parent->comm);
	e->name[0] = 0;
}

/* Whether fd `n` of the task is an internet socket. */
static __always_inline bool fd_inet(struct task_struct *t, u32 n)
{
	struct file **fds = t->files->fdt->fd;
	struct file *f = 0;
	struct inode *i = 0;
	struct socket *s = 0;
	struct sock *sk = 0;
	umode_t mode = 0;
	unsigned short fam = 0;

	if (n >= t->files->fdt->max_fds)
		return false;
	bpf_probe_read_kernel(&f, sizeof(f), fds + n);
	if (!f)
		return false;
	KREAD(i, f->f_inode);
	if (!i)
		return false;
	KREAD(mode, i->i_mode);
	if ((mode & S_IFMT) != S_IFSOCK)
		return false;
	KREAD(s, f->private_data);
	if (!s)
		return false;
	KREAD(sk, s->sk);
	if (!sk)
		return false;
	KREAD(fam, sk->__sk_common.skc_family);
	return fam == AF_INET || fam == AF_INET6;
}

SEC("tp_btf/sched_process_exec")
int msid_exec(u64 *ctx)
{
	struct task_struct *t = (struct task_struct *)ctx[0];
	u32 old_tid = (u32)ctx[1];
	struct linux_binprm *b = (struct linux_binprm *)ctx[2];
	struct event *e;
	struct pathbuf *p;
	struct inode *i;
	unsigned long magic;

	if (!(rules & R_EXEC))
		return 0;
	e = reserve();
	if (!e)
		return 0;
	fill(e, t, EV_EXEC);
	i = b->file->f_inode;
	e->ino = i->i_ino;
	e->dev = i->i_sb->s_dev;
	if (i->i_nlink == 0)
		e->flags |= F_DELETED;
	magic = i->i_sb->s_magic;
	if (magic == TMPFS_MAGIC || magic == RAMFS_MAGIC)
		e->flags |= F_TMPFS;
	if (fd_inet(t, 0))
		e->flags |= F_STDIN_INET;
	if (fd_inet(t, 1))
		e->flags |= F_STDOUT_INET;
	p = bpf_map_lookup_elem(&pending, &old_tid);
	if (p) {
		bpf_probe_read_kernel(e->path, sizeof(e->path), p->path);
		bpf_map_delete_elem(&pending, &old_tid);
	} else {
		bpf_probe_read_kernel_str(e->path, sizeof(e->path), b->filename);
		e->flags |= F_PATH_RAW;
	}
	if (!(e->flags & (F_DELETED | F_TMPFS | F_STDIN_INET | F_STDOUT_INET | F_PATH_RAW))) {
		struct ino_key k = {.ino = e->ino, .dev = e->dev, .pad = 0};
		if (bpf_map_lookup_elem(&exec_ok, &k)) {
			bpf_ringbuf_discard(e, 0);
			return 0;
		}
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* A failed execve leaves its first open behind; the next one starts clean. */
static __always_inline int exec_start(void)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&pending, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int msid_execve(struct syscall_ctx *c)
{
	return exec_start();
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int msid_execveat(struct syscall_ctx *c)
{
	return exec_start();
}

static __always_inline bool has_prefix(const char *s, const char *p, int n)
{
	for (int k = 0; k < n; k++)
		if (s[k] != p[k])
			return false;
	return true;
}

#define PREFIX(s, lit) has_prefix(s, lit, sizeof(lit) - 1)

/* Where a write is worth reporting: system code and configuration, and
 * root's and the system's crontabs. Userspace sorts the rest. */
static __always_inline bool watched(const char *p)
{
	return PREFIX(p, "/usr/") || PREFIX(p, "/etc/") || PREFIX(p, "/boot/") || PREFIX(p, "/bin/") ||
	       PREFIX(p, "/sbin/") || PREFIX(p, "/lib") || PREFIX(p, "/var/spool/cron/");
}

static __always_inline void learn(struct file *f)
{
	u32 zero = 0;
	struct conf *c = bpf_map_lookup_elem(&conf, &zero);
	u8 one = 1;

	if (!c)
		return;
	/* Only directories: the loader opens nothing else while learning
	 * (but the C library or a filesystem might). */
	if ((f->f_inode->i_mode & S_IFMT) != S_IFDIR)
		return;
	if (c->learn == LEARN_SB) {
		u64 sb = (u64)f->f_inode->i_sb;
		bpf_map_update_elem(&watch_sb, &sb, &one, BPF_ANY);
	} else if (c->learn == LEARN_ROOT && !c->root_dentry) {
		/* The first open only: overlayfs then opens the directory
		 * beneath, in the same task. */
		c->root_dentry = (u64)f->f_path.dentry;
	}
}

static __always_inline void devmem(struct file *f)
{
	struct task_struct *t = bpf_get_current_task_btf();
	struct event *e;

	if (!(rules & R_DEVMEM))
		return;
	e = reserve();
	if (!e)
		return;
	fill(e, t, EV_DEVMEM);
	e->ino = f->f_inode->i_ino;
	e->arg0 = f->f_inode->i_rdev;
	e->arg1 = f->f_mode;
	if (bpf_d_path(&f->f_path, e->path, sizeof(e->path)) < 0)
		bpf_probe_read_kernel_str(e->path, sizeof(e->path), f->f_path.dentry->d_name.name);
	bpf_ringbuf_submit(e, 0);
}

SEC("fentry/security_file_open")
int msid_open(u64 *ctx)
{
	struct file *f = (struct file *)ctx[0];
	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32, tid = (u32)id;
	fmode_t mode = f->f_mode;
	struct inode *i = f->f_inode;
	struct super_block *sb;
	struct task_struct *t;
	struct event *e;
	umode_t m;
	char name[16];
	bool keys;

	if (tgid == self_tgid) {
		learn(f);
		return 0;
	}
	/* __FMODE_EXEC is in the open flags; f_mode gets FMODE_EXEC later. */
	if (f->f_flags & __FMODE_EXEC) {
		u32 zero = 0;
		struct pathbuf *b;

		if (!(rules & R_EXEC) || bpf_map_lookup_elem(&pending, &tid))
			return 0;
		b = bpf_map_lookup_elem(&scratch, &zero);
		if (!b)
			return 0;
		if (bpf_d_path(&f->f_path, b->path, sizeof(b->path)) < 0)
			return 0;
		bpf_map_update_elem(&pending, &tid, b, BPF_NOEXIST);
		return 0;
	}
	m = i->i_mode;
	if ((m & S_IFMT) == S_IFCHR) {
		u32 rdev = i->i_rdev;
		if (rdev == MKDEV(1, 1) || rdev == MKDEV(1, 2) || rdev == MKDEV(1, 4))
			devmem(f);
		return 0;
	}
	if ((m & S_IFMT) != S_IFREG)
		return 0;
	sb = i->i_sb;
	if (!(mode & FMODE_WRITE)) {
		if (sb->s_magic == PROC_SUPER_MAGIC) {
			bpf_probe_read_kernel_str(name, sizeof(name), f->f_path.dentry->d_name.name);
			if (PREFIX(name, "kcore") && name[5] == 0)
				devmem(f);
		}
		return 0;
	}
	if (rules & R_EXEC) {
		struct ino_key k = {.ino = i->i_ino, .dev = sb->s_dev, .pad = 0};
		bpf_map_delete_elem(&exec_ok, &k);
	}
	if (!(rules & R_WRITE))
		return 0;
	bpf_probe_read_kernel_str(name, sizeof(name), f->f_path.dentry->d_name.name);
	keys = PREFIX(name, "authorized_keys");
	if (!keys) {
		u64 sbp = (u64)sb;
		if (!bpf_map_lookup_elem(&watch_sb, &sbp))
			return 0;
	}
	t = bpf_get_current_task_btf();
	if (!host_root(t))
		return 0;
	e = reserve();
	if (!e)
		return 0;
	if (bpf_d_path(&f->f_path, e->path, sizeof(e->path)) < 0 || !(keys || watched(e->path))) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	fill(e, t, EV_WRITE);
	if (mode & FMODE_CREATED)
		e->flags |= F_CREATED;
	e->dev = sb->s_dev;
	e->ino = i->i_ino;
	e->arg0 = mode;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/module_load")
int msid_mod(u64 *ctx)
{
	struct module *mod = (struct module *)ctx[0];
	struct event *e = reserve();

	if (!e)
		return 0;
	fill(e, bpf_get_current_task_btf(), EV_MODULE);
	e->path[0] = 0;
	bpf_probe_read_kernel_str(e->name, sizeof(e->name), mod->name);
	e->arg0 = 2; /* signature state unknown */
	if (FIELD_EXISTS(mod->sig_ok))
		e->arg0 = mod->sig_ok ? 1 : 0;
	e->arg1 = mod->taints;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline int kexec(u64 which, u64 flags)
{
	struct event *e = reserve();

	if (!e)
		return 0;
	fill(e, bpf_get_current_task_btf(), EV_KEXEC);
	e->path[0] = 0;
	e->arg0 = which;
	e->arg1 = flags;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_kexec_load")
int msid_kexec(struct syscall_ctx *c)
{
	return kexec(0, c->args[3]);
}

SEC("tracepoint/syscalls/sys_enter_kexec_file_load")
int msid_kexecf(struct syscall_ctx *c)
{
	return kexec(1, c->args[4]);
}

SEC("tracepoint/syscalls/sys_enter_bpf")
int msid_bpf(struct syscall_ctx *c)
{
	const char *attr = (const char *)c->args[1];
	struct event *e;
	u32 type = 0, attach = 0;

	if (c->args[0] != BPF_PROG_LOAD || (bpf_get_current_pid_tgid() >> 32) == self_tgid)
		return 0;
	/* union bpf_attr, BPF_PROG_LOAD: prog_type@0 prog_name@48 expected_attach_type@68 */
	bpf_probe_read_user(&type, sizeof(type), attr);
	switch (type) {
	case 2:  /* kprobe */
	case 5:  /* tracepoint */
	case 7:  /* perf_event */
	case 17: /* raw_tracepoint */
	case 24: /* raw_tracepoint_writable */
	case 26: /* tracing (fentry, fexit, iterators) */
	case 28: /* ext */
	case 29: /* lsm */
		break;
	default:
		return 0;
	}
	e = reserve();
	if (!e)
		return 0;
	fill(e, bpf_get_current_task_btf(), EV_BPF);
	e->path[0] = 0;
	bpf_probe_read_user(&attach, sizeof(attach), attr + 68);
	bpf_probe_read_user_str(e->name, 16, attr + 48);
	e->arg0 = type;
	e->arg1 = attach;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/security_bprm_committing_creds")
int msid_bprm(u64 *ctx)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u8 one = 1;

	bpf_map_update_elem(&in_exec, &tid, &one, BPF_ANY);
	return 0;
}

/* uid 0 gained by a task that held it in none of its uids, other than by
 * executing a setuid program: the classic kernel-exploit outcome
 * (commit_creds(prepare_kernel_cred(0))). */
SEC("fentry/commit_creds")
int msid_creds(u64 *ctx)
{
	struct cred *n = (struct cred *)ctx[0];
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct task_struct *t;
	const struct cred *o;
	struct event *e;

	if (bpf_map_lookup_elem(&in_exec, &tid)) {
		bpf_map_delete_elem(&in_exec, &tid);
		return 0;
	}
	t = bpf_get_current_task_btf();
	o = t->real_cred;
	if (o->uid.val == 0 || o->euid.val == 0 || o->suid.val == 0)
		return 0;
	if (n->uid.val != 0 && n->euid.val != 0 && n->suid.val != 0)
		return 0;
	e = reserve();
	if (!e)
		return 0;
	fill(e, t, EV_CREDS);
	e->path[0] = 0;
	e->arg0 = n->euid.val;
	e->arg1 = n->uid.val;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline int ptrace(u64 req, u64 target)
{
	struct event *e = reserve();

	if (!e)
		return 0;
	fill(e, bpf_get_current_task_btf(), EV_PTRACE);
	e->path[0] = 0;
	e->arg0 = req;
	e->arg1 = target;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int msid_ptrace(struct syscall_ctx *c)
{
	u64 req = c->args[0];

	if (req != 16 /* PTRACE_ATTACH */ && req != 0x4206 /* PTRACE_SEIZE */)
		return 0;
	return ptrace(req, c->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int msid_vmw(struct syscall_ctx *c)
{
	return ptrace(0xffffffff, c->args[0]);
}
