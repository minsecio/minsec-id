/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Ring buffer records; mirrored by `raw::Event` in src/lib.rs. */
#ifndef MINSEC_EVENT_H
#define MINSEC_EVENT_H

enum kind {
	EV_EXEC = 1,   /* a program started (sched_process_exec) */
	EV_WRITE = 2,  /* a watched file opened for writing */
	EV_MODULE = 3, /* a kernel module loaded */
	EV_KEXEC = 4,  /* kexec_load / kexec_file_load called */
	EV_BPF = 5,    /* a tracing-kind BPF program load requested */
	EV_CREDS = 6,  /* uid 0 gained outside a setuid exec */
	EV_PTRACE = 7, /* ptrace attach or process_vm_writev */
	EV_DEVMEM = 8, /* /dev/mem, /dev/port, or /proc/kcore opened */
};

enum flag {
	F_DELETED = 1 << 0,     /* exec: the file has no links left */
	F_TMPFS = 1 << 1,       /* exec: the file is on tmpfs or ramfs */
	F_STDIN_INET = 1 << 2,  /* exec: fd 0 is a TCP/UDP socket */
	F_STDOUT_INET = 1 << 3, /* exec: fd 1 is a TCP/UDP socket */
	F_PATH_RAW = 1 << 4,    /* exec: path is the execve argument, not resolved */
	F_HOST_ROOT = 1 << 5,   /* the task's root is the host's (not a container or chroot) */
	F_CREATED = 1 << 6,     /* write: the open created the file */
};

/* Rules the kernel side runs (const volatile `rules`); userspace maps them. */
enum rule {
	R_EXEC = 1 << 0,
	R_WRITE = 1 << 1,
	R_DEVMEM = 1 << 2,
};

#define PATH_LEN 256

struct event {
	u32 kind;
	u32 flags;
	u32 pid; /* tgid */
	u32 tid;
	u32 ppid;
	u32 uid;
	u32 euid;
	u32 dev; /* kernel dev_t of the file's superblock */
	u64 ino;
	u64 mntns;
	u64 arg0; /* per kind: see src/lib.rs */
	u64 arg1;
	char comm[16];
	char pcomm[16];
	char name[64];
	char path[PATH_LEN];
};

/* Read from the task iterator (iter.bpf.c). */
struct task_rec {
	u32 tgid;
	u32 ppid;
	u32 flags;
	char comm[16];
};

#endif
