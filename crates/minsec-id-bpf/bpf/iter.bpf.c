// SPDX-License-Identifier: GPL-2.0-or-later
/* Every process the kernel has, for comparison with what /proc lists: a
 * rootkit hiding pids from getdents does not hide them from this. */
#include "vmlinux.h"
#include "helpers.h"
#include "event.h"

/* "GPL" is the kernel's "GPL v2 or later", as this file is. */
char LICENSE[] SEC("license") = "GPL";

SEC("iter/task")
int msid_tasks(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *t = ctx->task;
	struct task_rec r;

	if (!t || t->pid != t->tgid)
		return 0;
	r.tgid = t->tgid;
	r.ppid = t->real_parent->tgid;
	r.flags = t->flags;
	bpf_probe_read_kernel_str(r.comm, sizeof(r.comm), t->comm);
	bpf_seq_write(seq, &r, sizeof(r));
	return 0;
}
