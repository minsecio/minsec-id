/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The few BPF helpers, map macros, and CO-RE builtins minsec-id uses, so the
 * build needs clang and nothing else (no libbpf headers). Helper numbers are
 * the kernel's stable uapi (enum bpf_func_id).
 */
#ifndef MINSEC_HELPERS_H
#define MINSEC_HELPERS_H

#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name

/* Read a field through a pointer the verifier does not trust (one loaded
 * with a probe read), with the field's offset relocated by CO-RE. */
#define KREAD(dst, ptr_field) bpf_probe_read_kernel(&(dst), sizeof(dst), __builtin_preserve_access_index(&(ptr_field)))
#define FIELD_EXISTS(field) __builtin_preserve_field_info(field, 2)

enum {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_RINGBUF = 27,
};

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
};

static void *(*const bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*const bpf_map_update_elem)(void *map, const void *key, const void *value, u64 flags) = (void *)2;
static long (*const bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static u64 (*const bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*const bpf_get_current_comm)(void *buf, u32 size) = (void *)16;
static long (*const bpf_probe_read_user)(void *dst, u32 size, const void *unsafe_ptr) = (void *)112;
static long (*const bpf_probe_read_kernel)(void *dst, u32 size, const void *unsafe_ptr) = (void *)113;
static long (*const bpf_probe_read_user_str)(void *dst, u32 size, const void *unsafe_ptr) = (void *)114;
static long (*const bpf_probe_read_kernel_str)(void *dst, u32 size, const void *unsafe_ptr) = (void *)115;
static long (*const bpf_seq_write)(struct seq_file *m, const void *data, u32 len) = (void *)127;
static void *(*const bpf_ringbuf_reserve)(void *ringbuf, u64 size, u64 flags) = (void *)131;
static void (*const bpf_ringbuf_submit)(void *data, u64 flags) = (void *)132;
static void (*const bpf_ringbuf_discard)(void *data, u64 flags) = (void *)133;
static long (*const bpf_d_path)(struct path *path, char *buf, u32 sz) = (void *)147;
static struct task_struct *(*const bpf_get_current_task_btf)(void) = (void *)158;

#endif
