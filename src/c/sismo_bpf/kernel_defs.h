// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

// Hand-maintained minimal stand-in for the multi-megabyte
// `bpftool btf dump file /sys/kernel/btf/vmlinux format c` output. sched.bpf.c
// only references a handful of kernel types, and BPF CO-RE relocates the
// kernel-internal field offsets at load time — so the compiler only needs the
// NAMES of the fields we read, not the real layout. Keeping this small (rather
// than checking in / regenerating the full dump) keeps the build hermetic with
// no bpftool / BTF dependency.
//
// When sched.bpf.c starts reading a new kernel field or type, add it here.

#ifndef SISMO_SRC_C_SISMO_BPF_KERNEL_DEFS_H_
#define SISMO_SRC_C_SISMO_BPF_KERNEL_DEFS_H_

typedef _Bool bool;
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;
// Byte-order / checksum aliases: bpf_helper_defs.h declares every helper,
// including networking ones that name these. We never use them, but the
// declarations must type-check.
typedef __u16 __be16;
typedef __u16 __le16;
typedef __u16 __sum16;
typedef __u32 __be32;
typedef __u32 __le32;
typedef __u32 __wsum;
typedef __u64 __be64;
typedef __u64 __le64;

// Kernel-internal: only the fields sched.bpf.c reads via CO-RE. The offsets
// here are placeholders; `preserve_access_index` makes every access a CO-RE
// relocation resolved against the running kernel's BTF.
struct task_struct {
  int pid;
  int tgid;
  char comm[16];
} __attribute__((preserve_access_index));

// perf_event program context — opaque; we only forward it to bpf_get_stack.
struct bpf_perf_event_data;

// Stable UAPI layout filled by bpf_perf_event_read_value (not CO-RE relocated).
struct bpf_perf_event_value {
  __u64 counter;
  __u64 enabled;
  __u64 running;
};

// ABI-stable values from include/uapi/linux/bpf.h, used by the map definitions
// and helpers below. (vmlinux.h would supply these via the full kernel enums.)
enum {
  BPF_MAP_TYPE_ARRAY = 2,
  BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
  BPF_MAP_TYPE_PERCPU_ARRAY = 6,
  BPF_MAP_TYPE_RINGBUF = 27,
  BPF_MAP_TYPE_TASK_STORAGE = 29,
};
enum { BPF_F_NO_PREALLOC = 1 };
enum { BPF_LOCAL_STORAGE_GET_F_CREATE = 1 };

#endif  // SISMO_SRC_C_SISMO_BPF_KERNEL_DEFS_H_
