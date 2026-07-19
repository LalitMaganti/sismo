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
  unsigned int __state;  // scheduler state (5.14+; 0 == TASK_RUNNING). Read at
                         // sched_switch to tell a voluntary block from preemption.
  char comm[16];
} __attribute__((preserve_access_index));

// x86_64 struct pt_regs — the kprobe context. BPF_KPROBE reads syscall args from
// it (PT_REGS_PARM1 = di). Stable ABI layout; this object is built x86-only.
struct pt_regs {
  unsigned long r15, r14, r13, r12, rbp, rbx;
  unsigned long r11, r10, r9, r8, rax, rcx, rdx, rsi, rdi;
  unsigned long orig_rax, rip, cs, eflags, rsp, ss;
};

// Just the socket 5-tuple fields the tcp_recvmsg kprobe reads, by name — CO-RE
// relocates their real offsets (they live in unions/anon structs in the kernel).
// skc_daddr / skc_dport are network byte order.
struct sock_common {
  __be32 skc_daddr;
  __be32 skc_rcv_saddr;
  __u16 skc_num;
  __be16 skc_dport;
  __u16 skc_family;
} __attribute__((preserve_access_index));
struct sock {
  struct sock_common __sk_common;
} __attribute__((preserve_access_index));

// The file/inode fields the vfs_read kprobe reads: i_mode to keep only regular
// files, the inode pointer as a stable identity key, and the dentry base name.
struct qstr {
  const unsigned char *name;
} __attribute__((preserve_access_index));
struct dentry {
  struct qstr d_name;
} __attribute__((preserve_access_index));
struct path {
  struct dentry *dentry;
} __attribute__((preserve_access_index));
struct inode {
  __u16 i_mode;  // umode_t
} __attribute__((preserve_access_index));
struct file {
  struct path f_path;
  struct inode *f_inode;
} __attribute__((preserve_access_index));

// The vma fields the CAP-2 module capture reads via bpf_find_vma's callback:
// vm_start and vm_pgoff (file offset in pages). image_base = vm_start -
// (vm_pgoff << PAGE_SHIFT) — the address file-offset-0 (the ELF header) maps to,
// constant across a file's segments and equal to the host's base_avma.
struct vm_area_struct {
  unsigned long vm_start;
  unsigned long vm_pgoff;
} __attribute__((preserve_access_index));

// perf_event program context. We forward it to bpf_get_stack and read `addr`
// (the PERF_SAMPLE_ADDR data linear address). The kernel rewrites loads from
// this context type (convert_ctx_access for BPF_PROG_TYPE_PERF_EVENT), so only
// the field *offsets* must match the UAPI layout
//   struct bpf_perf_event_data { bpf_user_pt_regs_t regs; __u64 sample_period;
//                                __u64 addr; };
// `regs` is the arch's user pt_regs (x86_64: 21 * 8 = 168 bytes); this BPF
// object is built x86-only (-D__TARGET_ARCH_x86 / -target bpf). An opaque blob
// keeps the UAPI ptrace headers out of the minimal-defs build.
struct bpf_perf_event_data {
  unsigned long long regs[21];  // bpf_user_pt_regs_t (x86_64 struct pt_regs)
  unsigned long long sample_period;
  unsigned long long addr;
};

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
  BPF_MAP_TYPE_LRU_HASH = 9,
  BPF_MAP_TYPE_RINGBUF = 27,
  BPF_MAP_TYPE_TASK_STORAGE = 29,
};
enum { BPF_F_NO_PREALLOC = 1 };
enum { BPF_LOCAL_STORAGE_GET_F_CREATE = 1 };
// bpf_map_update_elem flags.
enum { BPF_ANY = 0, BPF_NOEXIST = 1, BPF_EXIST = 2 };

#endif  // SISMO_SRC_C_SISMO_BPF_KERNEL_DEFS_H_
