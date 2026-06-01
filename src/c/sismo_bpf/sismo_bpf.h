// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

// Wire format shared between the BPF programs (sched.bpf.c) and the Zig
// userspace loader. Deliberately uses only universal C scalar types
// (`unsigned int` = u32, `unsigned long long` = u64) so it compiles unchanged
// both under the BPF target (no stdint) and via Zig's @cImport.
//
// Records flow one-way through a ringbuf. Every record's first `unsigned int`
// is an `enum sismo_event_type` tag (it aliases `sismo_hdr.type`, the first
// field of the sample record), so userspace dispatches on the leading u32.

#ifndef SISMO_SRC_C_SISMO_BPF_SISMO_BPF_H_
#define SISMO_SRC_C_SISMO_BPF_SISMO_BPF_H_

#define SISMO_MAX_CPUS 256
#define SISMO_MAX_STACK 64      // max user frames per sample
#define SISMO_MAX_KERNEL_STACK 64  // max kernel frames per sample
#define SISMO_KSYM_NAME_MAX 96  // max bytes of a resolved kernel symbol name
// Max PMU counters tracked per thread, across all multiplexed groups. Userspace
// (linux_bpf_capture.zig) parks up to this many events; the active candidate
// list may be shorter (unused slots read back as errors → 0). Bump when adding
// counter groups (e.g. an L2 memory group).
#define SISMO_MAX_COUNTERS 12

enum sismo_event_type {
  // A timer-tick stack sample of the running thread, carrying its cumulative
  // per-thread counter readings. Maps 1:1 to a Perfetto PerfSample (stack +
  // thread-scoped timebase/follower counts). Both the per-thread counter
  // timeline and the CPU profile.
  SISMO_EVT_SAMPLE = 0,
  // A kernel-symbol definition: the (id, name) for a kernel address the BPF
  // program resolved for the first time. Emitted once per unique address ahead
  // of the sample that references the id, so userspace can name kernel frames
  // without ever seeing the address. See sismo_ksym_rec.
  SISMO_EVT_KSYM = 1,
};

struct sismo_hdr {
  unsigned int type;          // enum sismo_event_type
  unsigned int tid;           // thread id (kernel task_struct.pid)
  unsigned int pid;           // process id / tgid (kernel task_struct.tgid)
  unsigned int cpu;           // SAMPLE: CPU the sample fired on
  unsigned int nr_frames;     // SAMPLE: number of valid entries in stack[]
  unsigned int nr_kernel_frames;  // SAMPLE: number of valid entries in kernel_stack[]
  unsigned long long ts;      // CLOCK_MONOTONIC ns
};

// SISMO_EVT_SAMPLE. counters[i] is the running thread's cumulative reading of
// the perf event parked in counters_pe slot i (userspace decides which event
// each slot holds; slots with no event read as 0). stack[] holds user PCs,
// leaf-first. kernel_ids[] holds kernel-symbol ids (see SISMO_EVT_KSYM),
// leaf-first — the BPF program resolves each kernel address to a symbol name
// in-kernel and ships only the opaque id, so no kernel address (and hence no
// KASLR slide) ever reaches userspace.
struct sismo_sample_rec {
  struct sismo_hdr hdr;
  unsigned long long counters[SISMO_MAX_COUNTERS];
  unsigned long long stack[SISMO_MAX_STACK];
  unsigned int kernel_ids[SISMO_MAX_KERNEL_STACK];
};

// SISMO_EVT_KSYM. A one-time definition mapping a kernel-symbol id to its
// resolved name (a `%pB` kallsyms lookup the kernel did for us). `name` is NUL
// -padded and may carry a trailing `+0xoffset/0xsize` that userspace strips;
// the offset is relative to the symbol and so reveals nothing about KASLR.
struct sismo_ksym_rec {
  unsigned int type;  // = SISMO_EVT_KSYM (aliases sismo_hdr.type)
  unsigned int id;
  char name[SISMO_KSYM_NAME_MAX];
};

#endif  // SISMO_SRC_C_SISMO_BPF_SISMO_BPF_H_
