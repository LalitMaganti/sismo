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
#define SISMO_MAX_PY_FRAMES 16  // max CPython interpreter frames per sample (CAP-1)
#define SISMO_KSYM_NAME_MAX 96  // max bytes of a resolved kernel symbol name
#define SISMO_PY_NAME_MAX 128   // max bytes of a Python qualname (power of two)
// Max PMU counters tracked per thread, across all multiplexed groups. Userspace
// (linux_bpf_capture.zig) parks up to this many events; the active candidate
// list may be shorter (unused slots read back as errors → 0). Bump when adding
// counter groups (e.g. an L2 memory group).
#define SISMO_MAX_COUNTERS 12
#define SISMO_BUILD_ID_SIZE 20

// Stable UAPI values used by bpf_get_stack(BPF_F_USER_BUILD_ID).
#define SISMO_STACK_BUILD_ID_EMPTY 0
#define SISMO_STACK_BUILD_ID_VALID 1
#define SISMO_STACK_BUILD_ID_IP 2

enum sismo_event_type {
  // A timer-tick stack sample of the running thread, carrying its cumulative
  // per-thread counter readings. Maps 1:1 to a Perfetto PerfSample (stack +
  // thread-scoped timebase/follower counts). Both the per-thread counter
  // timeline and the CPU profile.
  SISMO_EVT_SAMPLE = 0,
  // RETIRED. Kernel symbols were once interned in-kernel and shipped as (id,
  // name) definitions; kernel frames now ship raw addresses and are symbolized
  // host-side from /proc/kallsyms. The tag value is reserved (never emitted) so
  // the numbering below stays stable. The record struct it used
  // (sismo_ksym_rec) lives on for SISMO_EVT_FILE.
  SISMO_EVT_KSYM_RETIRED = 1,
  // An off-CPU sample: one thread's blocking stack (captured at sched-switch-
  // out, where its stack is parked in the scheduler = the block site) paired
  // with how long it stayed off-CPU. Reuses sismo_sample_rec verbatim; the
  // off-CPU duration in nanoseconds rides in `data_addr` (which has no meaning
  // for off-CPU) and is the sample's weight. `counters[]` are 0, except slot 0
  // which carries the block identity — the futex uaddr for a lock wait, the
  // bit-63-tagged TCP peer for a blocking recv, or a bit-62-tagged interned
  // file id for a blocking file read — 0 when the block is unnamed.
  //
  // Shared cross-backend contract (Linux eBPF here, macOS kperf lazy.wait,
  // Windows ETW): VOLUNTARY blocks only — the thread went to sleep (state !=
  // TASK_RUNNING), not involuntary preemption. Emitted once per completed
  // off-CPU interval over MIN_OFFCPU_NS, scoped to the target pid in-kernel,
  // carrying the blocking user stack + duration weight. macOS/Windows produce
  // the identical record from their native wait/cswitch triggers.
  SISMO_EVT_OFFCPU = 2,
  // A file-name definition: the (id, base name) for a file the BPF program saw
  // a blocking read on for the first time. An (id, name) record (reuses the
  // sismo_ksym_rec layout); emitted once ahead of the OFFCPU sample that
  // references the id in slot 0, so userspace can resolve the file name for a
  // disk block without shipping a string per sample.
  SISMO_EVT_FILE = 3,
  // An on-CPU sample whose raw user chain was selected by the in-kernel
  // lightswitch-format unwinder. The durable build-id helper chain remains in
  // the embedded sample; the selected raw PCs ride in sismo_unwind_rec.
  SISMO_EVT_SAMPLE_UNWIND = 4,
  // A CPython qualname definition: the (id, name) for an interpreter frame's
  // code-object qualname the BPF program recovered for the first time (CAP-1).
  // Same (id, name) shape/role as SISMO_EVT_KSYM, emitted once ahead of the
  // sample whose py_ids[] reference it, so userspace names Python frames
  // without the host walking the interpreter's memory.
  SISMO_EVT_PYFRAME = 5,
  // RETIRED. Module image prefixes once rode a dedicated ring here (CAP-2).
  // User stacks now carry build-id/file-offset identities directly. Keep the
  // number reserved so later event tags never change meaning.
  SISMO_EVT_MODULE_RETIRED = 6,
};

struct sismo_hdr {
  unsigned int type;          // enum sismo_event_type
  unsigned int tid;           // thread id (kernel task_struct.pid)
  unsigned int pid;           // process id / tgid (kernel task_struct.tgid)
  unsigned int cpu;           // SAMPLE: CPU the sample fired on
  unsigned int timebase;      // SAMPLE: which sampler/timebase fired (attach cookie index)
  unsigned int nr_frames;     // SAMPLE: number of valid entries in stack[]
  unsigned int nr_kernel_frames;  // SAMPLE: number of valid entries in kernel_stack[]
  unsigned int nr_py_frames;  // SAMPLE: valid entries in py_ids[] (CAP-1; fills
                              // the former padding before `ts`, so layout is
                              // unchanged for readers that ignore it)
  unsigned long long ts;      // CLOCK_MONOTONIC ns
};

// Exact mirror of Linux UAPI `struct bpf_stack_build_id`. For VALID entries,
// offset_or_ip is an ELF file offset; for IP entries it is a raw user PC.
struct sismo_stack_build_id {
  int status;
  unsigned char build_id[SISMO_BUILD_ID_SIZE];
  unsigned long long offset_or_ip;
};
_Static_assert(sizeof(struct sismo_stack_build_id) == 32,
               "bpf_stack_build_id size mismatch");
_Static_assert(__builtin_offsetof(struct sismo_stack_build_id, offset_or_ip) == 24,
               "bpf_stack_build_id offset mismatch");

// SISMO_EVT_SAMPLE. counters[i] is the running thread's cumulative reading of
// the perf event parked in counters_pe slot i (userspace decides which event
// each slot holds; slots with no event read as 0). stack[] holds typed kernel
// build-id entries, leaf-first. kernel_ids[] holds RAW kernel PCs, leaf-first — the host maps
// them to [kernel.kallsyms]-relative addresses (subtracting the kernel text
// base) and symbolizes them via wholesym from a /proc/kallsyms snapshot. The
// KASLR slide stays host-side: the base is subtracted before anything is
// written to the trace, so only image-relative addresses are stored.
struct sismo_sample_rec {
  struct sismo_hdr hdr;
  // SAMPLE: linear (virtual) address of the sampled memory access — the
  // PERF_SAMPLE_ADDR / Data_LA value. 0 unless the sampler leader is a precise
  // load event that carries it (the cache focus). Userspace maps it to the
  // memory region (heap/stack/object) the miss landed in.
  unsigned long long data_addr;
  unsigned long long counters[SISMO_MAX_COUNTERS];
  struct sismo_stack_build_id stack[SISMO_MAX_STACK];
  unsigned long long kernel_ids[SISMO_MAX_KERNEL_STACK];  // raw kernel PCs
  // CAP-1: CPython frame-name ids, leaf-first (see SISMO_EVT_PYFRAME). 0 unless
  // the target is a recognized interpreter and the in-BPF walk recovered
  // frames; count in hdr.nr_py_frames.
  unsigned int py_ids[SISMO_MAX_PY_FRAMES];
};

// SISMO_EVT_SAMPLE_UNWIND. The embedded sample preserves the durable typed
// helper chain. `unwind_stack` is the raw chain already selected by the
// in-kernel lightswitch walker and is normalized to build-id/file-offset by
// userspace where live mappings permit.
struct sismo_unwind_rec {
  struct sismo_sample_rec sample;  // hdr.type = SISMO_EVT_SAMPLE_UNWIND
  unsigned int nr_unwind_frames;
  unsigned int _pad;
  unsigned long long unwind_stack[SISMO_MAX_STACK];
};
_Static_assert(sizeof(struct sismo_hdr) == 40, "sismo_hdr layout mismatch");
_Static_assert(__builtin_offsetof(struct sismo_sample_rec, stack) == 144,
               "sample build-id stack offset mismatch");
_Static_assert(sizeof(struct sismo_sample_rec) == 2768,
               "sample build-id record size mismatch");
_Static_assert(__builtin_offsetof(struct sismo_unwind_rec, unwind_stack) == 2776,
               "unwind raw stack offset mismatch");
_Static_assert(sizeof(struct sismo_unwind_rec) == 3288,
               "unwind build-id record size mismatch");

// A generic (id -> name) definition record. Once used for kernel symbols
// (SISMO_EVT_KSYM, now retired — kernel frames ship raw); today it carries
// SISMO_EVT_FILE (id -> file base name). `name` is NUL-padded.
struct sismo_ksym_rec {
  unsigned int type;  // = SISMO_EVT_FILE (aliases sismo_hdr.type)
  unsigned int id;
  char name[SISMO_KSYM_NAME_MAX];
};

// SISMO_EVT_PYFRAME. A one-time (id -> CPython qualname) mapping: the BPF walk
// read the qualname from the target's interpreter memory and ships the interned
// id, so the sample carries only ids.
struct sismo_pyframe_rec {
  unsigned int type;  // = SISMO_EVT_PYFRAME (aliases sismo_hdr.type)
  unsigned int id;
  char name[SISMO_PY_NAME_MAX];
};

// CAP-1 config: the `_PyRuntime` runtime address + the `_Py_DebugOffsets` field
// offsets the in-BPF interpreter walk needs, pushed once by the host when the
// target is a recognized CPython 3.14. `runtime == 0` disables the walk. Each
// offset is a byte offset into the corresponding live CPython struct (mirrors
// the host PyDebugOffsets the /proc/<pid>/mem walk used).
struct sismo_py_cfg {
  unsigned long long runtime;             // _PyRuntime avma (0 = disabled)
  unsigned long long interpreters_head;   // _PyRuntime.interpreters.head
  unsigned long long threads_head;        // PyInterpreterState.threads.head
  unsigned long long current_frame;       // PyThreadState.current_frame
  unsigned long long frame_previous;      // _PyInterpreterFrame.previous
  unsigned long long frame_executable;    // _PyInterpreterFrame.f_executable (code obj)
  unsigned long long code_qualname;       // PyCodeObject.co_qualname
  unsigned long long unicode_length;      // PyASCIIObject.length
  unsigned long long unicode_data;        // ASCII header size (char data start)
};

#endif  // SISMO_SRC_C_SISMO_BPF_SISMO_BPF_H_
