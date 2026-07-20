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
  // a blocking read on for the first time. Same (id, name) shape as
  // SISMO_EVT_KSYM (reuses sismo_ksym_rec); emitted once ahead of the OFFCPU
  // sample that references the id in slot 0, so userspace can resolve the file
  // name for a disk block without shipping a string per sample.
  SISMO_EVT_FILE = 3,
  // A normal sample that additionally carries the user pt_regs + a raw
  // user-stack snapshot for host-side DWARF unwinding (NAT-1). The embedded
  // `sample` is byte-identical to a SISMO_EVT_SAMPLE record.
  SISMO_EVT_SAMPLE_UNWIND = 4,
  // A CPython qualname definition: the (id, name) for an interpreter frame's
  // code-object qualname the BPF program recovered for the first time (CAP-1).
  // Same (id, name) shape/role as SISMO_EVT_KSYM, emitted once ahead of the
  // sample whose py_ids[] reference it, so userspace names Python frames
  // without the host walking the interpreter's memory.
  SISMO_EVT_PYFRAME = 5,
  // A module identity page: a loaded module's image base + the first page of its
  // mapped image (ELF header + build-id note), copied from the target's memory
  // in-band at sample time (CAP-2). Emitted once per module base; the host
  // parses the build-id from it, so a binary deleted before symbolization keeps
  // a real id instead of a synthetic one. See sismo_module_rec.
  SISMO_EVT_MODULE = 6,
};

// Bytes of a module's mapped-image prefix carried by SISMO_EVT_MODULE — one page,
// which holds the ELF header, program headers, and (essentially always) the
// .note.gnu.build-id.
#define SISMO_MODULE_PREFIX 4096

// Max bytes of the raw user-stack snapshot carried by SISMO_EVT_SAMPLE_UNWIND;
// perf's default PERF_SAMPLE_STACK_USER size.
#define SISMO_STACK_SNAP_MAX 8192

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

// SISMO_EVT_SAMPLE. counters[i] is the running thread's cumulative reading of
// the perf event parked in counters_pe slot i (userspace decides which event
// each slot holds; slots with no event read as 0). stack[] holds user PCs,
// leaf-first. kernel_ids[] holds kernel-symbol ids (see SISMO_EVT_KSYM),
// leaf-first — the BPF program resolves each kernel address to a symbol name
// in-kernel and ships only the opaque id, so no kernel address (and hence no
// KASLR slide) ever reaches userspace.
struct sismo_sample_rec {
  struct sismo_hdr hdr;
  // SAMPLE: linear (virtual) address of the sampled memory access — the
  // PERF_SAMPLE_ADDR / Data_LA value. 0 unless the sampler leader is a precise
  // load event that carries it (the cache focus). Userspace maps it to the
  // memory region (heap/stack/object) the miss landed in.
  unsigned long long data_addr;
  unsigned long long counters[SISMO_MAX_COUNTERS];
  unsigned long long stack[SISMO_MAX_STACK];
  unsigned int kernel_ids[SISMO_MAX_KERNEL_STACK];
  // CAP-1: CPython frame-name ids, leaf-first (see SISMO_EVT_PYFRAME). 0 unless
  // the target is a recognized interpreter and the in-BPF walk recovered
  // frames; count in hdr.nr_py_frames.
  unsigned int py_ids[SISMO_MAX_PY_FRAMES];
};

// SISMO_EVT_SAMPLE_UNWIND. Composes sismo_sample_rec verbatim (hdr.type =
// SISMO_EVT_SAMPLE_UNWIND) so the leading bytes are layout-identical to a
// plain sample, plus the user pt_regs at sample time and a bounded raw copy
// of the user stack starting at the captured stack pointer. `stack_len` is
// the number of valid bytes in `stack_bytes` (0 if the copy failed);
// `stack_trunc` is set when the copy failed or was partial — a later step
// DWARF-unwinds this snapshot host-side.
struct sismo_unwind_rec {
  struct sismo_sample_rec sample;   // hdr.type = SISMO_EVT_SAMPLE_UNWIND
  unsigned long long regs_ip;
  unsigned long long regs_sp;
  unsigned long long regs_bp;
  unsigned int stack_len;    // valid bytes in stack_bytes (0 if the copy failed)
  unsigned int stack_trunc;  // 1 if the user-stack copy failed/was partial
  unsigned char stack_bytes[SISMO_STACK_SNAP_MAX];
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

// SISMO_EVT_PYFRAME. A one-time (id -> CPython qualname) mapping, the interpreter
// analogue of sismo_ksym_rec: the BPF walk read the qualname from the target's
// interpreter memory and ships the interned id, so the sample carries only ids.
struct sismo_pyframe_rec {
  unsigned int type;  // = SISMO_EVT_PYFRAME (aliases sismo_hdr.type)
  unsigned int id;
  char name[SISMO_PY_NAME_MAX];
};

// SISMO_EVT_MODULE. A module's image base + the first mapped page of its image,
// read from the target's memory in-band at sample time (CAP-2). `prefix_len` is
// the valid byte count (0 if the copy failed). The host parses the build-id from
// `prefix` via the same code that reads it from a file. Carried on the dedicated
// `module_hints` ringbuf and drained by its own thread, so this capture (and the
// fd pin it drives) is not stuck behind the sample backlog. `tgid` lets that
// thread read the owning process's /proc/<tgid>/maps to pin the file.
struct sismo_module_rec {
  unsigned int type;        // = SISMO_EVT_MODULE (aliases sismo_hdr.type)
  unsigned int prefix_len;  // valid bytes in prefix[]
  unsigned int tgid;        // owning process (for /proc/<tgid>/maps)
  unsigned int _pad;        // keep `base` 8-byte aligned
  unsigned long long base;  // module image base avma (== host base_avma)
  unsigned char prefix[SISMO_MODULE_PREFIX];
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
