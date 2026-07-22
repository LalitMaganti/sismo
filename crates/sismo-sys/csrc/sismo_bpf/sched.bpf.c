// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

// The sismo BPF CPU collector: per-thread PMU counter sampling plus stack
// profiling, push-based.
//
// Userspace parks one free-running counting perf event per (counter slot, CPU)
// in counters_pe at index slot*SISMO_MAX_CPUS + cpu. Slots it leaves empty
// (counters the hardware couldn't provide) simply read back as errors and are
// credited 0. Counters are read only on the per-CPU timer tick (perf_event):
// it diffs each event against the value at the previous tick on the same CPU
// (last_pe) and credits the delta to the thread running now, then captures that
// thread's stack. This is statistical (perf-style) attribution — the tick
// samples the counter and credits whoever is on-CPU — not exact per-slice
// accounting, which cost a PMU read on every context switch system-wide.
//
//   sched_switch  -> off-CPU accounting only (blocking-stack capture on
//                    switch-out, wake close-out on switch-in); no counter read.
//   perf_event    -> the per-CPU timer tick: sample + credit the counters and
//                    capture the running thread's stack (the CPU profile).
//
// last_pe is advanced on every tick regardless of the running thread, so each
// inter-tick interval's delta is counted once. Per-thread totals live in
// TASK_STORAGE (auto-freed on task exit).

#include "kernel_defs.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "sismo_bpf.h"

#ifndef BPF_F_USER_STACK
#define BPF_F_USER_STACK (1ULL << 8)
#endif

// bpf_get_stack's flags low byte (BPF_F_SKIP_FIELD_MASK) is a frame-skip count.
// Skip the leaf-most 3 kernel frames — the BPF trampoline + tracepoint/perf
// entry frames that are pure collector plumbing, never signal.
#define SKIP_KERNEL_FRAMES 3

// Watermark-batched consumer wakeups: submits stay silent
// until the ring's backlog crosses half its size, then force one wakeup.
// Per-submit irq_work wakeups are wasted kernel work on every sched event —
// and each wakeup is itself a sched event the collector observes — while the
// occasional half-full wakeup lets a bursting ring get drained ahead of the
// consumers' 20 ms poll tick instead of overflowing.
#ifndef BPF_RB_NO_WAKEUP
#define BPF_RB_NO_WAKEUP (1ULL << 0)
#endif
#ifndef BPF_RB_FORCE_WAKEUP
#define BPF_RB_FORCE_WAKEUP (1ULL << 1)
#endif
#ifndef BPF_RB_AVAIL_DATA
#define BPF_RB_AVAIL_DATA 0
#endif

// Ignore sub-threshold off-CPU blocks: a thread that yields for a few µs isn't
// a latency problem, and capturing a stack on every brief switch-out would
// dominate the cost. Latency lives in the long waits.
#define MIN_OFFCPU_NS 10000  // 10 µs

// Voluntary blocking only: we count a switch-out as off-CPU when the outgoing
// thread went to sleep (its state != TASK_RUNNING), not when it was involuntarily
// preempted while still runnable. This matches macOS kperf lazy.wait (which only
// fires on wait-wakeups) and the Windows ETW wait-reason filter — one consistent
// "wait analysis" semantic across backends. TASK_RUNNING is 0.
#define TASK_RUNNING 0

struct sismo_counters {
  __u64 v[SISMO_MAX_COUNTERS];
};

// Per-CPU previous reading for each slot: the raw counter plus the cumulative
// time-enabled / time-running the kernel tracks for multiplexed events. We diff
// all three each read so a multiplexed-off interval can be scaled back up to a
// full-period estimate (see read_advance).
struct sismo_last {
  __u64 c[SISMO_MAX_COUNTERS];
  __u64 en[SISMO_MAX_COUNTERS];
  __u64 run[SISMO_MAX_COUNTERS];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(max_entries, SISMO_MAX_COUNTERS * SISMO_MAX_CPUS);
  __type(key, __u32);
  __type(value, __u32);
} counters_pe SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct sismo_last);
} last_pe SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, struct sismo_counters);
} thread_ctrs SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 3);
  __type(key, __u32);
  __type(value, __u32);
} cfg SEC(".maps");  // cfg[0] = target tgid (0 = all), cfg[1] = unwind-capture flag
                     // (NAT-1), cfg[2] = parked counter slots (bounds read_advance)

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 22);  // 4 MiB
} events SEC(".maps");

// CAP-3(b): module-identity records (SISMO_EVT_MODULE) ride their own ringbuf,
// drained by a dedicated host thread. This keeps build-id capture and the fd pin
// it drives off the sample backlog, so a binary deleted or replaced mid-run is
// pinned/identified promptly instead of after the main queue catches up. Sized
// for the page-carrying records; module discovery is deduped in-BPF (module_seen)
// so the volume is one record per distinct module.
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 22);  // 4 MiB
} module_hints SEC(".maps");

// Both rings are 4 MiB; wake the consumer once the backlog crosses half.
static __always_inline long ringbuf_flags(void *rb) {
  return bpf_ringbuf_query(rb, BPF_RB_AVAIL_DATA) >= (1 << 21)
             ? BPF_RB_FORCE_WAKEUP
             : BPF_RB_NO_WAKEUP;
}


// Kernel frames ship as RAW addresses, resolved host-side via wholesym from a
// /proc/kallsyms snapshot. No in-kernel symbol interning: doing it here meant
// a per-address map updated from sched_switch and the NMI tick, whose eviction
// (LRU) or fill (plain hash) fails badly on the hottest path — the
// probe-side-map storm class. Userspace has kallsyms and an unbounded HashMap; the probe
// just copies u64 PCs into the record.

// CAP-1 CPython interpreter unwind. py_cfg holds the _PyRuntime avma + the
// _Py_DebugOffsets the in-BPF walk reads (runtime 0 = disabled, the default for
// non-Python targets). pyframe_ids/pyframe_next intern a qualname object pointer
// to an id, the same intern-once pattern the file/module ids use.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct sismo_py_cfg);
} py_cfg SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);  // not LRU: NMI/probe-context updates evict badly
  __uint(max_entries, 16384);
  __type(key, __u64);  // co_qualname PyUnicode pointer
  __type(value, __u32);
} pyframe_ids SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} pyframe_next SEC(".maps");

// CAP-2: emit a module's identity page (SISMO_EVT_MODULE) once per image base.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);  // not LRU: NMI/probe-context updates evict badly
  __uint(max_entries, 4096);
  __type(key, __u64);  // module image base avma
  __type(value, __u8);
} module_seen SEC(".maps");

// Per-CPU scratch for the kernel stack: bpf_get_stack writes the raw addresses
// here (kept off the 512-byte BPF stack), then they are copied straight into
// the record's kernel_ids[] — no resolution, no id table.
struct sismo_kstack {
  __u64 addr[SISMO_MAX_KERNEL_STACK];
};
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct sismo_kstack);
} kstack_scratch SEC(".maps");

// One thread's in-flight off-CPU block: its blocking stack (user PCs + raw
// kernel PCs) captured when it was switched out, plus when. Keyed by tid;
// emitted + deleted when the thread is switched back in. The value is too big
// for the 512-byte BPF stack, so it is built in offcpu_scratch (per-CPU) and
// copied into offcpu.
struct sismo_offcpu_state {
  __u64 start_ns;
  // What this block is waiting ON, when we can name it: the futex uaddr (lock
  // identity) for a futex wait, or the packed peer (host_port<<32 | be32 addr)
  // for a blocking TCP recv. 0 when the block carries no such id. A block is a
  // futex OR a socket, never both; the wait-type classifier tells them apart.
  __u64 block_id;
  __u32 nr_frames;
  __u32 nr_kernel;
  __u64 ustack[SISMO_MAX_STACK];
  __u64 kids[SISMO_MAX_KERNEL_STACK];  // raw kernel PCs, leaf-first
};
struct {
  // LRU so a long session self-bounds: an evicted in-flight block just drops
  // that one off-CPU sample, no correctness issue. The tid-keyed maps are
  // safe as LRU: their population is target-scoped threads, far below
  // capacity, so the eviction path that storms never runs.
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 10240);
  __type(key, __u32);
  __type(value, struct sismo_offcpu_state);
} offcpu SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct sismo_offcpu_state);
} offcpu_scratch SEC(".maps");

// tid -> the futex uaddr the thread is currently inside a futex() syscall on.
// Set on syscall entry, cleared on exit, so a lookup is non-zero only while the
// thread is actually parked in a futex — which is exactly when a voluntary
// off-CPU block through futex is a lock/condvar wait. A non-futex block (read,
// nanosleep) finds nothing here and carries uaddr 0.
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 10240);
  __type(key, __u32);
  __type(value, __u64);
} futex_wait SEC(".maps");

// tid -> the packed TCP peer (host_port<<32 | be32 daddr) the thread is inside
// tcp_recvmsg on. Same pattern as futex_wait: set on kprobe entry, cleared on
// return, so a blocking recv that goes off-CPU is tagged with the remote it's
// waiting on. IPv4 only for now (a u64 can't hold a v6 address).
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 10240);
  __type(key, __u32);
  __type(value, __u64);
} net_peer SEC(".maps");

// tid -> the bit-62-tagged interned file id the thread is inside a blocking
// file read on. Same set-on-entry / clear-on-return pattern as net_peer.
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 10240);
  __type(key, __u32);
  __type(value, __u64);
} disk_file SEC(".maps");

// inode pointer -> interned file id, + its monotonic allocator.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);  // not LRU: probe-context updates evict badly
  __uint(max_entries, 32768);
  __type(key, __u64);
  __type(value, __u32);
} file_ids SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} file_next SEC(".maps");

// Fixed-offset view of the syscalls/sys_enter_futex tracepoint record (the
// format is UAPI-stable, so no CO-RE): 8 bytes of common fields, then the
// syscall nr, then the futex() args. We only need uaddr (arg0, offset 16).
struct sys_enter_futex_ctx {
  __u64 _common;
  __s32 __syscall_nr;
  __u32 _pad0;
  __u64 uaddr;
};

// Intern a file (keyed by its inode pointer) to an id, emitting a SISMO_EVT_FILE
// definition (id + base name from the dentry) on first sight — a
// ship-an-id-once pattern, so a disk block references a file by
// id instead of carrying a string. Returns the id, or 0 if none could be minted.
static __always_inline __u32 resolve_file(struct file *file) {
  struct inode *inode = BPF_CORE_READ(file, f_inode);
  __u64 key = (__u64)inode;
  __u32 *idp = bpf_map_lookup_elem(&file_ids, &key);
  if (idp)
    return *idp;

  __u32 zero = 0;
  __u64 *next = bpf_map_lookup_elem(&file_next, &zero);
  if (!next)
    return 0;
  __u32 id = (__u32)__sync_fetch_and_add(next, 1) + 1;
  bpf_map_update_elem(&file_ids, &key, &id, BPF_ANY);

  struct sismo_ksym_rec *k = bpf_ringbuf_reserve(&events, sizeof(*k), 0);
  if (k) {
    k->type = SISMO_EVT_FILE;
    k->id = id;
    const unsigned char *namep = BPF_CORE_READ(file, f_path.dentry, d_name.name);
    bpf_probe_read_kernel_str(k->name, sizeof(k->name), namep);
    bpf_ringbuf_submit(k, ringbuf_flags(&events));
  }
  return id;
}

// CAP-1: intern a CPython code-object qualname (keyed by the PyUnicode pointer)
// to an id, emitting a SISMO_EVT_PYFRAME (id -> name) on first sight — the
// same intern-once pattern for interpreter frames. `qual` is the co_qualname pointer
// in the target; `pc` supplies the unicode offsets. Returns 0 if none minted.
static __noinline __u32 resolve_pyframe(struct sismo_py_cfg *pc, __u64 qual) {
  __u32 *idp = bpf_map_lookup_elem(&pyframe_ids, &qual);
  if (idp)
    return *idp;

  __u32 zero = 0;
  __u64 *next = bpf_map_lookup_elem(&pyframe_next, &zero);
  if (!next)
    return 0;
  __u32 id = (__u32)__sync_fetch_and_add(next, 1) + 1;
  bpf_map_update_elem(&pyframe_ids, &qual, &id, BPF_ANY);

  struct sismo_pyframe_rec *r = bpf_ringbuf_reserve(&events, sizeof(*r), 0);
  if (r) {
    r->type = SISMO_EVT_PYFRAME;
    r->id = id;
    r->name[0] = 0;
    // co_qualname is a compact-ASCII PyUnicode: `length` then that many chars at
    // the ASCII-header size. Mask the length to the buffer (power of two) so the
    // verifier accepts the variable-size read.
    __u64 len = 0;
    bpf_probe_read_user(&len, sizeof(len), (void *)(qual + pc->unicode_length));
    len &= (SISMO_PY_NAME_MAX - 1);
    if (len)
      bpf_probe_read_user(r->name, len, (void *)(qual + pc->unicode_data));
    r->name[len] = 0;
    bpf_ringbuf_submit(r, ringbuf_flags(&events));
  }
  return id;
}

// CAP-1: walk the sampled thread's CPython frame chain directly in the target's
// memory (bpf_probe_read_user, exact at sample time) and fill py_ids[] leaf-first,
// returning the count. Mirrors the host PY-1 walk: _PyRuntime -> first
// interpreter -> first thread state -> current_frame -> `previous` chain, naming
// each frame's code-object qualname. A frameless C-shim frame (executable == 0)
// is skipped, not named. No-op when py_cfg is unset (every non-Python target).
static __noinline __u32 walk_python(__u32 *py_ids) {
  __u32 zero = 0;
  struct sismo_py_cfg *pc = bpf_map_lookup_elem(&py_cfg, &zero);
  if (!pc || !pc->runtime)
    return 0;

  __u64 interp = 0, tstate = 0, frame = 0;
  if (bpf_probe_read_user(&interp, sizeof(interp),
                          (void *)(pc->runtime + pc->interpreters_head)) ||
      !interp)
    return 0;
  if (bpf_probe_read_user(&tstate, sizeof(tstate),
                          (void *)(interp + pc->threads_head)) ||
      !tstate)
    return 0;
  if (bpf_probe_read_user(&frame, sizeof(frame),
                          (void *)(tstate + pc->current_frame)))
    return 0;

  // Real bounded loop (not unrolled): the verifier walks the body once with a
  // bounded trip count, which keeps on_tick's complexity under the limit — the
  // 32x-unrolled form blew -E2BIG.
  __u32 n = 0;
  for (int i = 0; i < SISMO_MAX_PY_FRAMES; i++) {
    if (!frame || n >= SISMO_MAX_PY_FRAMES)
      break;
    __u64 code = 0;
    if (bpf_probe_read_user(&code, sizeof(code),
                            (void *)(frame + pc->frame_executable)))
      break;
    if (code) {
      __u64 qual = 0;
      if (!bpf_probe_read_user(&qual, sizeof(qual),
                               (void *)(code + pc->code_qualname)) &&
          qual) {
        __u32 id = resolve_pyframe(pc, qual);
        if (id)
          py_ids[n++ & (SISMO_MAX_PY_FRAMES - 1)] = id;
      }
    }
    __u64 nextf = 0;
    if (bpf_probe_read_user(&nextf, sizeof(nextf),
                            (void *)(frame + pc->frame_previous)))
      break;
    frame = nextf;
  }
  return n;
}

// CAP-2: bpf_find_vma callback — stash the containing vma's start + file page
// offset so the caller derives the module image base.
struct find_vma_ctx {
  __u64 start;
  __u64 end;
  __u64 pgoff;
};

// Per-CPU cache of the last VMA capture_module resolved, so a run of ticks in
// the same mapping (a hot loop) skips the bpf_find_vma tree walk — the single
// most expensive thing on the tick after the counter reads.
struct vma_cache {
  __u64 start;
  __u64 end;
};
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct vma_cache);
} last_vma SEC(".maps");
static long vma_info_cb(struct task_struct *task, struct vm_area_struct *vma, void *ctx) {
  struct find_vma_ctx *c = ctx;
  c->start = BPF_CORE_READ(vma, vm_start);
  c->end = BPF_CORE_READ(vma, vm_end);
  c->pgoff = BPF_CORE_READ(vma, vm_pgoff);
  return 0;
}

// CAP-2: on first sight of the module containing `pc`, copy its first mapped
// page (ELF header + build-id note) from the target's memory and ship it, so the
// host can name the module by build-id even if its file is later deleted. The
// image base is `vm_start - (vm_pgoff << PAGE_SHIFT)` — the address file-offset-0
// maps to, constant across the file's segments and equal to the host base_avma.
// bpf_find_vma trylocks mmap_lock, so it is best-effort in interrupt context; a
// miss just retries next sample (module_seen is set only on success).
static __noinline void capture_module(struct task_struct *cur, __u64 pc) {
  if (!pc)
    return;
  // Same VMA as the last tick on this CPU (the common case for a hot loop)?
  // Then its module was already resolved — skip the find_vma tree walk.
  __u32 zero = 0;
  struct vma_cache *vcache = bpf_map_lookup_elem(&last_vma, &zero);
  if (vcache && pc >= vcache->start && pc < vcache->end)
    return;

  struct find_vma_ctx vc = {};
  if (bpf_find_vma(cur, pc, vma_info_cb, &vc, 0) || !vc.start)
    return;
  // Cache the resolved range (seen or new) so repeated PCs in it skip find_vma.
  if (vcache) {
    vcache->start = vc.start;
    vcache->end = vc.end;
  }
  __u64 base = vc.start - (vc.pgoff << 12);  // PAGE_SHIFT = 12
  if (bpf_map_lookup_elem(&module_seen, &base))
    return;
  __u8 one = 1;
  bpf_map_update_elem(&module_seen, &base, &one, BPF_ANY);

  // Emit on the dedicated module_hints ringbuf so the capture thread pins this
  // module's fd and reads its build-id promptly, not behind the sample backlog.
  struct sismo_module_rec *r = bpf_ringbuf_reserve(&module_hints, sizeof(*r), 0);
  if (!r)
    return;
  r->type = SISMO_EVT_MODULE;
  r->base = base;
  r->tgid = bpf_get_current_pid_tgid() >> 32;
  r->_pad = 0;
  r->prefix_len = 0;
  if (bpf_probe_read_user(r->prefix, sizeof(r->prefix), (void *)base) == 0)
    r->prefix_len = sizeof(r->prefix);
  bpf_ringbuf_submit(r, 0);
}

static __always_inline __u32 target_tgid(void) {
  __u32 zero = 0;
  __u32 *t = bpf_map_lookup_elem(&cfg, &zero);
  return t ? *t : 0;
}

static __always_inline __u32 unwind_enabled(void) {
  __u32 one = 1;
  __u32 *v = bpf_map_lookup_elem(&cfg, &one);
  return v ? *v : 0;
}

// Slots actually parked by userspace. read_advance runs on the timer tick;
// reading only the live slots instead of all SISMO_MAX_COUNTERS bounds the
// per-tick cost. Empty slots always credit 0 either way.
static __always_inline __u32 counter_slots(void) {
  __u32 two = 2;
  __u32 *v = bpf_map_lookup_elem(&cfg, &two);
  __u32 n = v ? *v : SISMO_MAX_COUNTERS;
  return n > SISMO_MAX_COUNTERS ? SISMO_MAX_COUNTERS : n;
}

// Read every counter slot on the current CPU, diff against last_pe, advance
// last_pe (always — even on a non-target tick, so each interval's delta is
// counted once). Runs on the timer tick only; the delta since the previous
// tick is credited to the thread running now — statistical (perf-style)
// attribution, not exact per-slice accounting. Slots with no parked event read
// back an error and yield a 0 delta.
//
// Counters are multiplexed: more events are parked than the PMU has hardware
// counters, so the kernel time-shares groups on and off. bpf_perf_event_read_value
// reports each event's cumulative counter plus time-enabled/time-running; when
// an event was scheduled off for part of an interval (enabled advances faster
// than running) we scale the raw delta up by enabled/running to estimate the
// full-period count. When nothing was multiplexed the two move together and the
// delta is unchanged.
static __always_inline void read_advance(struct sismo_counters *dc) {
  __u32 zero = 0;
  __u32 cpu = bpf_get_smp_processor_id();
  struct sismo_last *last = bpf_map_lookup_elem(&last_pe, &zero);
  if (!last)
    return;
  __u32 nslots = counter_slots();
#pragma clang loop unroll(disable)
  for (__u32 s = 0; s < SISMO_MAX_COUNTERS; s++) {
    if (s >= nslots)
      break;
    struct bpf_perf_event_value val = {};
    __u64 idx = (__u64)s * SISMO_MAX_CPUS + cpu;
    if (bpf_perf_event_read_value(&counters_pe, idx, &val, sizeof(val))) {
      dc->v[s] = 0;
      continue;
    }
    __u64 dcount = val.counter - last->c[s];
    __u64 den = val.enabled - last->en[s];
    __u64 drun = val.running - last->run[s];
    // Scale only when the event was multiplexed off for part of the interval
    // (enabled outran running). Guard the divide; never-ran intervals (drun==0)
    // keep the raw 0 delta. Cap the scale-up at 8x: an event that ran for only a
    // sliver of the interval produces a wild enabled/running ratio that would
    // otherwise blow the estimate up by orders of magnitude (and overflow the
    // multiply) — clamp `den` so dcount*den can't run away.
    __u64 scaled = dcount;
    if (drun > 0 && den > drun) {
      __u64 max_den = drun * 8;
      if (den > max_den)
        den = max_den;
      scaled = dcount * den / drun;
    }
    dc->v[s] = scaled;
    last->c[s] = val.counter;
    last->en[s] = val.enabled;
    last->run[s] = val.running;
  }
}

static __always_inline struct sismo_counters *credit(struct task_struct *t,
                                                     const struct sismo_counters *dc) {
  struct sismo_counters *tc =
      bpf_task_storage_get(&thread_ctrs, t, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
  if (!tc)
    return 0;
#pragma clang loop unroll(disable)
  for (int s = 0; s < SISMO_MAX_COUNTERS; s++)
    tc->v[s] += dc->v[s];
  return tc;
}

// Switched OUT: capture the outgoing thread's blocking stack and remember when.
// Uses bpf_get_stack(ctx, ...) — the context's SAVED registers point at the
// block site (the outgoing thread is parked in __schedule, its user regs saved
// at syscall entry), which is what perf/offcputime use. bpf_get_task_stack
// instead walks from where the CPU is *now* (inside the helper) and returns an
// empty user stack for a task that still looks on-CPU here. Built in the per-CPU
// scratch, then stored keyed by tid.
static __always_inline void offcpu_record_block(void *ctx, __u32 tid) {
  __u32 zero = 0;
  struct sismo_offcpu_state *st = bpf_map_lookup_elem(&offcpu_scratch, &zero);
  if (!st)
    return;
  st->start_ns = bpf_ktime_get_ns();

  // A block names at most one waited-on thing: the futex uaddr, the TCP peer,
  // or the file id (a thread is in one syscall; the S_ISREG filter keeps sockets
  // out of disk_file). Fixed precedence, defensively.
  __u64 *fu = bpf_map_lookup_elem(&futex_wait, &tid);
  __u64 *pe = bpf_map_lookup_elem(&net_peer, &tid);
  __u64 *df = bpf_map_lookup_elem(&disk_file, &tid);
  st->block_id = fu ? *fu : (pe ? *pe : (df ? *df : 0));

  long un = bpf_get_stack(ctx, st->ustack, sizeof(st->ustack), BPF_F_USER_STACK);
  __u32 nu = (un > 0) ? (__u32)(un / 8) : 0;
  if (nu > SISMO_MAX_STACK)
    nu = SISMO_MAX_STACK;
  st->nr_frames = nu;

  // Raw kernel PCs, saved in the block state until wake; symbolized host-side.
  struct sismo_kstack *ks = bpf_map_lookup_elem(&kstack_scratch, &zero);
  __u32 nk = 0;
  if (ks) {
    long kn = bpf_get_stack(ctx, ks->addr, sizeof(ks->addr), SKIP_KERNEL_FRAMES);
    nk = (kn > 0) ? (__u32)(kn / 8) : 0;
    if (nk > SISMO_MAX_KERNEL_STACK)
      nk = SISMO_MAX_KERNEL_STACK;
    for (int i = 0; i < SISMO_MAX_KERNEL_STACK && i < nk; i++)
      st->kids[i] = ks->addr[i];
  }
  st->nr_kernel = nk;

  bpf_map_update_elem(&offcpu, &tid, st, BPF_ANY);
}

// Switched IN: if this thread has a pending block record, emit an OFFCPU sample
// with the measured off-CPU duration (unless the block was too short) and clear
// it.
static __always_inline void offcpu_emit_wake(__u32 tid, __u32 tgid) {
  struct sismo_offcpu_state *st = bpf_map_lookup_elem(&offcpu, &tid);
  if (!st)
    return;
  __u64 now = bpf_ktime_get_ns();
  __u64 delta = now - st->start_ns;
  if (delta >= MIN_OFFCPU_NS) {
    struct sismo_sample_rec *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
      e->hdr.type = SISMO_EVT_OFFCPU;
      e->hdr.tid = tid;
      e->hdr.pid = tgid;
      e->hdr.cpu = bpf_get_smp_processor_id();
      e->hdr.timebase = 0;
      e->hdr.nr_frames = st->nr_frames;
      e->hdr.nr_kernel_frames = st->nr_kernel;
      e->hdr.ts = now;
      e->data_addr = delta; // off-CPU duration (ns) = the sample's weight
#pragma clang loop unroll(disable)
      for (int s = 0; s < SISMO_MAX_COUNTERS; s++)
        e->counters[s] = 0;
      // counters[] are meaningless for an off-CPU sample; slot 0 carries the
      // block identity (futex uaddr or packed TCP peer), 0 when unnamed.
      e->counters[0] = st->block_id;
      #pragma clang loop unroll(disable)
      for (int i = 0; i < SISMO_MAX_STACK; i++)
        e->stack[i] = (i < st->nr_frames) ? st->ustack[i] : 0;
      #pragma clang loop unroll(disable)
      for (int i = 0; i < SISMO_MAX_KERNEL_STACK; i++)
        e->kernel_ids[i] = (i < st->nr_kernel) ? st->kids[i] : 0;
      bpf_ringbuf_submit(e, ringbuf_flags(&events));
    }
  }
  bpf_map_delete_elem(&offcpu, &tid);
}

SEC("tp_btf/sched_switch")
int BPF_PROG(on_sched_switch, bool preempt, struct task_struct *prev,
             struct task_struct *next) {
  __u32 tgt = target_tgid();

  // No PMU work here: counters are sampled on the timer tick, not read at every
  // switch, so this program does only the target's off-CPU accounting. That
  // keeps the highest-frequency, system-wide hook down to a couple of field
  // reads for a non-target switch.
  //
  // Outgoing thread (if in the target): if it went to sleep (a voluntary block,
  // not preemption), record its off-CPU block.
  __u32 prev_tgid = BPF_CORE_READ(prev, tgid);
  if (tgt == 0 || prev_tgid == tgt) {
    if (BPF_CORE_READ(prev, __state) != TASK_RUNNING)
      offcpu_record_block(ctx, (__u32)BPF_CORE_READ(prev, pid));
  }

  // Incoming thread (if in the target): close out its off-CPU block.
  __u32 next_tgid = BPF_CORE_READ(next, tgid);
  if (tgt == 0 || next_tgid == tgt) {
    offcpu_emit_wake((__u32)BPF_CORE_READ(next, pid), next_tgid);
  }
  return 0;
}

// Track which futex uaddr each target thread is parked on. Set on entry, cleared
// on exit; offcpu_record_block reads it so a block inside futex() is tagged with
// the lock instance. Storing all futex ops (not just WAIT) is fine: only a
// WAIT-family op actually blocks off-CPU, and clearing on exit bounds staleness
// so a later non-futex block never sees a stale uaddr.
SEC("tracepoint/syscalls/sys_enter_futex")
int on_futex_enter(struct sys_enter_futex_ctx *ctx) {
  __u32 tgt = target_tgid();
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);
  if (tgt != 0 && tgid != tgt)
    return 0;
  __u32 tid = (__u32)pid_tgid;
  __u64 uaddr = ctx->uaddr;
  bpf_map_update_elem(&futex_wait, &tid, &uaddr, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_futex")
int on_futex_exit(void *ctx) {
  __u32 tgt = target_tgid();
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  if (tgt != 0 && (__u32)(pid_tgid >> 32) != tgt)
    return 0;  // the map only ever holds target tids
  __u32 tid = (__u32)pid_tgid;
  bpf_map_delete_elem(&futex_wait, &tid);
  return 0;
}

// Blocking TCP recv: read the peer 5-tuple off the sock on entry so a recv that
// parks off-CPU (waiting for data) is tagged with the remote it waits on. sk is
// arg0 of tcp_recvmsg on every kernel. IPv4 only; a v6 peer stores 0 (unnamed).
SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(on_tcp_recvmsg, struct sock *sk) {
  __u32 tgt = target_tgid();
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);
  if (tgt != 0 && tgid != tgt)
    return 0;
  __u32 tid = (__u32)pid_tgid;
  __u64 peer = 0;
  __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
  if (family == 2 /* AF_INET */) {
    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);   // be32
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);   // be16
    __u16 port = (__u16)((dport >> 8) | (dport << 8));        // -> host order
    // Bit 63 tags this block_id as a network peer, not a futex uaddr (userspace
    // addresses are canonical < 2^48, so they never set it) — so the classifier
    // can tell network from lock without another field. port in 32..47, addr low.
    peer = (1ULL << 63) | ((__u64)port << 32) | (__u64)daddr;
  }
  bpf_map_update_elem(&net_peer, &tid, &peer, BPF_ANY);
  return 0;
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(on_tcp_recvmsg_ret) {
  __u32 tgt = target_tgid();
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  if (tgt != 0 && (__u32)(pid_tgid >> 32) != tgt)
    return 0;  // the map only ever holds target tids
  __u32 tid = (__u32)pid_tgid;
  bpf_map_delete_elem(&net_peer, &tid);
  return 0;
}

// Blocking file read: tag a read that parks off-CPU (page-cache miss / direct
// I/O waiting on the device) with the file it reads. Only regular files —
// sockets/pipes go through vfs_read too but are named by peer / classified by
// their own primitive, so we skip them. file is arg0 of vfs_read.
SEC("kprobe/vfs_read")
int BPF_KPROBE(on_vfs_read, struct file *file) {
  __u32 tgt = target_tgid();
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);
  if (tgt != 0 && tgid != tgt)
    return 0;
  __u16 mode = BPF_CORE_READ(file, f_inode, i_mode);
  if ((mode & 0170000) != 0100000 /* S_ISREG */)
    return 0;
  __u32 id = resolve_file(file);
  if (id == 0)
    return 0;
  __u32 tid = (__u32)pid_tgid;
  // Bit 62 tags block_id as a file id (bit 63 is a network peer); a futex uaddr
  // is a userspace address < 2^48 and sets neither.
  __u64 tagged = (1ULL << 62) | (__u64)id;
  bpf_map_update_elem(&disk_file, &tid, &tagged, BPF_ANY);
  return 0;
}

SEC("kretprobe/vfs_read")
int BPF_KRETPROBE(on_vfs_read_ret) {
  __u32 tgt = target_tgid();
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  if (tgt != 0 && (__u32)(pid_tgid >> 32) != tgt)
    return 0;  // the map only ever holds target tids
  __u32 tid = (__u32)pid_tgid;
  bpf_map_delete_elem(&disk_file, &tid);
  return 0;
}

SEC("perf_event")
int on_tick(struct bpf_perf_event_data *ctx) {
  struct sismo_counters dc;
  read_advance(&dc);

  struct task_struct *cur = bpf_get_current_task_btf();
  __u32 tgt = target_tgid();
  __u32 tgid = BPF_CORE_READ(cur, tgid);
  if (tgt != 0 && tgid != tgt)
    return 0;

  struct sismo_counters *tc = credit(cur, &dc);
  if (!tc)
    return 0;

  // Kernel stack first (no BPF_F_USER_STACK): empty for samples that fired in
  // pure userspace, otherwise the in-kernel frames the tick interrupted. Each
  // address is resolved to an id now — committing any new KSYM definitions to
  // the ringbuf *before* the sample below, so userspace sees a frame's name
  // defined ahead of the sample that uses it.
  __u32 zero = 0;
  struct sismo_kstack *ks = bpf_map_lookup_elem(&kstack_scratch, &zero);
  __u32 nr_kernel = 0;
  if (ks) {
    long kn = bpf_get_stack(ctx, ks->addr, sizeof(ks->addr), SKIP_KERNEL_FRAMES);
    nr_kernel = (kn > 0) ? (__u32)(kn / 8) : 0;
    if (nr_kernel > SISMO_MAX_KERNEL_STACK)
      nr_kernel = SISMO_MAX_KERNEL_STACK;
    // Raw PCs ship straight from ks->addr[] into the record below; no
    // resolution here — symbolized host-side from kallsyms.
  }

  // CAP-2: ship the sampled module's identity page (image base + build-id note)
  // in-band, once per module, so a binary deleted before symbolization still
  // resolves to a real build-id.
  capture_module(cur, PT_REGS_IP((struct pt_regs *)&ctx->regs));

  // NAT-1: when unwind capture is on, ship a sismo_unwind_rec instead of the
  // plain sample — same sample fields (only hdr.type differs), plus the regs
  // + a raw user-stack snapshot for host-side DWARF unwinding. Filled
  // directly into the ringbuf reservation (never on the 512-byte BPF stack).
  // Nothing consumes regs/stack_bytes yet: the FP stack[] above is still what
  // gets processed, so today's facts don't move.
  if (unwind_enabled()) {
    struct sismo_unwind_rec *ue = bpf_ringbuf_reserve(&events, sizeof(*ue), 0);
    if (!ue)
      return 0;
    ue->sample.hdr.type = SISMO_EVT_SAMPLE_UNWIND;
    ue->sample.hdr.tid = BPF_CORE_READ(cur, pid);
    ue->sample.hdr.pid = tgid;
    ue->sample.hdr.cpu = bpf_get_smp_processor_id();
    ue->sample.hdr.timebase = (unsigned int)bpf_get_attach_cookie(ctx);
    ue->sample.hdr.nr_kernel_frames = nr_kernel;
    ue->sample.hdr.ts = bpf_ktime_get_ns();
    ue->sample.data_addr = ctx->addr;
#pragma clang loop unroll(disable)
    for (int s = 0; s < SISMO_MAX_COUNTERS; s++)
      ue->sample.counters[s] = tc->v[s];
    long un = bpf_get_stack(ctx, ue->sample.stack, sizeof(ue->sample.stack), BPF_F_USER_STACK);
    ue->sample.hdr.nr_frames = (un > 0) ? (__u32)(un / 8) : 0;
    #pragma clang loop unroll(disable)
    for (int i = 0; i < SISMO_MAX_KERNEL_STACK; i++)
      ue->sample.kernel_ids[i] = (ks && i < nr_kernel) ? ks->addr[i] : 0;
    // CAP-1: recover CPython frames from the interpreter's memory at sample time.
    ue->sample.hdr.nr_py_frames = walk_python(ue->sample.py_ids);

    // bpf_perf_event_data.regs is an opaque u64[21] blob (see kernel_defs.h)
    // laid out exactly like x86_64 struct pt_regs, so the CO-RE-safe
    // PT_REGS_* accessors work once cast to that type.
    struct pt_regs *uregs = (struct pt_regs *)&ctx->regs;
    ue->regs_ip = PT_REGS_IP(uregs);
    ue->regs_sp = PT_REGS_SP(uregs);
    ue->regs_bp = PT_REGS_FP(uregs);

    // bpf_probe_read_user is all-or-nothing: it copies the whole requested
    // size or nothing. A shallow stack sits close to its mapping top, so a
    // full SISMO_STACK_SNAP_MAX read from sp overruns the top page and fails
    // outright — which is the common case for the simple, FP-less workloads
    // NAT-1 targets. Try decreasing power-of-two sizes and keep the largest
    // that maps; each unrolled size is a compile-time constant the verifier
    // can bound against the 8 KiB buffer.
    __u32 snap = 0;
#pragma unroll
    for (int shift = 0; shift < 5; shift++) {
      if (snap == 0) {
        __u32 sz = SISMO_STACK_SNAP_MAX >> shift;
        if (bpf_probe_read_user(ue->stack_bytes, sz, (void *)ue->regs_sp) == 0)
          snap = sz;
      }
    }
    ue->stack_len = snap;
    ue->stack_trunc = (snap < SISMO_STACK_SNAP_MAX) ? 1 : 0;

    bpf_ringbuf_submit(ue, ringbuf_flags(&events));
    return 0;
  }

  struct sismo_sample_rec *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;
  e->hdr.type = SISMO_EVT_SAMPLE;
  e->hdr.tid = BPF_CORE_READ(cur, pid);
  e->hdr.pid = tgid;
  e->hdr.cpu = bpf_get_smp_processor_id();
  // Which sampler (timebase) overflowed: the per-link attach cookie set when
  // openSampler attached on_tick. 0 for the single-timebase (survey) path.
  e->hdr.timebase = (unsigned int)bpf_get_attach_cookie(ctx);
  e->hdr.nr_kernel_frames = nr_kernel;
  e->hdr.ts = bpf_ktime_get_ns();
  // Data linear address of the sampled access (the kernel fills ctx->addr only
  // when the leader event sampled PERF_SAMPLE_ADDR — the cache focus; 0 else).
  e->data_addr = ctx->addr;
#pragma clang loop unroll(disable)
  for (int s = 0; s < SISMO_MAX_COUNTERS; s++)
    e->counters[s] = tc->v[s];
  long n = bpf_get_stack(ctx, e->stack, sizeof(e->stack), BPF_F_USER_STACK);
  e->hdr.nr_frames = (n > 0) ? (__u32)(n / 8) : 0;
  #pragma clang loop unroll(disable)
  for (int i = 0; i < SISMO_MAX_KERNEL_STACK; i++)
    e->kernel_ids[i] = (ks && i < nr_kernel) ? ks->addr[i] : 0;
  e->hdr.nr_py_frames = walk_python(e->py_ids);  // CAP-1
  bpf_ringbuf_submit(e, ringbuf_flags(&events));
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
