// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

// The sismo BPF CPU collector: exact per-thread accounting of up to
// SISMO_MAX_COUNTERS PMU counters plus stack profiling, push-based.
//
// Userspace parks one free-running counting perf event per (counter slot, CPU)
// in counters_pe at index slot*SISMO_MAX_CPUS + cpu. Slots it leaves empty
// (counters the hardware couldn't provide) simply read back as errors and are
// credited 0. The counters are read at three hook points; each diffs against
// the value at the previous read on the same CPU (last_pe) and credits the
// delta to the thread that ran during that interval:
//
//   sched_switch  -> credit the outgoing thread (exact run-boundary totals)
//   perf_event    -> a per-CPU timer tick: credit the *running* thread (flushes
//                    long-running threads that rarely switch out) AND capture
//                    its stack — both the periodic counter flush and the CPU
//                    profile.
//
// last_pe is advanced on every read regardless of whether the thread is in the
// target process, so deltas always reflect exactly the interval's counts. Per-
// thread totals live in TASK_STORAGE (auto-freed on task exit).

#include "kernel_defs.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "sismo_bpf.h"

#ifndef BPF_F_USER_STACK
#define BPF_F_USER_STACK (1ULL << 8)
#endif

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
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} cfg SEC(".maps");  // cfg[0] = target tgid (0 = all)

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 22);  // 4 MiB
} events SEC(".maps");

// Kernel-symbol interning. ksym_ids maps a kernel address to the id we assigned
// it; LRU so a long session self-bounds — an evicted address is just re-resolved
// and gets a fresh id, harmless because userspace dedups by name. ksym_next is
// the monotonic id allocator (value 0 is reserved for "unresolved").
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 8192);
  __type(key, __u64);
  __type(value, __u32);
} ksym_ids SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} ksym_next SEC(".maps");

// Per-CPU scratch for the kernel stack: bpf_get_stack writes the addresses here
// (kept off the 512-byte BPF stack and out of the shipped record); the resolve
// loop then fills `id` in place.
struct sismo_kstack {
  __u64 addr[SISMO_MAX_KERNEL_STACK];
  __u32 id[SISMO_MAX_KERNEL_STACK];
};
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct sismo_kstack);
} kstack_scratch SEC(".maps");

// Resolve a kernel address to a symbol id, assigning + emitting a SISMO_EVT_KSYM
// definition on first sight. The address is used only as a lookup key and to
// drive the in-kernel `%pB` kallsyms lookup; it never leaves the kernel, so the
// KASLR slide can't be reconstructed from the trace. Returns 0 if no id could
// be assigned (userspace renders such frames as "[kernel]").
static __always_inline __u32 resolve_ksym(__u64 addr) {
  __u32 *idp = bpf_map_lookup_elem(&ksym_ids, &addr);
  if (idp)
    return *idp;

  __u32 zero = 0;
  __u64 *next = bpf_map_lookup_elem(&ksym_next, &zero);
  if (!next)
    return 0;
  // Atomic so concurrent CPUs get distinct ids. A race can still mint two ids
  // for one address (both miss the lookup); that yields two definitions of the
  // same name, which userspace collapses — no correctness issue.
  __u32 id = (__u32)__sync_fetch_and_add(next, 1) + 1;
  bpf_map_update_elem(&ksym_ids, &addr, &id, BPF_ANY);

  struct sismo_ksym_rec *k = bpf_ringbuf_reserve(&events, sizeof(*k), 0);
  if (k) {
    k->type = SISMO_EVT_KSYM;
    k->id = id;
    // %pB: kallsyms symbol for a return address (it subtracts 1 before the
    // lookup). Emits "name+0xoff/0xsize"; userspace keeps the bare name.
    __u64 args[1] = {addr};
    bpf_snprintf(k->name, sizeof(k->name), "%pB", args, sizeof(args));
    bpf_ringbuf_submit(k, 0);
  }
  return id;
}

static __always_inline __u32 target_tgid(void) {
  __u32 zero = 0;
  __u32 *t = bpf_map_lookup_elem(&cfg, &zero);
  return t ? *t : 0;
}

// Read every counter slot on the current CPU, diff against last_pe, advance
// last_pe (always — even for non-target threads, to keep future deltas exact).
// Slots with no parked event read back an error and yield a 0 delta.
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
#pragma unroll
  for (int s = 0; s < SISMO_MAX_COUNTERS; s++) {
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
#pragma unroll
  for (int s = 0; s < SISMO_MAX_COUNTERS; s++)
    tc->v[s] += dc->v[s];
  return tc;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(on_sched_switch, bool preempt, struct task_struct *prev,
             struct task_struct *next) {
  struct sismo_counters dc;
  read_advance(&dc);

  __u32 tgt = target_tgid();
  __u32 tgid = BPF_CORE_READ(prev, tgid);
  if (tgt != 0 && tgid != tgt)
    return 0;

  // Credit keeps the per-thread cumulative exact across run boundaries; the
  // value is carried out by the next timer-tick PerfSample, so no emit here.
  credit(prev, &dc);
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
    long kn = bpf_get_stack(ctx, ks->addr, sizeof(ks->addr), 0);
    nr_kernel = (kn > 0) ? (__u32)(kn / 8) : 0;
    if (nr_kernel > SISMO_MAX_KERNEL_STACK)
      nr_kernel = SISMO_MAX_KERNEL_STACK;
    // A real bounded loop, not #pragma unroll: resolve_ksym inlines a ringbuf
    // reserve + bpf_snprintf, so 64 unrolled copies blow the 512-byte BPF stack.
    for (int i = 0; i < SISMO_MAX_KERNEL_STACK && i < nr_kernel; i++)
      ks->id[i] = resolve_ksym(ks->addr[i]);
  }

  struct sismo_sample_rec *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;
  e->hdr.type = SISMO_EVT_SAMPLE;
  e->hdr.tid = BPF_CORE_READ(cur, pid);
  e->hdr.pid = tgid;
  e->hdr.cpu = bpf_get_smp_processor_id();
  e->hdr.nr_kernel_frames = nr_kernel;
  e->hdr.ts = bpf_ktime_get_ns();
#pragma unroll
  for (int s = 0; s < SISMO_MAX_COUNTERS; s++)
    e->counters[s] = tc->v[s];
  long n = bpf_get_stack(ctx, e->stack, sizeof(e->stack), BPF_F_USER_STACK);
  e->hdr.nr_frames = (n > 0) ? (__u32)(n / 8) : 0;
  for (int i = 0; i < SISMO_MAX_KERNEL_STACK; i++)
    e->kernel_ids[i] = (ks && i < nr_kernel) ? ks->id[i] : 0;
  bpf_ringbuf_submit(e, 0);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
