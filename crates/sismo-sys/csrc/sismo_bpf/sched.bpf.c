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

// One thread's in-flight off-CPU block: its blocking stack (user PCs + resolved
// kernel-symbol ids) captured when it was switched out, plus when. Keyed by tid;
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
  __u32 kids[SISMO_MAX_KERNEL_STACK];
};
struct {
  // LRU so a long session self-bounds (like ksym_ids): an evicted in-flight
  // block just drops that one off-CPU sample, no correctness issue.
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

// Fixed-offset view of the syscalls/sys_enter_futex tracepoint record (the
// format is UAPI-stable, so no CO-RE): 8 bytes of common fields, then the
// syscall nr, then the futex() args. We only need uaddr (arg0, offset 16).
struct sys_enter_futex_ctx {
  __u64 _common;
  __s32 __syscall_nr;
  __u32 _pad0;
  __u64 uaddr;
};

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

  // A block names at most one waited-on thing: the futex uaddr, else the TCP
  // peer. Mutually exclusive in practice (a thread is in one syscall).
  __u64 *fu = bpf_map_lookup_elem(&futex_wait, &tid);
  __u64 *pe = bpf_map_lookup_elem(&net_peer, &tid);
  st->block_id = fu ? *fu : (pe ? *pe : 0);

  long un = bpf_get_stack(ctx, st->ustack, sizeof(st->ustack), BPF_F_USER_STACK);
  __u32 nu = (un > 0) ? (__u32)(un / 8) : 0;
  if (nu > SISMO_MAX_STACK)
    nu = SISMO_MAX_STACK;
  st->nr_frames = nu;

  // Kernel frames resolved to symbol ids now, so their KSYM definitions reach
  // the ringbuf before the OFFCPU sample (emitted at wake) that references them.
  struct sismo_kstack *ks = bpf_map_lookup_elem(&kstack_scratch, &zero);
  __u32 nk = 0;
  if (ks) {
    long kn = bpf_get_stack(ctx, ks->addr, sizeof(ks->addr), 0);
    nk = (kn > 0) ? (__u32)(kn / 8) : 0;
    if (nk > SISMO_MAX_KERNEL_STACK)
      nk = SISMO_MAX_KERNEL_STACK;
    for (int i = 0; i < SISMO_MAX_KERNEL_STACK && i < nk; i++)
      st->kids[i] = resolve_ksym(ks->addr[i]);
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
#pragma unroll
      for (int s = 0; s < SISMO_MAX_COUNTERS; s++)
        e->counters[s] = 0;
      // counters[] are meaningless for an off-CPU sample; slot 0 carries the
      // block identity (futex uaddr or packed TCP peer), 0 when unnamed.
      e->counters[0] = st->block_id;
      for (int i = 0; i < SISMO_MAX_STACK; i++)
        e->stack[i] = (i < st->nr_frames) ? st->ustack[i] : 0;
      for (int i = 0; i < SISMO_MAX_KERNEL_STACK; i++)
        e->kernel_ids[i] = (i < st->nr_kernel) ? st->kids[i] : 0;
      bpf_ringbuf_submit(e, 0);
    }
  }
  bpf_map_delete_elem(&offcpu, &tid);
}

SEC("tp_btf/sched_switch")
int BPF_PROG(on_sched_switch, bool preempt, struct task_struct *prev,
             struct task_struct *next) {
  struct sismo_counters dc;
  read_advance(&dc);

  __u32 tgt = target_tgid();

  // Outgoing thread (if in the target): credit its exact counter deltas — the
  // value is carried out by the next timer-tick PerfSample, so no emit here —
  // and, if it went to sleep (voluntary block, not preemption), record its
  // off-CPU block. Counter crediting happens for every switch-out; only the
  // off-CPU block is gated on prev actually blocking.
  __u32 prev_tgid = BPF_CORE_READ(prev, tgid);
  if (tgt == 0 || prev_tgid == tgt) {
    credit(prev, &dc);
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
  __u32 tid = (__u32)bpf_get_current_pid_tgid();
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
  __u32 tid = (__u32)bpf_get_current_pid_tgid();
  bpf_map_delete_elem(&net_peer, &tid);
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
  // Which sampler (timebase) overflowed: the per-link attach cookie set when
  // openSampler attached on_tick. 0 for the single-timebase (survey) path.
  e->hdr.timebase = (unsigned int)bpf_get_attach_cookie(ctx);
  e->hdr.nr_kernel_frames = nr_kernel;
  e->hdr.ts = bpf_ktime_get_ns();
  // Data linear address of the sampled access (the kernel fills ctx->addr only
  // when the leader event sampled PERF_SAMPLE_ADDR — the cache focus; 0 else).
  e->data_addr = ctx->addr;
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
