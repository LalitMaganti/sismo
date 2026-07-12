# Off-CPU profiling: one contract, three backends

sismo captures off-CPU (blocked/waiting) time the same way on every platform.
This doc is the shared **semantic contract** and how each backend
(Linux eBPF, macOS kperf, Windows ETW) produces it. Keep the three in sync with
this doc — if a backend can't meet the contract, the divergence is documented
here, not left implicit.

## The contract

An **off-CPU sample** describes one completed interval in which a thread was
voluntarily blocked, attributed to where it blocked and weighted by how long.

Wire form: `SISMO_EVT_OFFCPU` (reuses `sismo_sample_rec`, see
`crates/sismo-sys/csrc/sismo_bpf/sismo_bpf.h`):

| field | meaning |
| --- | --- |
| `tid`, `pid` | the blocked thread / its process |
| `ts` | wake timestamp (monotonic ns) |
| `stack[]` | **blocking user PCs**, leaf-first, ≤ `SISMO_MAX_STACK` |
| `kernel_ids[]` | blocking kernel frames (interned symbol ids), ≤ `SISMO_MAX_KERNEL_STACK` |
| `data_addr` | **off-CPU duration in ns = the sample weight** |
| `counters[]` | 0 |

Rules — identical on every backend:

1. **Voluntary blocks only.** Count an off-CPU interval when the thread *went to
   sleep* (waiting on I/O, a lock, a timer, a condition), **not** when it was
   involuntarily preempted while still runnable. This is "wait analysis", and
   it's the only semantic all three backends can produce natively.
2. **Emit once per completed interval, at wake**, carrying the blocking stack and
   `duration = wake − block`.
3. **Threshold.** Drop intervals shorter than a minimum (Linux `MIN_OFFCPU_NS`,
   default 10 µs) — sub-threshold yields aren't latency and dominate cost.
4. **Pid-scoped.** Restrict to the target process as early as the platform allows
   (in-kernel where possible; see the asymmetry table).
5. **The stack is the blocking call chain.** Whether captured at block time
   (Linux) or at wake (macOS/Windows), it is the same chain for a thread parked
   in a syscall/wait — the user frames don't move while blocked.

## Backend mapping

| | Linux eBPF | macOS kperf `lazy.wait` | Windows ETW |
| --- | --- | --- | --- |
| trigger | `tp_btf/sched_switch` | `kperf.lazy.wait_action` (fires on wake) | `Thread/CSwitch` events |
| voluntary filter | `prev->__state != TASK_RUNNING` at switch-out | native (fires only on wait-wakeups) | `OldThreadState == Waiting` in consumer |
| stack capture | switch-out, `bpf_get_stack(ctx)` | wake, `SAMPLE_FLAG_PEND_USER` AST | switch-in stack (StackWalk on CSwitch) |
| duration | computed `wake − block` (bpf map keyed by tid) | kernel-provided `wait_time` (`PERF_LZ_WAITSAMPLE`) | computed by pairing out→in per tid |
| threshold | `MIN_OFFCPU_NS` in the BPF program | `kperf.lazy.wait_time_threshold` (native) | in the consumer |
| **pid scope** | **in-kernel** (`cfg` tgid) | **in-kernel** (`pid_filter`, honored on this on-core path) | **in the consumer** (CSwitch is system-wide) |

### Asymmetries (documented, not accidental)

- **Pid filtering location.** Linux and macOS drop non-target work in the kernel.
  ETW's `CSwitch` is a system-wide kernel event with no per-process filter, so the
  consumer receives every context switch and filters there — higher overhead, no
  way around it on Windows. (This is the same reason we abandoned macOS PET: see
  `docs`/commit history — PET's user-stack sampler is unfiltered. `lazy.wait` is
  on-core and *is* filtered, which is why macOS matches Linux here and Windows
  can't.)
- **Stack capture point.** Linux grabs the stack at switch-out; macOS/Windows at
  wake/switch-in. Same chain for a blocked thread (rule 5).

## Linux (implemented)

`crates/sismo-sys/csrc/sismo_bpf/sched.bpf.c`. On `sched_switch`: if the outgoing
thread is in the target and `prev->__state != TASK_RUNNING`, capture its user +
kernel blocking stack via `bpf_get_stack(ctx, …)` and store it keyed by tid. On
the incoming thread's switch-in, compute `delta`, and if `delta ≥ MIN_OFFCPU_NS`
emit `SISMO_EVT_OFFCPU`. Kernel frames are interned to symbol ids in-kernel so no
kernel address (KASLR) leaves the kernel.

## macOS (implemented as a spike; fold into `macos_sched_capture`)

`crates/kperf-spike` (default mode). Arm `kperf.lazy.wait_action = <action>` +
`kperf.lazy.wait_time_threshold` (mach-abs ticks) with an action that samples
`USTACK | TH_INFO`, `filter_by_pid = target`. No timer/PET. `osfmk/kperf/lazy.c`
`kperf_lazy_wait_sample` fires on-core when a thread wakes from a wait over the
threshold: it emits `PERF_LZ_WAITSAMPLE(wait_time, runnable_time, running_time)`
(mach ticks) and, via `SAMPLE_FLAG_PEND_USER` → `kperf_sample` (pid-filtered),
the blocking user stack. Decoder pairs each `WAITSAMPLE` with the pended user
callstack for the same tid (the kd_buf tid is the woken thread, since on-core).

Verified: 3 threads sleeping 20 ms → per-block durations ~20–25 ms, block site
`time_sleep → __semwait_signal`, **1 distinct pid** (in-kernel filter), ~300×
less ring traffic than PET.

Next step: fold the arming + `LazyDecoder` into
`crates/sismo-core/src/sched/macos_sched_capture.rs` as a second decoder on the
one kdebug session (demux `DBG_MACH_SCHED` vs `DBG_PERF`), emitting the shared
`SISMO_EVT_OFFCPU` record.

## Windows ETW (design — not yet implemented)

Windows is greenfield. The plan below conforms to the contract; **items marked
[VERIFY] must be confirmed on Windows** (same rigor as the kperf spike — don't
trust the docs blind).

**Session / providers.** A kernel-logger trace with context-switch events:
- `EVENT_TRACE_FLAG_CSWITCH` → `Thread/CSwitch` events (Old/NewThreadId,
  `OldThreadState`, `OldThreadWaitReason`, `OldThreadWaitMode`, timestamp).
- Stack walking on the CSwitch event via `TraceSetInformation` /
  `TraceStackTracingInfo` (the CSwitch stack-walk hook id).
- Optionally `EVENT_TRACE_FLAG_DISPATCHER` (`ReadyThread`) if we later want
  "who woke me" waker attribution — not needed for the base contract.

**Consumer state machine** (per tid, in the ETW real-time consumer):
- CSwitch with `OldThreadId = T`, T in the target process, **and
  `OldThreadState == Waiting`** (the voluntary-block filter, rule 1 — excludes
  preemption where the old thread is Ready/Standby): record `t_out = ts`.
  [VERIFY] exact `OldThreadState` enum value for "Waiting", and that quantum-end
  preemption reports a non-Waiting state.
- CSwitch with `NewThreadId = T`, T in target, and a recorded `t_out`:
  `duration = ts − t_out`; if `duration ≥ threshold`, emit `SISMO_EVT_OFFCPU`
  with `duration` as the weight and the **switch-in stack** as the blocking
  stack. Clear `t_out`.
  [VERIFY] that the StackWalk accompanying a CSwitch is the **incoming** thread's
  stack (T resuming out of the wait = the blocking chain). If it is instead the
  outgoing thread's stack, capture the stack on the switch-**out** CSwitch
  instead — semantics (rule 5) are unchanged either way; only which event we read
  the stack from changes.

**Pid scope.** Filter to the target process in the consumer (CSwitch is
system-wide; see asymmetry note). Resolve New/Old ThreadId → process via the
Thread rundown (`Thread/DCStart` + `Thread/Start`/`End`) the kernel logger emits.

**Threshold / duration units.** ETW timestamps are QPC (or 100 ns FILETIME
depending on `Wnode.ClientContext`); convert the paired delta to ns for
`data_addr`. Apply the same minimum as Linux/macOS.

**Symbolization.** User frames are module+offset resolved from the ETW image
rundown (`Image/DCStart`) against the target's modules — the Windows analog of
`atos` / the dyld-cache path.

## Checklist for keeping backends aligned

- [ ] Same record (`SISMO_EVT_OFFCPU`) and weight (duration ns in `data_addr`).
- [ ] Voluntary-only on every backend (state/wait-reason filter).
- [ ] Same threshold semantics.
- [ ] Pid scope as early as the platform allows; asymmetry documented above.
- [ ] Blocking stack = the block call chain (rule 5), leaf-first.
