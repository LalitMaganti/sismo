// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.
//
//! macOS ring host: the one worker thread that owns the shared kdebug ring and
//! the kperf singleton, and fans each drained batch out to its consumers.
//!
//! The kdebug ring and kperf are machine-global — exactly one owner per machine
//! — so the sched timeline, off-CPU lazy.wait samples, and on-CPU timer samples
//! can't each run their own worker: they'd fight over KERN_KDEBUG. Instead this
//! host opens the ring once (with the union of its consumers' typefilters), arms
//! kperf once (with whichever samplers are enabled), and drives one drain loop.
//! Each consumer is a data source with its own SDK lifecycle; the host tracks
//! their run state and only feeds a batch to the ones that are running.
//!
//! The [`SchedConsumer`] (kdebug MACH_SCHED pairing → task-state timeline +
//! process tree) lives here; the perf consumers live in `kperf_sample`.
//!
//! macOS only; gated in lib.rs.

use crate::ffi::{sismo_ds_emit, sismo_ds_register, sismo_flush_done, sismo_stop_done};
use crate::mach::{mach_task_self_, mach_timebase_info, MachPort, TimebaseInfo, KERN_SUCCESS};
use crate::proto::sched_protos::{encode_kernel_process_tree, macos_sched_vm_program, ProcessC, ThreadC};
use crate::proto::session_config::encode_data_source_descriptor;
use crate::proto::sismo_config::{config_extract, cpu_decode, sched_decode};
use crate::proto::ProtoWriter;
use crate::sched::kdebug::KdebugRing;
use crate::sched::kperf::{arm, disarm, KperfConfig};
use crate::sched::kperf_sample::{OffCpuConsumer, OnCpuConsumer, DBG_PERF_CSC_RANGE};
use crate::sched::proc_info::{parent_pid, pid_path, thread_name};
use crate::sched::ring::{ConsumerCtl, KdEvent, KdThreadMap, RingConsumer};
use crate::worker_sdk::{now_ns, Event};
use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// Data-source names.
const SCHED_DS_NAME: &[u8] = b"sismo.macos_sched";
const OFFCPU_DS_NAME: &[u8] = b"sismo.macos_offcpu";
const ONCPU_DS_NAME: &[u8] = b"sismo.macos_cpu_samples";

// Defaults.
const DEFAULT_KERNEL_BUFFER_EVENTS: i32 = 256 * 1024;
const DEFAULT_OFFCPU_THRESHOLD_US: u32 = 500; // ignore waits < 0.5ms by default
const DEFAULT_CPU_INTERVAL_US: u32 = 1_000; // 1 kHz on-CPU timer
const DRAIN_INTERVAL_NS: u64 = 100 * 1_000_000;
const DRAIN_CAPACITY_EVENTS: usize = 256 * 1024;
const THREAD_MAP_CAPACITY: usize = 16 * 1024;

const MAX_CPUS: usize = 256;
// The sched consumer's kdebug filter contribution: DBG_MACH_SCHED, i.e. class
// DBG_MACH (1), subclass 0x40. csc = (class<<8)|subclass.
const SCHED_CSC: u16 = (1 << 8) | 0x40;
const SCHED_RANGES: [(u16, u16); 1] = [(SCHED_CSC, SCHED_CSC)];

// Staging caps per drain.
const MAX_NEW_THREADS: usize = 256;
const MAX_NEW_PROCESSES: usize = 128;

// TracePacket field tags.
const TP_FIELD_GENERIC_KERNEL_TASK_STATE: u32 = 117;
const TP_FIELD_GENERIC_KERNEL_PROCESS_TREE: u32 = 122;

// TaskStateEnum values (protos/.../generic_task.proto).
const TS_RUNNABLE: u32 = 2;
const TS_RUNNING: u32 = 3;
const TS_INTERRUPTIBLE_SLEEP: u32 = 4;
const TS_UNINTERRUPTIBLE_SLEEP: u32 = 5;
const TS_STOPPED: u32 = 6;

// ---- Sched consumer --------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct PendingSwitch {
    valid: bool,
    timestamp: u64,
    outgoing_tid: u64,
    outgoing_pri: u32,
    incoming_tid: u64,
    incoming_pri: u32,
}

/// First-seen name cache. Threads keyed by mach tid, processes by pid.
#[derive(Default)]
struct PtCache {
    threads: HashMap<u64, (i32, Vec<u8>)>,   // tid -> (pid, comm)
    processes: HashMap<i32, (i32, Vec<u8>)>, // pid -> (ppid, cmdline)
}

/// xnu thread-state bits → outgoing TaskState. Incoming is always RUNNING.
fn outgoing_task_state(state_bits: u32) -> u32 {
    if state_bits & 0x02 != 0 {
        return TS_STOPPED;
    }
    if state_bits & 0x01 != 0 {
        return if state_bits & 0x08 != 0 { TS_UNINTERRUPTIBLE_SLEEP } else { TS_INTERRUPTIBLE_SLEEP };
    }
    TS_RUNNABLE
}

/// The sched timeline consumer: pairs xnu's MACH_SCHED/STACK_HANDOFF (switch
/// endpoints + TIDs) with the following MACH_DISPATCH (outgoing finalized state)
/// per-CPU, emitting two GenericKernelTaskStateEvents per switch plus a process
/// tree delta for newly-seen pids/tids.
struct SchedConsumer {
    ctl: Arc<ConsumerCtl>,
    slot: u32,
    tb_n: u64,
    tb_d: u64,
    pending: Vec<PendingSwitch>,
    cache: PtCache,
    /// Reused across every emitted packet — cleared, not reallocated.
    scratch: ProtoWriter,
}

impl SchedConsumer {
    fn new(ctl: Arc<ConsumerCtl>, tb_n: u64, tb_d: u64) -> Self {
        let slot = ctl.ds_slot.load(Ordering::Acquire);
        SchedConsumer {
            ctl,
            slot,
            tb_n,
            tb_d,
            pending: vec![PendingSwitch::default(); MAX_CPUS],
            cache: PtCache::default(),
            scratch: ProtoWriter::with_capacity(128),
        }
    }

    /// Populate the name cache from the threadmap and emit a
    /// GenericKernelProcessTree delta for newly-seen pids/tids.
    fn refresh_and_emit_tree(&mut self, thread_map: &[KdThreadMap]) {
        // Owned staging — each name/cmdline is its own Vec, so the ProcessC/
        // ThreadC pointers stay valid through the encode (no aliasing).
        let mut new_threads: Vec<(u64, i32, Vec<u8>)> = Vec::new();
        let mut new_processes: Vec<(i32, i32, Vec<u8>)> = Vec::new();

        for t in thread_map {
            if t.thread == 0 || t.pid <= 0 {
                continue;
            }
            let tid = t.thread;
            let pid = t.pid;

            let known = self.cache.threads.get(&tid).map(|(p, _)| *p == pid).unwrap_or(false);
            if !known {
                let name = thread_name(pid, tid).unwrap_or_else(|| t.command_bytes().to_vec());
                self.cache.threads.insert(tid, (pid, name.clone()));
                if new_threads.len() < MAX_NEW_THREADS {
                    new_threads.push((tid, pid, name));
                }

                if !self.cache.processes.contains_key(&pid) {
                    let ppid = parent_pid(pid).unwrap_or(0) as i32;
                    let path = pid_path(pid).unwrap_or_default();
                    self.cache.processes.insert(pid, (ppid, path.clone()));
                    if new_processes.len() < MAX_NEW_PROCESSES {
                        new_processes.push((pid, ppid, path));
                    }
                }
            }
        }

        if new_threads.is_empty() && new_processes.is_empty() {
            return;
        }

        let procs_c: Vec<ProcessC> = new_processes
            .iter()
            .map(|(pid, ppid, cmd)| ProcessC { pid: *pid as i64, ppid: *ppid as i64, cmdline: cmd.as_ptr(), cmdline_len: cmd.len() })
            .collect();
        let threads_c: Vec<ThreadC> = new_threads
            .iter()
            .map(|(tid, pid, comm)| ThreadC {
                tid: *tid as i64,
                pid: *pid as i64,
                comm: comm.as_ptr(),
                comm_len: comm.len(),
                is_main_thread: false,
                is_idle: false,
            })
            .collect();

        let tree = encode_kernel_process_tree(&procs_c, &threads_c);
        let mut w = ProtoWriter::new();
        w.write_message(TP_FIELD_GENERIC_KERNEL_PROCESS_TREE, &tree);
        unsafe { sismo_ds_emit(self.slot, w.bytes().as_ptr(), w.bytes().len()) };
    }

    fn emit_batch(&mut self, events: &[KdEvent]) -> u64 {
        // Disjoint field borrows so the comm slice (from `cache`) and the scratch
        // writer can be held at once with no copy.
        let SchedConsumer { slot, tb_n, tb_d, pending, cache, scratch, .. } = self;
        let (slot, tb_n, tb_d) = (*slot, *tb_n, *tb_d);
        let mut emitted: u64 = 0;
        for e in events {
            // The ring also carries DBG_PERF (kperf) events for the on/off-CPU
            // consumers; skip anything that isn't DBG_MACH_SCHED, or a kperf event
            // whose 14-bit code collides with a sched code (e.g. PERF_TM_FIRE = 0
            // == MACH_SCHED) would be misread as a context switch.
            if ((e.debugid >> 16) & 0xffff) as u16 != SCHED_CSC {
                continue;
            }
            let code = e.code();
            let cpu = e.cpuid as usize;
            if cpu >= MAX_CPUS {
                continue;
            }
            match code {
                0x00 | 0x02 => {
                    // MACH_SCHED / MACH_STACK_HANDOFF: buffer the first half.
                    let outgoing_tid = e.arg5;
                    let incoming_tid = e.arg2;
                    if outgoing_tid == incoming_tid {
                        continue; // idle-loop self-switch
                    }
                    pending[cpu] = PendingSwitch {
                        valid: true,
                        timestamp: e.timestamp,
                        outgoing_tid,
                        outgoing_pri: e.arg3 as u32,
                        incoming_tid,
                        incoming_pri: e.arg4 as u32,
                    };
                }
                0x20 => {
                    // MACH_DISPATCH: complete the pair with the outgoing state.
                    let d_outgoing_tid = e.arg1;
                    let d_outgoing_state = e.arg3 as u32;
                    let slot_ps = pending[cpu];
                    if !slot_ps.valid {
                        continue;
                    }
                    if slot_ps.outgoing_tid != d_outgoing_tid {
                        pending[cpu].valid = false;
                        continue;
                    }
                    let ts_ns = slot_ps.timestamp.wrapping_mul(tb_n) / tb_d;
                    let off_state = outgoing_task_state(d_outgoing_state);
                    let off_comm = lookup_comm(cache, slot_ps.outgoing_tid);
                    emit_task_state(slot, scratch, ts_ns, cpu as i32, off_comm, slot_ps.outgoing_tid as i64, off_state, slot_ps.outgoing_pri as i32);
                    let on_comm = lookup_comm(cache, slot_ps.incoming_tid);
                    emit_task_state(slot, scratch, ts_ns, cpu as i32, on_comm, slot_ps.incoming_tid as i64, TS_RUNNING, slot_ps.incoming_pri as i32);
                    pending[cpu].valid = false;
                    emitted += 2;
                }
                _ => {}
            }
        }
        emitted
    }
}

impl RingConsumer for SchedConsumer {
    fn csc_ranges(&self) -> &[(u16, u16)] {
        &SCHED_RANGES
    }

    fn on_drain(&mut self, events: &[KdEvent], thread_map: &[KdThreadMap]) {
        self.refresh_and_emit_tree(thread_map);
        let emitted = self.emit_batch(events);
        self.ctl.samples.fetch_add(emitted, Ordering::Relaxed);
    }
}

/// Resolve tid → comm from the first-seen cache (populated by
/// refresh_and_emit_tree), else "?".
fn lookup_comm<'a>(cache: &'a PtCache, tid: u64) -> &'a [u8] {
    if let Some((_, name)) = cache.threads.get(&tid) {
        if !name.is_empty() {
            return name;
        }
    }
    b"?"
}

fn emit_task_state(slot: u32, w: &mut ProtoWriter, ts_ns: u64, cpu: i32, comm: &[u8], tid: i64, state: u32, prio: i32) {
    w.clear();
    if ts_ns != 0 {
        w.write_uint64(8, ts_ns);
    }
    w.write_kernel_task_state_event(TP_FIELD_GENERIC_KERNEL_TASK_STATE, cpu, comm, tid, state, prio);
    unsafe { sismo_ds_emit(slot, w.bytes().as_ptr(), w.bytes().len()) };
}

// ---- Ring host -------------------------------------------------------------

/// Which consumers to host. off-CPU + on-CPU each need a target pid (carried in
/// the sched / cpu data-source configs).
#[derive(Clone, Copy)]
pub struct RingConfig {
    pub sched: bool,
    pub offcpu: bool,
    pub oncpu: bool,
}

/// Stats reported by [`RingHost::shutdown`].
pub struct RingStats {
    pub sched_events: u64,
    pub drain_calls: u64,
    pub offcpu_samples: u64,
    pub oncpu_samples: u64,
}

pub struct RingHost {
    config_kernel_buffer_events: i32,

    wakeup: Event,
    exit_requested: AtomicBool,
    setups_needed: AtomicU32,
    setups_received: AtomicU32,

    // Merged config from the data-source setups.
    setup_kernel_buffer_events: AtomicI32,
    setup_target_pid: AtomicU32,
    setup_offcpu_threshold_us: AtomicU32,
    setup_cpu_interval_us: AtomicU32,

    // Per-consumer control blocks (Some once its DS registered). Shared (Arc)
    // between the SDK trampolines here and the worker-thread consumers.
    sched_ctl: Option<Arc<ConsumerCtl>>,
    offcpu_ctl: Option<Arc<ConsumerCtl>>,
    oncpu_ctl: Option<Arc<ConsumerCtl>>,

    drain_calls: AtomicU64,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

fn as_ref<'a>(p: *mut c_void) -> &'a RingHost {
    unsafe { &*(p as *const RingHost) }
}

// ---- SDK trampolines (one set per data source) -----------------------------

extern "C" fn sched_on_setup(user_arg: *mut c_void, dsc: *const c_void, sz: usize) {
    let self_ = as_ref(user_arg);
    if !dsc.is_null() {
        let dsc = unsafe { std::slice::from_raw_parts(dsc as *const u8, sz) };
        if let Some((kbe, pid, threshold_us)) = config_extract(dsc).map(sched_decode) {
            self_.setup_kernel_buffer_events.store(kbe, Ordering::Release);
            if pid != 0 {
                self_.setup_target_pid.store(pid, Ordering::Release);
            }
            self_.setup_offcpu_threshold_us.store(threshold_us, Ordering::Release);
        }
    }
    self_.on_setup_done();
}

extern "C" fn cpu_on_setup(user_arg: *mut c_void, dsc: *const c_void, sz: usize) {
    let self_ = as_ref(user_arg);
    if !dsc.is_null() {
        let dsc = unsafe { std::slice::from_raw_parts(dsc as *const u8, sz) };
        if let Some((pid, interval_us)) = config_extract(dsc).map(cpu_decode) {
            if pid != 0 {
                self_.setup_target_pid.store(pid, Ordering::Release);
            }
            self_.setup_cpu_interval_us.store(interval_us, Ordering::Release);
        }
    }
    self_.on_setup_done();
}

extern "C" fn offcpu_on_setup(user_arg: *mut c_void, _dsc: *const c_void, _sz: usize) {
    // Off-CPU carries no config of its own (pid/threshold ride the sched config).
    as_ref(user_arg).on_setup_done();
}

extern "C" fn sched_on_start(user_arg: *mut c_void) {
    start_ctl(as_ref(user_arg).sched_ctl.as_ref());
    as_ref(user_arg).wakeup.set();
}
extern "C" fn offcpu_on_start(user_arg: *mut c_void) {
    start_ctl(as_ref(user_arg).offcpu_ctl.as_ref());
    as_ref(user_arg).wakeup.set();
}
extern "C" fn cpu_on_start(user_arg: *mut c_void) {
    start_ctl(as_ref(user_arg).oncpu_ctl.as_ref());
    as_ref(user_arg).wakeup.set();
}

extern "C" fn sched_on_stop(user_arg: *mut c_void, stopper: *mut c_void) {
    stop_ctl(as_ref(user_arg).sched_ctl.as_ref(), stopper);
    as_ref(user_arg).wakeup.set();
}
extern "C" fn offcpu_on_stop(user_arg: *mut c_void, stopper: *mut c_void) {
    stop_ctl(as_ref(user_arg).offcpu_ctl.as_ref(), stopper);
    as_ref(user_arg).wakeup.set();
}
extern "C" fn cpu_on_stop(user_arg: *mut c_void, stopper: *mut c_void) {
    stop_ctl(as_ref(user_arg).oncpu_ctl.as_ref(), stopper);
    as_ref(user_arg).wakeup.set();
}

// The ring drains continuously in the loop; nothing per-DS is buffered, so flush
// acks inline on the SDK thread.
extern "C" fn on_flush(_user_arg: *mut c_void, flusher: *mut c_void) {
    if !flusher.is_null() {
        unsafe { sismo_flush_done(flusher) };
    }
}

fn start_ctl(ctl: Option<&Arc<ConsumerCtl>>) {
    if let Some(c) = ctl {
        c.running.store(true, Ordering::Release);
    }
}

fn stop_ctl(ctl: Option<&Arc<ConsumerCtl>>, stopper: *mut c_void) {
    // Defer the ack to the worker: it does a final drain (flushing any last
    // buffered sched pairs) before stop_done, then clears running.
    if let Some(c) = ctl {
        if !stopper.is_null() {
            c.pending_stopper.store(stopper as usize, Ordering::Release);
        }
    }
}

impl RingHost {
    fn on_setup_done(&self) {
        self.setups_received.fetch_add(1, Ordering::Release);
        self.wakeup.set();
    }

    /// Block until every registered DS has been set up (or exit is requested).
    /// Returns true if setups arrived, false if exit was requested first.
    fn wait_for_setups(&self) -> bool {
        let needed = self.setups_needed.load(Ordering::Acquire);
        while !self.exit_requested.load(Ordering::Acquire) && self.setups_received.load(Ordering::Acquire) < needed {
            self.wakeup.reset();
            if self.exit_requested.load(Ordering::Acquire) || self.setups_received.load(Ordering::Acquire) >= needed {
                break;
            }
            self.wakeup.wait();
        }
        !self.exit_requested.load(Ordering::Acquire)
    }

    fn any_running(&self) -> bool {
        [&self.sched_ctl, &self.offcpu_ctl, &self.oncpu_ctl]
            .into_iter()
            .flatten()
            .any(|c| c.running.load(Ordering::Acquire))
    }

    fn run(&self) {
        if !self.wait_for_setups() {
            return;
        }

        let kbe = self.setup_kernel_buffer_events.load(Ordering::Acquire);
        let kernel_buffer_events = if kbe != 0 { kbe } else { self.config_kernel_buffer_events };
        let target_pid = self.setup_target_pid.load(Ordering::Acquire);
        let threshold_us = self.setup_offcpu_threshold_us.load(Ordering::Acquire);
        let threshold_ns = (if threshold_us != 0 { threshold_us } else { DEFAULT_OFFCPU_THRESHOLD_US }) as u64 * 1_000;
        let interval_us = self.setup_cpu_interval_us.load(Ordering::Acquire);
        let period_ns = (if interval_us != 0 { interval_us } else { DEFAULT_CPU_INTERVAL_US }) as u64 * 1_000;

        let mut tb = TimebaseInfo { numer: 1, denom: 1 };
        unsafe { mach_timebase_info(&mut tb) };
        let (tb_n, tb_d) = (tb.numer as u64, tb.denom as u64);

        // A perf consumer is only viable with a target pid to filter on.
        let want_offcpu = self.offcpu_ctl.is_some() && target_pid != 0;
        let want_oncpu = self.oncpu_ctl.is_some() && target_pid != 0;

        // Open the ring with the union of its consumers' csc filters.
        let mut csc_ranges: Vec<(u16, u16)> = Vec::new();
        if self.sched_ctl.is_some() {
            csc_ranges.extend_from_slice(&SCHED_RANGES);
        }
        if want_offcpu || want_oncpu {
            csc_ranges.push(DBG_PERF_CSC_RANGE);
        }
        let ring = match KdebugRing::open(kernel_buffer_events, &csc_ranges) {
            Ok(r) => r,
            Err(_) => {
                eprintln!("ring_host: kdebug ring open failed");
                return;
            }
        };

        // task_for_pid the target (shared by both perf consumers for module
        // enumeration), then arm kperf for whichever samplers are enabled.
        let mut offcpu: Option<OffCpuConsumer> = None;
        let mut oncpu: Option<OnCpuConsumer> = None;
        if want_offcpu || want_oncpu {
            let mut task: MachPort = 0;
            if unsafe { libc::task_for_pid(mach_task_self_, target_pid as i32, &mut task) } != KERN_SUCCESS {
                eprintln!(
                    "ring_host: kperf sampling disabled — task_for_pid({target_pid}) failed (need sudo or the debugger entitlement)"
                );
            } else {
                let kcfg = KperfConfig {
                    pid: target_pid as i32,
                    offcpu_threshold_ns: want_offcpu.then_some(threshold_ns),
                    oncpu_period_ns: want_oncpu.then_some(period_ns),
                };
                if let Err(e) = arm(&kcfg) {
                    eprintln!("ring_host: kperf sampling disabled — arm failed: {e}");
                } else {
                    if want_offcpu {
                        eprintln!("ring_host: off-CPU armed for pid {target_pid} (wait threshold {}us)", threshold_ns / 1_000);
                        offcpu = Some(OffCpuConsumer::new(self.offcpu_ctl.clone().unwrap(), task));
                    }
                    if want_oncpu {
                        eprintln!("ring_host: on-CPU armed for pid {target_pid} (timer {}us)", period_ns / 1_000);
                        oncpu = Some(OnCpuConsumer::new(self.oncpu_ctl.clone().unwrap(), task, period_ns));
                    }
                }
            }
        }

        let mut sched = self.sched_ctl.clone().map(|ctl| SchedConsumer::new(ctl, tb_n, tb_d));

        let mut event_buf = vec![KdEvent::ZERO; DRAIN_CAPACITY_EVENTS];
        let mut thread_map_buf = vec![KdThreadMap::ZERO; THREAD_MAP_CAPACITY];

        loop {
            self.wakeup.reset();
            if self.exit_requested.load(Ordering::Acquire) {
                break;
            }

            if self.any_running() {
                self.drain_once(&ring, &mut event_buf, &mut thread_map_buf, sched.as_mut(), offcpu.as_mut(), oncpu.as_mut());
            }

            // Collect any stop acks, do a final drain to flush, then ack + clear.
            let mut stoppers: Vec<(usize, Arc<ConsumerCtl>)> = Vec::new();
            for ctl in [&self.sched_ctl, &self.offcpu_ctl, &self.oncpu_ctl].into_iter().flatten() {
                let s = ctl.pending_stopper.swap(0, Ordering::AcqRel);
                if s != 0 {
                    stoppers.push((s, ctl.clone()));
                }
            }
            if !stoppers.is_empty() {
                self.drain_once(&ring, &mut event_buf, &mut thread_map_buf, sched.as_mut(), offcpu.as_mut(), oncpu.as_mut());
                for (s, ctl) in stoppers {
                    unsafe { sismo_stop_done(s as *mut c_void) };
                    ctl.running.store(false, Ordering::Release);
                }
            }

            if self.exit_requested.load(Ordering::Acquire) {
                break;
            }

            if self.any_running() {
                self.wakeup.wait_timeout(Duration::from_nanos(DRAIN_INTERVAL_NS));
            } else {
                self.wakeup.wait();
            }
        }
        // `ring` drops here (KDREMOVE); kperf is disarmed in shutdown().
    }

    #[allow(clippy::too_many_arguments)]
    fn drain_once(
        &self,
        ring: &KdebugRing,
        event_buf: &mut [KdEvent],
        thread_map_buf: &mut [KdThreadMap],
        sched: Option<&mut SchedConsumer>,
        offcpu: Option<&mut OffCpuConsumer>,
        oncpu: Option<&mut OnCpuConsumer>,
    ) {
        let t0 = now_ns();
        // KdEvent / KdThreadMap are repr(C) POD; kdebug reads raw bytes into them.
        let evt_bytes =
            unsafe { std::slice::from_raw_parts_mut(event_buf.as_mut_ptr() as *mut u8, std::mem::size_of_val(event_buf)) };
        let n_evt = ring.drain(evt_bytes).unwrap_or(0);
        let t_drain = now_ns();

        let thr_bytes = unsafe {
            std::slice::from_raw_parts_mut(thread_map_buf.as_mut_ptr() as *mut u8, std::mem::size_of_val(thread_map_buf))
        };
        let n_thr = ring.read_thread_map(thr_bytes).unwrap_or(0);
        let thread_map = &thread_map_buf[..n_thr.min(thread_map_buf.len())];
        let events = &event_buf[..n_evt.min(event_buf.len())];

        // Fan the batch out to each running consumer. Each filters the events it
        // cares about (sched: MACH_SCHED; perf: DBG_PERF), so the shared stream
        // needs no pre-split.
        if let Some(c) = sched {
            if self.sched_ctl.as_ref().map(|x| x.running.load(Ordering::Acquire)).unwrap_or(false) {
                c.on_drain(events, thread_map);
            }
        }
        if let Some(c) = offcpu {
            if self.offcpu_ctl.as_ref().map(|x| x.running.load(Ordering::Acquire)).unwrap_or(false) {
                c.on_drain(events, thread_map);
            }
        }
        if let Some(c) = oncpu {
            if self.oncpu_ctl.as_ref().map(|x| x.running.load(Ordering::Acquire)).unwrap_or(false) {
                c.on_drain(events, thread_map);
            }
        }
        let t_end = now_ns();

        let drain_idx = self.drain_calls.fetch_add(1, Ordering::Relaxed);
        let overflow_threshold = DRAIN_CAPACITY_EVENTS * 9 / 10;
        if drain_idx == 0 || n_evt >= overflow_threshold {
            let tag = if n_evt >= overflow_threshold { "[ring near-full]" } else { "" };
            eprintln!(
                "ring_host: drain[{drain_idx}] evt={n_evt} thr={n_thr}  drain={}us process={}us {tag}",
                (t_drain - t0) / 1000,
                (t_end - t_drain) / 1000,
            );
        }
    }

    /// Register the data sources requested by `cfg` and spawn the worker thread.
    /// `None` if no data source registered.
    pub fn start(cfg: RingConfig) -> Option<Box<RingHost>> {
        let mut host = Box::new(RingHost {
            config_kernel_buffer_events: DEFAULT_KERNEL_BUFFER_EVENTS,
            wakeup: Event::new(),
            exit_requested: AtomicBool::new(false),
            setups_needed: AtomicU32::new(0),
            setups_received: AtomicU32::new(0),
            setup_kernel_buffer_events: AtomicI32::new(0),
            setup_target_pid: AtomicU32::new(0),
            setup_offcpu_threshold_us: AtomicU32::new(0),
            setup_cpu_interval_us: AtomicU32::new(0),
            sched_ctl: None,
            offcpu_ctl: None,
            oncpu_ctl: None,
            drain_calls: AtomicU64::new(0),
            thread: Mutex::new(None),
        });

        // The worker + trampolines share `&RingHost` via the box's stable heap
        // address, which outlives them: shutdown joins before the box drops.
        let addr = &*host as *const RingHost as usize;
        let arg = addr as *mut c_void;

        if cfg.sched {
            let ctl = Arc::new(ConsumerCtl::new());
            let prog = macos_sched_vm_program();
            let desc = encode_data_source_descriptor(SCHED_DS_NAME, true, false, &prog);
            let slot = unsafe { sismo_ds_register(desc.as_ptr(), desc.len(), sched_on_setup, sched_on_start, sched_on_stop, on_flush, arg) };
            if slot != u32::MAX {
                ctl.ds_slot.store(slot, Ordering::Release);
                host.sched_ctl = Some(ctl);
                host.setups_needed.fetch_add(1, Ordering::Release);
            } else {
                eprintln!("ring_host: sched data source registration failed");
            }
        }
        if cfg.offcpu {
            let ctl = Arc::new(ConsumerCtl::new());
            let desc = encode_data_source_descriptor(OFFCPU_DS_NAME, true, false, &[]);
            let slot = unsafe { sismo_ds_register(desc.as_ptr(), desc.len(), offcpu_on_setup, offcpu_on_start, offcpu_on_stop, on_flush, arg) };
            if slot != u32::MAX {
                ctl.ds_slot.store(slot, Ordering::Release);
                host.offcpu_ctl = Some(ctl);
                host.setups_needed.fetch_add(1, Ordering::Release);
            } else {
                eprintln!("ring_host: off-CPU data source registration failed");
            }
        }
        if cfg.oncpu {
            let ctl = Arc::new(ConsumerCtl::new());
            let desc = encode_data_source_descriptor(ONCPU_DS_NAME, true, false, &[]);
            let slot = unsafe { sismo_ds_register(desc.as_ptr(), desc.len(), cpu_on_setup, cpu_on_start, cpu_on_stop, on_flush, arg) };
            if slot != u32::MAX {
                ctl.ds_slot.store(slot, Ordering::Release);
                host.oncpu_ctl = Some(ctl);
                host.setups_needed.fetch_add(1, Ordering::Release);
            } else {
                eprintln!("ring_host: on-CPU data source registration failed");
            }
        }

        if host.setups_needed.load(Ordering::Acquire) == 0 {
            return None;
        }

        let handle = std::thread::spawn(move || {
            let self_ = unsafe { &*(addr as *const RingHost) };
            self_.run();
        });
        *host.thread.lock().unwrap() = Some(handle);
        Some(host)
    }

    /// Signal exit, join the worker (its ring drops, tearing the kdebug session
    /// down), disarm kperf, and return the accumulated stats.
    pub fn shutdown(self: Box<Self>) -> RingStats {
        self.exit_requested.store(true, Ordering::Release);
        self.wakeup.set();
        let handle = self.thread.lock().unwrap().take();
        if let Some(h) = handle {
            let _ = h.join();
        }
        disarm();
        let samples = |ctl: &Option<Arc<ConsumerCtl>>| ctl.as_ref().map(|c| c.samples.load(Ordering::Relaxed)).unwrap_or(0);
        RingStats {
            sched_events: samples(&self.sched_ctl),
            drain_calls: self.drain_calls.load(Ordering::Relaxed),
            offcpu_samples: samples(&self.offcpu_ctl),
            oncpu_samples: samples(&self.oncpu_ctl),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outgoing_state_mapping() {
        assert_eq!(outgoing_task_state(0), TS_RUNNABLE);
        assert_eq!(outgoing_task_state(0x01), TS_INTERRUPTIBLE_SLEEP);
        assert_eq!(outgoing_task_state(0x09), TS_UNINTERRUPTIBLE_SLEEP); // TH_WAIT|TH_UNINT
        assert_eq!(outgoing_task_state(0x02), TS_STOPPED);
    }

    #[test]
    fn event_code_matches_masks() {
        // code field = bits [2..16). debugid 0x01400080 -> (0x80 & 0xfffc)>>2 = 0x20.
        assert_eq!(KdEvent { debugid: 0x0140_0080, ..KdEvent::ZERO }.code(), 0x20);
        assert_eq!(KdEvent { debugid: 0x0140_0008, ..KdEvent::ZERO }.code(), 0x02);
    }

    #[test]
    fn struct_sizes() {
        assert_eq!(std::mem::size_of::<KdEvent>(), 64);
        assert_eq!(std::mem::size_of::<KdThreadMap>(), 32);
    }

    #[test]
    fn perf_events_excluded_from_sched_by_csc() {
        // PERF_TM_FIRE (on-CPU trigger): class=DBG_PERF(0x25), subclass=PERF_TIMER
        // (3), code=0 — its 14-bit code collides with MACH_SCHED (0), so the
        // class+subclass (csc) guard, not the code, is what keeps it out of the
        // sched pairing.
        let tm_fire = KdEvent { debugid: (0x25 << 24) | (3 << 16), ..KdEvent::ZERO };
        assert_eq!(tm_fire.code(), 0x00, "collides with MACH_SCHED code");
        assert_ne!(((tm_fire.debugid >> 16) & 0xffff) as u16, SCHED_CSC);
        // A real MACH_SCHED event: class=DBG_MACH(1), subclass=DBG_MACH_SCHED(0x40).
        let sched = KdEvent { debugid: (1 << 24) | (0x40 << 16), ..KdEvent::ZERO };
        assert_eq!(((sched.debugid >> 16) & 0xffff) as u16, SCHED_CSC);
    }
}
