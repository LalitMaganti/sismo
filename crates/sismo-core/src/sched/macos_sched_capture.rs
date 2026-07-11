// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! macOS kdebug → `sismo.macos_sched` capture worker. Owns the worker thread
//! and the C++ SDK data-source lifecycle; the kdebug ring, proc-info lookups,
//! and all proto encoding live in the Rust paths it calls.
//!
//! Per switch, xnu emits two kdebug events on the same CPU: MACH_SCHED /
//! MACH_STACK_HANDOFF (timestamps + both TIDs + priorities) then MACH_DISPATCH
//! (outgoing thread's finalized state). We pair them per-CPU and emit two
//! GenericKernelTaskStateEvents (outgoing → its off-CPU state, incoming →
//! RUNNING). A GenericKernelProcessTree delta carries process/thread names.
//!
//! macOS only; gated in lib.rs.

use crate::sched::proc_info::{parent_pid, pid_path, thread_name};
use crate::proto::ProtoWriter;
use crate::proto::sched_protos::{
    encode_kernel_process_tree, macos_sched_vm_program, ProcessC, ThreadC,
};
use crate::proto::session_config::encode_data_source_descriptor;
use crate::proto::sismo_config::{config_extract, sched_decode};
use crate::ffi::{sismo_ds_emit, sismo_ds_register, sismo_flush_done, sismo_stop_done};
use crate::worker_sdk::Event;
use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

const DS_NAME: &[u8] = b"sismo.macos_sched";
const MAX_CPUS: usize = 256;

// Field tags.
const TP_FIELD_GENERIC_KERNEL_TASK_STATE: u32 = 117;
const TP_FIELD_GENERIC_KERNEL_PROCESS_TREE: u32 = 122;

// TaskStateEnum values (protos/.../generic_task.proto).
const TS_RUNNABLE: u32 = 2;
const TS_RUNNING: u32 = 3;
const TS_INTERRUPTIBLE_SLEEP: u32 = 4;
const TS_UNINTERRUPTIBLE_SLEEP: u32 = 5;
const TS_STOPPED: u32 = 6;

// Config defaults.
const DEFAULT_KERNEL_BUFFER_EVENTS: i32 = 256 * 1024;
const DRAIN_INTERVAL_NS: u64 = 100 * 1_000_000;
const DRAIN_CAPACITY_EVENTS: usize = 256 * 1024;
const THREAD_MAP_CAPACITY: usize = 16 * 1024;

// Staging caps per drain.
const MAX_NEW_THREADS: usize = 256;
const MAX_NEW_PROCESSES: usize = 128;

// ---- kdebug ring + timebase ------------------------------------------------

use crate::sched::kdebug::{kdebug_drain, kdebug_read_thread_map, kdebug_start, kdebug_teardown};

// libc's mach_timebase_info struct is deprecated (points at the mach2 crate),
// so keep this one hand-rolled; clock_gettime comes from libc.
extern "C" {
    fn mach_timebase_info(info: *mut MachTimebaseInfo) -> i32;
}

#[repr(C)]
struct MachTimebaseInfo {
    numer: u32,
    denom: u32,
}

fn now_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

// kd_buf event record — 64 bytes on arm64. Fields read directly.
#[repr(C)]
#[derive(Clone, Copy)]
struct KdBuf {
    timestamp: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    debugid: u32,
    cpuid: u32,
    unused: u64,
}

// kd_threadmap entry — 32 bytes. `pid` is the owning process.
#[repr(C)]
#[derive(Clone, Copy)]
struct KdThreadMap {
    thread: u64,
    pid: i32,
    command: [u8; 20],
}

/// Event code from a kd_buf debugid: (debugid & KDBG_CODE_MASK) >> KDBG_CODE_OFFSET.
fn extract_code(debugid: u32) -> u32 {
    (debugid & 0x0000_fffc) >> 2
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

fn threadmap_command(t: &KdThreadMap) -> &[u8] {
    let n = t.command.iter().position(|&b| b == 0).unwrap_or(t.command.len());
    &t.command[..n]
}

// ---- Worker ----------------------------------------------------------------

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
    threads: HashMap<u64, (i32, Vec<u8>)>, // tid -> (pid, comm)
    processes: HashMap<i32, (i32, Vec<u8>)>, // pid -> (ppid, cmdline)
}

pub struct SchedCapture {
    ds_slot: AtomicU32,
    config_kernel_buffer_events: i32,

    wakeup: Event,
    running: AtomicBool,
    exit_requested: AtomicBool,
    pending_stopper: AtomicUsize,

    setup_received: AtomicBool,
    setup_kernel_buffer_events: AtomicI32,

    events_emitted: AtomicU64,
    drain_calls: AtomicU64,

    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

fn as_ref<'a>(p: *mut c_void) -> &'a SchedCapture {
    unsafe { &*(p as *const SchedCapture) }
}

extern "C" fn on_setup(user_arg: *mut c_void, dsc_bytes: *const c_void, dsc_size: usize) {
    let self_ = as_ref(user_arg);
    if !dsc_bytes.is_null() {
        let dsc = unsafe { std::slice::from_raw_parts(dsc_bytes as *const u8, dsc_size) };
        if let Some(kbe) = config_extract(dsc).and_then(sched_decode) {
            self_.setup_kernel_buffer_events.store(kbe, Ordering::Release);
        }
    }
    self_.setup_received.store(true, Ordering::Release);
    self_.wakeup.set();
}

extern "C" fn on_start(user_arg: *mut c_void) {
    let self_ = as_ref(user_arg);
    self_.running.store(true, Ordering::Release);
    self_.wakeup.set();
}

extern "C" fn on_stop(user_arg: *mut c_void, stopper: *mut c_void) {
    let self_ = as_ref(user_arg);
    if !stopper.is_null() {
        self_.pending_stopper.store(stopper as usize, Ordering::Release);
    }
    self_.wakeup.set();
}

extern "C" fn on_flush(_user_arg: *mut c_void, flusher: *mut c_void) {
    // kdebug emits continuously in the drain loop; nothing buffered — ack inline.
    if !flusher.is_null() {
        unsafe { sismo_flush_done(flusher) };
    }
}

impl SchedCapture {
    fn run(&self) {
        // Wait for on_setup (carries the kdebug buffer sizing).
        while !self.exit_requested.load(Ordering::Acquire)
            && !self.setup_received.load(Ordering::Acquire)
        {
            self.wakeup.reset();
            if self.exit_requested.load(Ordering::Acquire)
                || self.setup_received.load(Ordering::Acquire)
            {
                break;
            }
            self.wakeup.wait();
        }
        if self.exit_requested.load(Ordering::Acquire) {
            return;
        }

        let kbe = self.setup_kernel_buffer_events.load(Ordering::Acquire);
        let kernel_buffer_events = if kbe != 0 { kbe } else { self.config_kernel_buffer_events };

        // Heavy setup on the worker thread.
        let mut tb = MachTimebaseInfo { numer: 1, denom: 1 };
        unsafe { mach_timebase_info(&mut tb) };
        let (tb_n, tb_d) = (tb.numer as u64, tb.denom as u64);

        let mut setup_failed = false;
        if kdebug_start(kernel_buffer_events).is_err() {
            eprintln!("macos_sched_capture: kdebug.start failed");
            setup_failed = true;
        }

        let slot = self.ds_slot.load(Ordering::Acquire);
        let mut event_buf = vec![
            KdBuf {
                timestamp: 0,
                arg1: 0,
                arg2: 0,
                arg3: 0,
                arg4: 0,
                arg5: 0,
                debugid: 0,
                cpuid: 0,
                unused: 0,
            };
            DRAIN_CAPACITY_EVENTS
        ];
        let mut thread_map_buf = vec![KdThreadMap { thread: 0, pid: 0, command: [0; 20] }; THREAD_MAP_CAPACITY];
        let mut pending = vec![PendingSwitch::default(); MAX_CPUS];
        let mut cache = PtCache::default();

        loop {
            self.wakeup.reset();
            if self.exit_requested.load(Ordering::Acquire) {
                break;
            }

            if self.running.load(Ordering::Acquire) && !setup_failed {
                self.drain_once(slot, tb_n, tb_d, &mut event_buf, &mut thread_map_buf, &mut pending, &mut cache);
            }

            let stopper = self.pending_stopper.swap(0, Ordering::AcqRel);
            if stopper != 0 {
                if !setup_failed {
                    self.drain_once(slot, tb_n, tb_d, &mut event_buf, &mut thread_map_buf, &mut pending, &mut cache);
                }
                unsafe { sismo_stop_done(stopper as *mut c_void) };
                self.running.store(false, Ordering::Release);
            }

            if self.exit_requested.load(Ordering::Acquire) {
                break;
            }

            if self.running.load(Ordering::Acquire) {
                self.wakeup.wait_timeout(Duration::from_nanos(DRAIN_INTERVAL_NS));
            } else {
                self.wakeup.wait();
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn drain_once(
        &self,
        slot: u32,
        tb_n: u64,
        tb_d: u64,
        event_buf: &mut [KdBuf],
        thread_map_buf: &mut [KdThreadMap],
        pending: &mut [PendingSwitch],
        cache: &mut PtCache,
    ) {
        let t0 = now_ns();
        // KdBuf / KdThreadMap are repr(C) POD; kdebug reads raw bytes into them.
        let evt_bytes = unsafe {
            std::slice::from_raw_parts_mut(event_buf.as_mut_ptr() as *mut u8, std::mem::size_of_val(event_buf))
        };
        let n_evt = kdebug_drain(evt_bytes).unwrap_or(0);
        let t_drain = now_ns();

        let thr_bytes = unsafe {
            std::slice::from_raw_parts_mut(
                thread_map_buf.as_mut_ptr() as *mut u8,
                std::mem::size_of_val(thread_map_buf),
            )
        };
        let n_thr = kdebug_read_thread_map(thr_bytes).unwrap_or(0);
        let thread_map = &thread_map_buf[..n_thr.min(thread_map_buf.len())];

        self.refresh_and_emit_tree(slot, thread_map, cache);
        let t_refresh = now_ns();

        let events = &event_buf[..n_evt.min(event_buf.len())];
        let emitted = self.emit_batch(slot, events, thread_map, cache, tb_n, tb_d, pending);
        let t_end = now_ns();

        self.events_emitted.fetch_add(emitted, Ordering::Relaxed);
        let drain_idx = self.drain_calls.fetch_add(1, Ordering::Relaxed);

        let overflow_threshold = DRAIN_CAPACITY_EVENTS * 9 / 10;
        if drain_idx == 0 || n_evt >= overflow_threshold {
            let tag = if n_evt >= overflow_threshold { "[ring near-full]" } else { "" };
            eprintln!(
                "macos_sched: drain[{drain_idx}] evt={n_evt} thr={n_thr} emit={emitted}  drain={}us refresh={}us emit={}us {tag}",
                (t_drain - t0) / 1000,
                (t_refresh - t_drain) / 1000,
                (t_end - t_refresh) / 1000,
            );
        }
    }

    /// Populate the name cache from the threadmap and emit a
    /// GenericKernelProcessTree delta for newly-seen pids/tids.
    fn refresh_and_emit_tree(&self, slot: u32, thread_map: &[KdThreadMap], cache: &mut PtCache) {
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

            let known = cache.threads.get(&tid).map(|(p, _)| *p == pid).unwrap_or(false);
            if !known {
                // Resolve pth_name; fall back to the threadmap comm.
                let name = thread_name(pid, tid).unwrap_or_else(|| threadmap_command(t).to_vec());
                cache.threads.insert(tid, (pid, name.clone()));
                if new_threads.len() < MAX_NEW_THREADS {
                    new_threads.push((tid, pid, name));
                }

                if !cache.processes.contains_key(&pid) {
                    let ppid = parent_pid(pid).unwrap_or(0) as i32;
                    let path = pid_path(pid).unwrap_or_default();
                    cache.processes.insert(pid, (ppid, path.clone()));
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
            .map(|(pid, ppid, cmd)| ProcessC {
                pid: *pid as i64,
                ppid: *ppid as i64,
                cmdline: cmd.as_ptr(),
                cmdline_len: cmd.len(),
            })
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

        // Wrap in a TracePacket body (no timestamp — tree entries are
        // time-independent metadata) and emit.
        let mut w = ProtoWriter::new();
        w.write_message(TP_FIELD_GENERIC_KERNEL_PROCESS_TREE, &tree);
        unsafe { sismo_ds_emit(slot, w.bytes().as_ptr(), w.bytes().len()) };
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_batch(
        &self,
        slot: u32,
        events: &[KdBuf],
        thread_map: &[KdThreadMap],
        cache: &PtCache,
        tb_n: u64,
        tb_d: u64,
        pending: &mut [PendingSwitch],
    ) -> u64 {
        let mut emitted: u64 = 0;
        for e in events {
            let code = extract_code(e.debugid);
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
                    let off_comm = lookup_comm(thread_map, cache, slot_ps.outgoing_tid);
                    emit_task_state(
                        slot,
                        ts_ns,
                        cpu as i32,
                        off_comm,
                        slot_ps.outgoing_tid as i64,
                        off_state,
                        slot_ps.outgoing_pri as i32,
                    );
                    let on_comm = lookup_comm(thread_map, cache, slot_ps.incoming_tid);
                    emit_task_state(
                        slot,
                        ts_ns,
                        cpu as i32,
                        on_comm,
                        slot_ps.incoming_tid as i64,
                        TS_RUNNING,
                        slot_ps.incoming_pri as i32,
                    );
                    pending[cpu].valid = false;
                    emitted += 2;
                }
                _ => {}
            }
        }
        emitted
    }
}

/// Resolve tid → comm: cache hit (from refresh_and_emit_tree), else a linear
/// threadmap scan, else "?".
fn lookup_comm<'a>(threads: &'a [KdThreadMap], cache: &'a PtCache, tid: u64) -> &'a [u8] {
    if let Some((_, name)) = cache.threads.get(&tid) {
        if !name.is_empty() {
            return name;
        }
    }
    for t in threads {
        if t.thread == tid {
            return threadmap_command(t);
        }
    }
    b"?"
}

fn emit_task_state(slot: u32, ts_ns: u64, cpu: i32, comm: &[u8], tid: i64, state: u32, prio: i32) {
    let mut w = ProtoWriter::new();
    if ts_ns != 0 {
        w.write_uint64(8, ts_ns);
    }
    w.write_kernel_task_state_event(
        TP_FIELD_GENERIC_KERNEL_TASK_STATE,
        cpu,
        comm,
        tid,
        state,
        prio,
    );
    unsafe { sismo_ds_emit(slot, w.bytes().as_ptr(), w.bytes().len()) };
}

impl SchedCapture {
    /// Create the sched capture: register the data source (with the ProtoVM
    /// program) and spawn the worker thread. `None` on registration failure.
    pub fn start() -> Option<Box<SchedCapture>> {
        let cap = Box::new(SchedCapture {
            ds_slot: AtomicU32::new(u32::MAX),
            config_kernel_buffer_events: DEFAULT_KERNEL_BUFFER_EVENTS,
            wakeup: Event::new(),
            running: AtomicBool::new(false),
            exit_requested: AtomicBool::new(false),
            pending_stopper: AtomicUsize::new(0),
            setup_received: AtomicBool::new(false),
            setup_kernel_buffer_events: AtomicI32::new(0),
            events_emitted: AtomicU64::new(0),
            drain_calls: AtomicU64::new(0),
            thread: Mutex::new(None),
        });

        // The worker shares `&SchedCapture` via the box's (stable) heap address,
        // which outlives the thread: shutdown joins it before the box drops.
        let cap_addr = &*cap as *const SchedCapture as usize;

        // Descriptor carries the ProtoVM program (mirrors process-tree packets
        // into traced's DST for ring/flight mode).
        let prog = macos_sched_vm_program();
        let desc = encode_data_source_descriptor(DS_NAME, true, false, &prog);
        let slot = unsafe {
            sismo_ds_register(desc.as_ptr(), desc.len(), on_setup, on_start, on_stop, on_flush, cap_addr as *mut c_void)
        };
        if slot == u32::MAX {
            return None;
        }
        cap.ds_slot.store(slot, Ordering::Release);

        let handle = std::thread::spawn(move || {
            let self_ = unsafe { &*(cap_addr as *const SchedCapture) };
            self_.run();
        });
        *cap.thread.lock().unwrap() = Some(handle);
        Some(cap)
    }

    /// Signal exit, join the worker, tear down the kdebug session, and return
    /// the accumulated stats.
    pub fn shutdown(self: Box<Self>) -> SchedStats {
        self.exit_requested.store(true, Ordering::Release);
        self.wakeup.set();
        let handle = self.thread.lock().unwrap().take();
        if let Some(h) = handle {
            let _ = h.join();
        }
        kdebug_teardown();
        SchedStats {
            events_emitted: self.events_emitted.load(Ordering::Relaxed),
            drain_calls: self.drain_calls.load(Ordering::Relaxed),
        }
    }
}

/// Sched stats reported by [`SchedCapture::shutdown`].
pub struct SchedStats {
    pub events_emitted: u64,
    pub drain_calls: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_code_matches_masks() {
        // code field = bits [2..16). e.g. debugid 0x01400080 -> (0x80 & 0xfffc)>>2 = 0x20.
        assert_eq!(extract_code(0x0140_0080), 0x20);
        assert_eq!(extract_code(0x0140_0000), 0x00);
        assert_eq!(extract_code(0x0140_0008), 0x02);
    }

    #[test]
    fn outgoing_state_mapping() {
        assert_eq!(outgoing_task_state(0), TS_RUNNABLE);
        assert_eq!(outgoing_task_state(0x01), TS_INTERRUPTIBLE_SLEEP);
        assert_eq!(outgoing_task_state(0x09), TS_UNINTERRUPTIBLE_SLEEP); // TH_WAIT|TH_UNINT
        assert_eq!(outgoing_task_state(0x02), TS_STOPPED);
    }

    #[test]
    fn struct_sizes() {
        assert_eq!(std::mem::size_of::<KdBuf>(), 64);
        assert_eq!(std::mem::size_of::<KdThreadMap>(), 32);
    }
}
