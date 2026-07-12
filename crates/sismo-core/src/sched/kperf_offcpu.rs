// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! macOS off-CPU capture via kperf's `lazy.wait` sampler, decoded off the shared
//! kdebug ring the sched worker owns. When a thread wakes from a wait longer than
//! a threshold, kperf samples it on-core in the woken thread's context, emitting
//! its blocking user stack + the wait duration (all pid-filtered in the kernel).
//! We pair each `PERF_LZ_WAITSAMPLE` with the thread's pended user callstack and
//! emit an off-CPU Perfetto PerfSample weighted by the off-CPU duration — the
//! macOS side of the shared off-CPU contract (see docs/offcpu-cross-platform.md).
//!
//! macOS-only; gated in sched/mod.rs.

use crate::ffi::sismo_ds_emit;
use crate::mach::{mach_timebase_info, MachPort, TimebaseInfo};
use crate::proto::ProtoWriter;
use crate::symbolize::dyld_images::{read_macho, ImageList};
use std::collections::HashMap;
use std::ffi::c_void;

// ---- kperf event codes (osfmk/kperf/buffer.h) ------------------------------

const DBG_PERF: u32 = 0x25;
const PERF_THREADINFO: u32 = 1;
const PERF_TI_DATA: u32 = 1; // BUF_DATA(PERF_TI_DATA, pid, tid, dq_addr, runmode)
const PERF_CALLSTACK: u32 = 2;
const PERF_CS_UDATA: u32 = 4;
const PERF_CS_UHDR: u32 = 6;
const PERF_LAZY: u32 = 9;
const PERF_LZ_WAITSAMPLE: u32 = 1; // BUF_DATA(wait_time, runnable_time, running_time), mach ticks

// kperf samplers (osfmk/kperf/action.h).
const SAMPLER_TH_INFO: u32 = 1 << 0;
const SAMPLER_USTACK: u32 = 1 << 3;
const ACTION_ID: u64 = 1; // 1-based; 0 = "no action"
const UCALLSTACK_DEPTH: u64 = 128;
const MAX_FRAMES: usize = 256; // guard against a garbage UHDR nframes

// Perfetto sequence/scope/clock constants (mirror linux_bpf_capture.rs).
const SEQ_INCREMENTAL_STATE_CLEARED: u32 = 1;
const SEQ_NEEDS_INCREMENTAL_STATE: u32 = 2;
const BUILTIN_CLOCK_MONOTONIC: u32 = 3;
const SAMPLE_SCOPE_THREAD: u32 = 2;
const TP_FIELD_PERF_SAMPLE: u32 = 66;

// ---- kperf sysctl helpers --------------------------------------------------

fn errno() -> i32 {
    unsafe { *libc::__error() }
}

fn kperf_set_u32(name: &[u8], value: u32) -> Result<(), i32> {
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr() as *const libc::c_char,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &value as *const u32 as *mut c_void,
            std::mem::size_of::<u32>(),
        )
    };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

fn kperf_set_u64(name: &[u8], value: u64) -> Result<(), i32> {
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr() as *const libc::c_char,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &value as *const u64 as *mut c_void,
            std::mem::size_of::<u64>(),
        )
    };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

/// Indexed kperf knob: the kernel reads `[id, value]` as two u64s.
fn kperf_set_indexed(name: &[u8], id: u64, value: u64) -> Result<(), i32> {
    let inputs: [u64; 2] = [id, value];
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr() as *const libc::c_char,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            inputs.as_ptr() as *mut c_void,
            std::mem::size_of::<[u64; 2]>(),
        )
    };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

fn timebase() -> (u64, u64) {
    let mut tb = TimebaseInfo { numer: 1, denom: 1 };
    unsafe { mach_timebase_info(&mut tb) };
    (tb.numer as u64, tb.denom as u64)
}

fn ns_to_ticks(ns: u64) -> u64 {
    let (n, d) = timebase();
    (ns as u128 * d as u128 / n as u128) as u64
}

fn ticks_to_ns(ticks: u64) -> u64 {
    let (n, d) = timebase();
    (ticks as u128 * n as u128 / d as u128) as u64
}

// ---- control plane ---------------------------------------------------------

/// Arm the lazy.wait off-CPU sampler for `pid`, sampling waits longer than
/// `threshold_ns`. No timer/PET — the scheduler triggers it on wakeup. Assumes
/// the kdebug ring is already up (the sched worker owns it) and keeps DBG_PERF.
pub fn arm_lazy_wait(pid: i32, threshold_ns: u64) -> Result<(), String> {
    let step = |r: Result<(), i32>, what: &str| r.map_err(|e| format!("{what} failed (errno {e})"));
    step(kperf_set_u32(b"kperf.reset\0", 1), "kperf.reset")?;
    step(kperf_set_u32(b"kperf.action.count\0", 1), "kperf.action.count")?;
    step(
        kperf_set_indexed(b"kperf.action.samplers\0", ACTION_ID, (SAMPLER_USTACK | SAMPLER_TH_INFO) as u64),
        "kperf.action.samplers",
    )?;
    step(
        kperf_set_indexed(b"kperf.action.ucallstack_depth\0", ACTION_ID, UCALLSTACK_DEPTH),
        "kperf.action.ucallstack_depth",
    )?;
    step(
        kperf_set_indexed(b"kperf.action.filter_by_pid\0", ACTION_ID, pid as u64),
        "kperf.action.filter_by_pid",
    )?;
    step(
        kperf_set_u64(b"kperf.lazy.wait_time_threshold\0", ns_to_ticks(threshold_ns)),
        "kperf.lazy.wait_time_threshold",
    )?;
    step(kperf_set_u32(b"kperf.lazy.wait_action\0", ACTION_ID as u32), "kperf.lazy.wait_action")?;
    step(kperf_set_u32(b"kperf.sampling\0", 1), "kperf.sampling")?;
    Ok(())
}

/// Stop kperf sampling and clear its state (idempotent; ignores errors).
pub fn disarm() {
    let _ = kperf_set_u32(b"kperf.sampling\0", 0);
    let _ = kperf_set_u32(b"kperf.reset\0", 1);
}

// ---- decode ----------------------------------------------------------------

fn class_of(debugid: u32) -> u32 {
    (debugid >> 24) & 0xff
}
fn subclass_of(debugid: u32) -> u32 {
    (debugid >> 16) & 0xff
}
fn code_of(debugid: u32) -> u32 {
    (debugid >> 2) & 0x3fff
}

/// The kd_buf fields the off-CPU decoder needs (the sched worker builds this
/// from its own KdBuf each event).
pub struct KdEvent {
    pub debugid: u32,
    pub timestamp: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
    pub cpuid: u32,
}

struct Pending {
    want: usize,
    frames: Vec<u64>,
}

/// A completed off-CPU sample: a thread's blocking user stack + how long it was
/// blocked (the weight), leaf-first PCs.
pub struct OffCpuSample {
    pub pid: u64,
    pub tid: u64,
    pub cpu: u32,
    pub ts_ticks: u64,
    pub wait_ns: u64,
    pub frames: Vec<u64>,
}

/// Decodes the lazy.wait stream. Every event is in the woken thread's context
/// (on-core), so the kd_buf tid (arg5) IS the sampled thread — key on it. A
/// WAITSAMPLE records the wait duration + wake time; the pended user callstack
/// that follows (same tid) closes it into an OffCpuSample.
#[derive(Default)]
pub struct LazyDecoder {
    /// tid -> (wait_time ticks, wake timestamp ticks) from the last WAITSAMPLE.
    pending_wait: HashMap<u64, (u64, u64)>,
    /// tid -> pid from THREADINFO (kperf pid_filter already restricts to target).
    pid_of: HashMap<u64, u64>,
    /// tid -> user callstack being reassembled.
    building: HashMap<u64, Pending>,
}

impl LazyDecoder {
    pub fn on_event(&mut self, e: &KdEvent) -> Option<OffCpuSample> {
        if class_of(e.debugid) != DBG_PERF {
            return None;
        }
        let tid = e.arg5;
        match (subclass_of(e.debugid), code_of(e.debugid)) {
            (PERF_LAZY, PERF_LZ_WAITSAMPLE) => {
                self.pending_wait.insert(tid, (e.arg1, e.timestamp));
                None
            }
            (PERF_THREADINFO, PERF_TI_DATA) => {
                self.pid_of.insert(tid, e.arg1); // arg1 = pid
                None
            }
            (PERF_CALLSTACK, PERF_CS_UHDR) => {
                let want = (e.arg2 as usize).min(MAX_FRAMES);
                self.building.insert(tid, Pending { want, frames: Vec::with_capacity(want) });
                None
            }
            (PERF_CALLSTACK, PERF_CS_UDATA) => {
                let done = {
                    let p = self.building.get_mut(&tid)?;
                    for pc in [e.arg1, e.arg2, e.arg3, e.arg4] {
                        if p.frames.len() < p.want {
                            p.frames.push(pc);
                        }
                    }
                    if p.frames.len() < p.want {
                        return None;
                    }
                    self.building.remove(&tid).unwrap()
                };
                // Pair with this thread's pending wait; with only lazy.wait armed
                // every user stack has one — skip orphans.
                let (wait_ticks, ts_ticks) = self.pending_wait.remove(&tid)?;
                let pid = self.pid_of.get(&tid).copied().unwrap_or(0);
                Some(OffCpuSample {
                    pid,
                    tid,
                    cpu: e.cpuid,
                    ts_ticks,
                    wait_ns: ticks_to_ns(wait_ticks),
                    frames: done.frames,
                })
            }
            _ => None,
        }
    }
}

// ---- emit (interned, symbolizable PerfSamples) -----------------------------

/// A loaded mach-o module: address range + path + UUID (the Mach-O build-id),
/// used to emit Perfetto Mapping entries so off-CPU frames symbolize post-record.
struct Module {
    base: u64,
    end: u64,
    path: Vec<u8>,
    uuid: [u8; 16],
}

/// Enumerate the target's mach-o images into a base-sorted module table.
fn load_modules(task: MachPort) -> Vec<Module> {
    let list = match ImageList::enumerate(task) {
        Ok(l) => l,
        Err(_) => return Vec::new(),
    };
    let mut imgs: Vec<(u64, Vec<u8>)> = list.images().to_vec();
    imgs.sort_by_key(|(b, _)| *b);
    let n = imgs.len();
    let mut mods = Vec::with_capacity(n);
    for idx in 0..n {
        let base = imgs[idx].0;
        let next = if idx + 1 < n { imgs[idx + 1].0 } else { u64::MAX };
        if let Some(m) = read_macho(task, base) {
            let end = base.wrapping_add(m.text_vmsize).min(next);
            mods.push(Module { base, end, path: imgs[idx].1.clone(), uuid: m.uuid });
        }
    }
    mods
}

/// Binary-search a PC into the base-sorted module table.
fn find_module(mods: &[Module], pc: u64) -> Option<usize> {
    let i = mods.partition_point(|m| m.base <= pc);
    if i == 0 {
        return None;
    }
    if pc < mods[i - 1].end {
        Some(i - 1)
    } else {
        None
    }
}

/// Perfetto InternedData interner (its own iid spaces, all counting from 1 per
/// incremental-state-cleared sequence). Mirrors the Linux interner, but frames
/// come from the dyld module table rather than /proc/pid/maps.
struct Interner {
    paths: HashMap<Vec<u8>, u64>,
    build_ids: HashMap<Vec<u8>, u64>,
    mappings: HashMap<u64, u64>,   // module.base -> iid
    frames: HashMap<(u64, u64), u64>, // (mapping_iid, pc) -> iid
    callstacks: HashMap<Vec<u8>, u64>,
    next_path: u64,
    next_build_id: u64,
    next_mapping: u64,
    next_frame: u64,
    next_callstack: u64,
}

impl Interner {
    fn new() -> Self {
        Interner {
            paths: HashMap::new(),
            build_ids: HashMap::new(),
            mappings: HashMap::new(),
            frames: HashMap::new(),
            callstacks: HashMap::new(),
            next_path: 1,
            next_build_id: 1,
            next_mapping: 1,
            next_frame: 1,
            next_callstack: 1,
        }
    }

    fn reset(&mut self) {
        *self = Interner::new();
    }

    fn intern_string(
        idw: &mut ProtoWriter,
        field: u32,
        s: &[u8],
        map: &mut HashMap<Vec<u8>, u64>,
        next: &mut u64,
    ) -> u64 {
        if let Some(&iid) = map.get(s) {
            return iid;
        }
        let iid = *next;
        *next += 1;
        map.insert(s.to_vec(), iid);
        idw.message(field, |m| {
            m.write_uint64(1, iid);
            m.write_string(2, s);
        });
        iid
    }

    fn intern_mapping(&mut self, idw: &mut ProtoWriter, base: u64, end: u64, path: &[u8], uuid: &[u8]) -> u64 {
        if let Some(&iid) = self.mappings.get(&base) {
            return iid;
        }
        let path_iid = Self::intern_string(idw, 17, path, &mut self.paths, &mut self.next_path);
        let build_iid = if uuid.iter().any(|&b| b != 0) {
            Self::intern_string(idw, 16, uuid, &mut self.build_ids, &mut self.next_build_id)
        } else {
            0
        };
        let iid = self.next_mapping;
        self.next_mapping += 1;
        self.mappings.insert(base, iid);
        idw.message(19, |mp| {
            mp.write_uint64(1, iid);
            if build_iid != 0 {
                mp.write_uint64(2, build_iid);
            }
            mp.write_uint64(4, base); // start
            mp.write_uint64(5, end); // end
            mp.write_uint64(6, base); // load_bias = base_avma
            mp.write_uint64(8, 0); // exact_offset (0 on macOS)
            mp.write_uint64(7, path_iid); // path_string_ids
        });
        iid
    }

    fn intern_frame(&mut self, idw: &mut ProtoWriter, mapping_iid: u64, pc: u64) -> u64 {
        if let Some(&iid) = self.frames.get(&(mapping_iid, pc)) {
            return iid;
        }
        let iid = self.next_frame;
        self.next_frame += 1;
        self.frames.insert((mapping_iid, pc), iid);
        idw.message(6, |fr| {
            fr.write_uint64(1, iid);
            fr.write_uint64(3, mapping_iid);
            fr.write_uint64(4, pc); // rel_pc = absolute PC; Perfetto subtracts load_bias
        });
        iid
    }

    fn intern_callstack(&mut self, idw: &mut ProtoWriter, fids: &[u64]) -> u64 {
        let key: Vec<u8> = fids.iter().flat_map(|f| f.to_le_bytes()).collect();
        if let Some(&iid) = self.callstacks.get(&key) {
            return iid;
        }
        let iid = self.next_callstack;
        self.next_callstack += 1;
        self.callstacks.insert(key, iid);
        idw.message(7, |cs| {
            cs.write_uint64(1, iid);
            for &f in fids {
                cs.write_uint64(2, f);
            }
        });
        iid
    }
}

/// Emits decoded off-CPU samples as Perfetto PerfSamples on their own data-source
/// sequence (timebase `off-cpu-ns`, weight = off-CPU duration).
pub struct OffCpuEmitter {
    ds_slot: u32,
    task: MachPort,
    modules: Vec<Module>,
    interner: Interner,
    need_defaults: bool,
    tb_numer: u64,
    tb_denom: u64,
}

impl OffCpuEmitter {
    /// Build the emitter: enumerate the target's modules for symbolization.
    pub fn new(ds_slot: u32, task: MachPort) -> Self {
        let (tb_numer, tb_denom) = timebase();
        OffCpuEmitter {
            ds_slot,
            task,
            modules: load_modules(task),
            interner: Interner::new(),
            need_defaults: true,
            tb_numer,
            tb_denom,
        }
    }

    /// A new incremental-state-cleared sequence begins — re-emit defaults + reset
    /// interning on the next sample (called after (re)start).
    pub fn mark_needs_defaults(&mut self) {
        self.need_defaults = true;
    }

    fn emit_defaults(&mut self) {
        let mut w = ProtoWriter::new();
        w.write_perf_defaults_packet(
            b"off-cpu-ns",
            0,
            &[],
            SAMPLE_SCOPE_THREAD,
            BUILTIN_CLOCK_MONOTONIC,
            SEQ_INCREMENTAL_STATE_CLEARED,
        );
        unsafe { sismo_ds_emit(self.ds_slot, w.bytes().as_ptr(), w.bytes().len()) };
    }

    pub fn emit(&mut self, s: &OffCpuSample) {
        if self.need_defaults {
            self.interner.reset();
            self.emit_defaults();
            self.need_defaults = false;
        }
        // A dlopen after startup can leave frames unmapped — re-enumerate once.
        if s.frames.iter().any(|&pc| pc != 0 && find_module(&self.modules, pc).is_none()) {
            self.modules = load_modules(self.task);
        }

        let mut idw = ProtoWriter::new();
        let mut fids: Vec<u64> = Vec::with_capacity(s.frames.len());
        for &pc in &s.frames {
            if pc == 0 {
                continue;
            }
            if let Some(i) = find_module(&self.modules, pc) {
                let (base, end) = (self.modules[i].base, self.modules[i].end);
                let m = &self.modules[i];
                let mapping_iid = self.interner.intern_mapping(&mut idw, base, end, &m.path, &m.uuid);
                let frame_iid = self.interner.intern_frame(&mut idw, mapping_iid, pc);
                fids.push(frame_iid);
            }
        }
        let cs_iid = if fids.is_empty() {
            0
        } else {
            fids.reverse(); // leaf-first -> root-first
            self.interner.intern_callstack(&mut idw, &fids)
        };

        let ts_ns = s.ts_ticks.wrapping_mul(self.tb_numer) / self.tb_denom;
        let mut tp = ProtoWriter::new();
        tp.write_uint64(8, ts_ns);
        tp.write_uint32(13, SEQ_NEEDS_INCREMENTAL_STATE);
        if !idw.bytes().is_empty() {
            tp.write_message(12, idw.bytes());
        }
        tp.write_perf_sample(
            TP_FIELD_PERF_SAMPLE,
            s.cpu,
            s.pid as u32,
            s.tid as u32,
            cs_iid,
            s.wait_ns, // timebase_count = off-CPU duration ns = the weight
            &[],
            0,
            None,
        );
        unsafe { sismo_ds_emit(self.ds_slot, tp.bytes().as_ptr(), tp.bytes().len()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(sub: u32, code: u32, ts: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> KdEvent {
        KdEvent {
            debugid: (DBG_PERF << 24) | (sub << 16) | (code << 2),
            timestamp: ts,
            arg1: a1,
            arg2: a2,
            arg3: a3,
            arg4: a4,
            arg5: a5,
            cpuid: 0,
        }
    }

    #[test]
    fn pairs_waitsample_with_stack() {
        let mut d = LazyDecoder::default();
        // WAITSAMPLE: wait_time=1000 ticks, wake ts=42; tid (arg5) = 7.
        assert!(d.on_event(&mk(PERF_LAZY, PERF_LZ_WAITSAMPLE, 42, 1000, 0, 0, 0, 7)).is_none());
        // THREADINFO: pid=1234, tid=7.
        assert!(d.on_event(&mk(PERF_THREADINFO, PERF_TI_DATA, 0, 1234, 7, 0, 0, 7)).is_none());
        // UHDR nframes=2, then one UDATA of 4 (2 used).
        assert!(d.on_event(&mk(PERF_CALLSTACK, PERF_CS_UHDR, 0, 0, 2, 0, 0, 7)).is_none());
        let s = d
            .on_event(&mk(PERF_CALLSTACK, PERF_CS_UDATA, 0, 0xaaaa, 0xbbbb, 0, 0, 7))
            .unwrap();
        assert_eq!((s.pid, s.tid, s.ts_ticks), (1234, 7, 42));
        assert_eq!(s.frames, vec![0xaaaa, 0xbbbb]);
        assert!(s.wait_ns > 0); // 1000 ticks -> some ns
    }

    #[test]
    fn stack_without_wait_is_dropped() {
        let mut d = LazyDecoder::default();
        d.on_event(&mk(PERF_CALLSTACK, PERF_CS_UHDR, 0, 0, 1, 0, 0, 9));
        // No preceding WAITSAMPLE for tid 9 -> orphan, no sample.
        assert!(d.on_event(&mk(PERF_CALLSTACK, PERF_CS_UDATA, 0, 0xc0de, 0, 0, 0, 9)).is_none());
    }

    #[test]
    fn find_module_ranges() {
        let mods = vec![
            Module { base: 0x1000, end: 0x2000, path: b"a".to_vec(), uuid: [0; 16] },
            Module { base: 0x4000, end: 0x5000, path: b"b".to_vec(), uuid: [0; 16] },
        ];
        assert_eq!(find_module(&mods, 0x1500), Some(0));
        assert_eq!(find_module(&mods, 0x4000), Some(1));
        assert_eq!(find_module(&mods, 0x2000), None); // end is exclusive
        assert_eq!(find_module(&mods, 0x0fff), None);
        assert_eq!(find_module(&mods, 0x9000), None);
    }
}
