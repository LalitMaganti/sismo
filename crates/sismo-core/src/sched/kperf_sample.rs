// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.
//
//! macOS kperf stack samples (on-CPU + off-CPU), decoded off the shared kdebug
//! ring the ring host owns. Both samplers emit the same DBG_PERF event shape —
//! THREADINFO (pid) + a user CALLSTACK for the thread whose id is stamped in
//! `arg5` — the only difference is the *trigger*:
//!
//!   * off-CPU: a `PERF_LZ_WAITSAMPLE` precedes the stack (thread woke from a
//!     long wait); the sample is weighted by the wait duration.
//!   * on-CPU: a `PERF_TM_FIRE` precedes the stack (a kperf timer fired on this
//!     CPU while the thread ran); the sample is weighted by the timer period.
//!
//! The two consumers reassemble stacks independently and each emits only the
//! stacks whose thread has one of *its* triggers pending — so they demux cleanly
//! off one interleaved event stream without coordinating. Both reuse the shared
//! module table + interner to emit symbolizable Perfetto `PerfSample`s (off-CPU
//! is the macOS side of docs/offcpu-cross-platform.md; on-CPU mirrors the Linux
//! CPU-samples timeline).
//!
//! macOS-only; gated in sched/mod.rs.

use crate::ffi::sismo_ds_emit;
use crate::mach::MachPort;
use crate::proto::ProtoWriter;
use crate::sched::kperf::{ticks_to_ns, timebase};
use crate::sched::ring::{ConsumerCtl, KdEvent, KdThreadMap, RingConsumer};
use crate::symbolize::dyld_images::{read_macho_meta, ImageList};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

// ---- kperf event codes (osfmk/kperf/buffer.h) ------------------------------

const DBG_PERF: u32 = 0x25;
/// The DBG_PERF class csc range (0x2500..=0x25ff — every kperf subclass): the
/// kdebug typefilter contribution both perf consumers need. The ring host unions
/// it with the sched consumer's range.
pub(crate) const DBG_PERF_CSC_RANGE: (u16, u16) = (0x2500, 0x25ff);
const PERF_RANGES: [(u16, u16); 1] = [DBG_PERF_CSC_RANGE];

const PERF_THREADINFO: u32 = 1;
const PERF_TI_DATA: u32 = 1; // BUF_DATA(PERF_TI_DATA, pid, tid, dq_addr, runmode)
const PERF_CALLSTACK: u32 = 2;
const PERF_CS_KDATA: u32 = 3; // kernel stack frames (on-CPU only)
const PERF_CS_UDATA: u32 = 4;
const PERF_CS_KHDR: u32 = 5; // kernel stack header (nframes)
const PERF_CS_UHDR: u32 = 6;
const PERF_TIMER: u32 = 3;
const PERF_TM_FIRE: u32 = 0; // BUF_START of a timer sample (on-CPU trigger)
const PERF_LAZY: u32 = 9;
const PERF_LZ_WAITSAMPLE: u32 = 1; // BUF_DATA(wait_time, runnable_time, running_time), mach ticks

const MAX_FRAMES: usize = 256; // guard against a garbage UHDR nframes

// Perfetto sequence/scope/clock constants (mirror linux_bpf_capture.rs).
const SEQ_INCREMENTAL_STATE_CLEARED: u32 = 1;
const SEQ_NEEDS_INCREMENTAL_STATE: u32 = 2;
const BUILTIN_CLOCK_MONOTONIC: u32 = 3;
const SAMPLE_SCOPE_THREAD: u32 = 2;
const TP_FIELD_PERF_SAMPLE: u32 = 66;

// Synthetic mapping for on-CPU kernel frames. No build-id / KASLR slide yet, so
// they render as raw addresses under "[kernel]" until kernel symbolization
// lands; base 0 (== load_bias 0) makes rel_pc the absolute kernel PC. The key 0
// never collides with a dyld module base, and this mapping lives only in the
// interner (never the `modules` table `find_module` searches).
const KERNEL_MAP_BASE: u64 = 0;
const KERNEL_MAP_END: u64 = u64::MAX;
const KERNEL_PATH: &[u8] = b"[kernel]";

fn class_of(debugid: u32) -> u32 {
    (debugid >> 24) & 0xff
}
fn subclass_of(debugid: u32) -> u32 {
    (debugid >> 16) & 0xff
}
fn code_of(debugid: u32) -> u32 {
    (debugid >> 2) & 0x3fff
}

// ---- user-stack reassembly (shared by both consumers) ----------------------

struct Pending {
    want: usize,
    frames: Vec<u64>,
}

/// A decoded stack sample ready to emit: leaf-first user PCs (+ kernel PCs for
/// on-CPU samples) and the thread it belongs to. The weight (off-CPU duration or
/// on-CPU period) is applied by the consumer at emit time.
struct DecodedStack {
    pid: u64,
    tid: u64,
    cpu: u32,
    ts_ticks: u64,
    /// Leaf-first user frames.
    frames: Vec<u64>,
    /// Leaf-first kernel frames (empty for off-CPU; on-CPU when in a syscall).
    kernel_frames: Vec<u64>,
}

/// Cap on recycled frame buffers kept around (bounds pool memory; ample for the
/// handful of stacks in flight at once).
const FRAME_POOL_CAP: usize = 256;

/// Reassembles per-thread callstacks from the DBG_PERF THREADINFO / CALLSTACK
/// events. Keyed on tid (`arg5`) — a thread runs on one CPU at a time, so its
/// events are naturally serialized. Handles the user stack (both consumers) and
/// the kernel stack (on-CPU only): the kernel stack arrives first (KHDR/KDATA)
/// and is parked in `kernel_done` until the following user stack completes,
/// which is when the consumer packages the pair. Completed frame buffers are
/// recycled through `free_frames` so steady-state decode does not allocate.
#[derive(Default)]
struct UserStacks {
    /// tid -> pid, from THREADINFO (kperf pid_filter already restricts to target).
    pid_of: HashMap<u64, u64>,
    /// tid -> user callstack being reassembled.
    building: HashMap<u64, Pending>,
    /// tid -> kernel callstack being reassembled (on-CPU only).
    building_kernel: HashMap<u64, Pending>,
    /// tid -> completed kernel callstack awaiting its user stack (on-CPU only).
    kernel_done: HashMap<u64, Vec<u64>>,
    /// Recycled frame buffers (returned by the consumer after emit).
    free_frames: Vec<Vec<u64>>,
}

impl UserStacks {
    fn on_threadinfo(&mut self, tid: u64, pid: u64) {
        self.pid_of.insert(tid, pid);
    }

    fn take_buf(&mut self, want: usize) -> Vec<u64> {
        let mut frames = self.free_frames.pop().unwrap_or_default();
        frames.clear();
        frames.reserve(want);
        frames
    }

    fn on_uhdr(&mut self, tid: u64, nframes: u64) {
        let want = (nframes as usize).min(MAX_FRAMES);
        let frames = self.take_buf(want);
        self.building.insert(tid, Pending { want, frames });
    }

    /// Push up to four PCs; return `Some((pid, leaf-first frames))` once the
    /// user stack for `tid` is complete.
    fn on_udata(&mut self, tid: u64, pcs: [u64; 4]) -> Option<(u64, Vec<u64>)> {
        let p = self.building.get_mut(&tid)?;
        push_pcs(p, pcs);
        if p.frames.len() < p.want {
            return None;
        }
        let done = self.building.remove(&tid).unwrap();
        let pid = self.pid_of.get(&tid).copied().unwrap_or(0);
        Some((pid, done.frames))
    }

    fn on_khdr(&mut self, tid: u64, nframes: u64) {
        let want = (nframes as usize).min(MAX_FRAMES);
        let frames = self.take_buf(want);
        self.building_kernel.insert(tid, Pending { want, frames });
    }

    /// Push up to four kernel PCs; when the kernel stack for `tid` completes,
    /// park it (leaf-first) until the user stack closes the sample.
    fn on_kdata(&mut self, tid: u64, pcs: [u64; 4]) {
        let Some(p) = self.building_kernel.get_mut(&tid) else { return };
        push_pcs(p, pcs);
        if p.frames.len() >= p.want {
            let done = self.building_kernel.remove(&tid).unwrap();
            // Recycle any prior parked kernel stack we're about to overwrite.
            if let Some(old) = self.kernel_done.insert(tid, done.frames) {
                self.recycle(old);
            }
        }
    }

    /// Take the parked kernel stack for `tid` (empty if none).
    fn take_kernel(&mut self, tid: u64) -> Vec<u64> {
        self.kernel_done.remove(&tid).unwrap_or_default()
    }

    /// Return an emitted frame buffer to the pool for reuse.
    fn recycle(&mut self, buf: Vec<u64>) {
        if self.free_frames.len() < FRAME_POOL_CAP {
            self.free_frames.push(buf);
        }
    }
}

/// Append up to four PCs to a pending stack, honoring its frame cap.
fn push_pcs(p: &mut Pending, pcs: [u64; 4]) {
    for pc in pcs {
        if p.frames.len() < p.want {
            p.frames.push(pc);
        }
    }
}

// ---- off-CPU consumer (lazy.wait) ------------------------------------------

/// Off-CPU samples: kperf's `lazy.wait` sampler fires when a thread wakes from a
/// wait longer than the configured threshold. Emits the blocking user stack
/// weighted by the off-CPU duration.
pub struct OffCpuConsumer {
    ctl: Arc<ConsumerCtl>,
    emitter: PerfEmitter,
    stacks: UserStacks,
    /// tid -> (wait_time ticks, wake timestamp ticks) from the last WAITSAMPLE.
    pending_wait: HashMap<u64, (u64, u64)>,
}

impl OffCpuConsumer {
    pub fn new(ctl: Arc<ConsumerCtl>, task: MachPort) -> Self {
        let slot = ctl.ds_slot.load(Ordering::Acquire);
        OffCpuConsumer {
            ctl,
            emitter: PerfEmitter::new(slot, task, b"off-cpu-ns"),
            stacks: UserStacks::default(),
            pending_wait: HashMap::new(),
        }
    }

    /// Decode one event; return a completed sample (with its off-CPU weight ns).
    fn decode(&mut self, e: &KdEvent) -> Option<(DecodedStack, u64)> {
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
                self.stacks.on_threadinfo(tid, e.arg1);
                None
            }
            (PERF_CALLSTACK, PERF_CS_UHDR) => {
                self.stacks.on_uhdr(tid, e.arg2);
                None
            }
            (PERF_CALLSTACK, PERF_CS_UDATA) => {
                let (pid, frames) = self.stacks.on_udata(tid, [e.arg1, e.arg2, e.arg3, e.arg4])?;
                // Pair with this thread's pending wait; a stack with no pending
                // wait was triggered by something else (e.g. the on-CPU timer) —
                // drop it, the on-CPU consumer will claim it.
                let (wait_ticks, ts_ticks) = self.pending_wait.remove(&tid)?;
                // Off-CPU is user-only (lazy.wait fires in the scheduler).
                Some((DecodedStack { pid, tid, cpu: e.cpuid, ts_ticks, frames, kernel_frames: Vec::new() }, ticks_to_ns(wait_ticks)))
            }
            _ => None,
        }
    }
}

impl RingConsumer for OffCpuConsumer {
    fn csc_ranges(&self) -> &[(u16, u16)] {
        &PERF_RANGES
    }

    fn on_drain(&mut self, events: &[KdEvent], _thread_map: &[KdThreadMap]) {
        for e in events {
            if let Some((s, weight_ns)) = self.decode(e) {
                self.emitter.emit(&s, weight_ns);
                self.ctl.samples.fetch_add(1, Ordering::Relaxed);
                self.stacks.recycle(s.frames);
            }
        }
    }
}

// ---- on-CPU consumer (kperf timer) -----------------------------------------

/// On-CPU samples: a kperf timer fires per-CPU and samples the running thread.
/// Emits the running stack (kernel frames under a synthetic `[kernel]` mapping,
/// then user frames) weighted by the timer period, so the flamegraph reads as
/// CPU time — mirroring the Linux CPU-samples timeline.
pub struct OnCpuConsumer {
    ctl: Arc<ConsumerCtl>,
    emitter: PerfEmitter,
    stacks: UserStacks,
    /// tid -> timer-fire timestamp ticks. Presence = "this thread was
    /// timer-sampled"; the following stack pairs with it.
    pending_fire: HashMap<u64, u64>,
    /// Weight per sample: the timer period in ns.
    period_ns: u64,
}

impl OnCpuConsumer {
    pub fn new(ctl: Arc<ConsumerCtl>, task: MachPort, period_ns: u64) -> Self {
        let slot = ctl.ds_slot.load(Ordering::Acquire);
        OnCpuConsumer {
            ctl,
            emitter: PerfEmitter::new(slot, task, b"cpu-ns"),
            stacks: UserStacks::default(),
            pending_fire: HashMap::new(),
            period_ns,
        }
    }

    fn decode(&mut self, e: &KdEvent) -> Option<DecodedStack> {
        if class_of(e.debugid) != DBG_PERF {
            return None;
        }
        let tid = e.arg5;
        match (subclass_of(e.debugid), code_of(e.debugid)) {
            (PERF_TIMER, PERF_TM_FIRE) => {
                self.pending_fire.insert(tid, e.timestamp);
                None
            }
            (PERF_THREADINFO, PERF_TI_DATA) => {
                self.stacks.on_threadinfo(tid, e.arg1);
                None
            }
            // Kernel stack (arrives before the user stack of the same sample).
            (PERF_CALLSTACK, PERF_CS_KHDR) => {
                self.stacks.on_khdr(tid, e.arg2);
                None
            }
            (PERF_CALLSTACK, PERF_CS_KDATA) => {
                self.stacks.on_kdata(tid, [e.arg1, e.arg2, e.arg3, e.arg4]);
                None
            }
            (PERF_CALLSTACK, PERF_CS_UHDR) => {
                self.stacks.on_uhdr(tid, e.arg2);
                None
            }
            (PERF_CALLSTACK, PERF_CS_UDATA) => {
                let (pid, frames) = self.stacks.on_udata(tid, [e.arg1, e.arg2, e.arg3, e.arg4])?;
                // Pair with this thread's pending timer fire; a stack with no
                // pending fire belongs to the off-CPU consumer — drop it.
                let ts_ticks = self.pending_fire.remove(&tid)?;
                let kernel_frames = self.stacks.take_kernel(tid);
                Some(DecodedStack { pid, tid, cpu: e.cpuid, ts_ticks, frames, kernel_frames })
            }
            _ => None,
        }
    }
}

impl RingConsumer for OnCpuConsumer {
    fn csc_ranges(&self) -> &[(u16, u16)] {
        &PERF_RANGES
    }

    fn on_drain(&mut self, events: &[KdEvent], _thread_map: &[KdThreadMap]) {
        let period = self.period_ns;
        for e in events {
            if let Some(s) = self.decode(e) {
                self.emitter.emit(&s, period);
                self.ctl.samples.fetch_add(1, Ordering::Relaxed);
                self.stacks.recycle(s.frames);
                if !s.kernel_frames.is_empty() {
                    self.stacks.recycle(s.kernel_frames);
                }
            }
        }
    }
}

// ---- shared module table + interner ----------------------------------------

/// A loaded mach-o module: address range + path + UUID (the Mach-O build-id),
/// used to emit Perfetto Mapping entries so frames symbolize post-record.
struct Module {
    base: u64,
    end: u64,
    path: Vec<u8>,
    uuid: [u8; 16],
}

/// Enumerate the target's mach-o images into a base-sorted module table. Reads
/// only each image's metadata (UUID + __TEXT vmsize), not its bytes. The end is
/// base + __TEXT vmsize — NOT clamped to the next image's base: under the dyld
/// shared cache image headers are packed together, so a next-base clamp would
/// truncate ranges and make in-cache frames miss.
fn load_modules(task: MachPort) -> Vec<Module> {
    let list = match ImageList::enumerate(task) {
        Ok(l) => l,
        Err(_) => return Vec::new(),
    };
    let mut mods = Vec::with_capacity(list.len());
    for (base, path) in list.images() {
        if let Some((uuid, text_vmsize)) = read_macho_meta(task, *base) {
            mods.push(Module { base: *base, end: base.wrapping_add(text_vmsize), path: path.clone(), uuid });
        }
    }
    mods.sort_by_key(|m| m.base);
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
/// incremental-state-cleared sequence). Frames come from the dyld module table
/// rather than /proc/pid/maps.
struct Interner {
    paths: HashMap<Vec<u8>, u64>,
    build_ids: HashMap<Vec<u8>, u64>,
    mappings: HashMap<u64, u64>,      // module.base -> iid
    frames: HashMap<(u64, u64), u64>, // (mapping_iid, pc) -> iid
    callstacks: HashMap<Vec<u8>, u64>,
    /// Reused buffer for the callstack lookup key (frame iids as little-endian
    /// bytes) — cleared per sample, cloned only when a new callstack is interned.
    key_scratch: Vec<u8>,
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
            key_scratch: Vec::with_capacity(256),
            next_path: 1,
            next_build_id: 1,
            next_mapping: 1,
            next_frame: 1,
            next_callstack: 1,
        }
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
        self.key_scratch.clear();
        for f in fids {
            self.key_scratch.extend_from_slice(&f.to_le_bytes());
        }
        if let Some(&iid) = self.callstacks.get(self.key_scratch.as_slice()) {
            return iid;
        }
        let iid = self.next_callstack;
        self.next_callstack += 1;
        self.callstacks.insert(self.key_scratch.clone(), iid);
        idw.message(7, |cs| {
            cs.write_uint64(1, iid);
            for &f in fids {
                cs.write_uint64(2, f);
            }
        });
        iid
    }
}

/// Emits decoded stack samples as interned Perfetto `PerfSample`s on one
/// data-source sequence. Parameterized by the timebase name (`off-cpu-ns` /
/// `cpu-ns`); the per-sample weight (off-CPU duration or timer period) is the
/// `timebase_count`. Shared by both perf consumers — each owns its own emitter
/// (own sequence, own interner) but the code is one implementation.
struct PerfEmitter {
    ds_slot: u32,
    task: MachPort,
    timebase_name: &'static [u8],
    modules: Vec<Module>,
    interner: Interner,
    need_defaults: bool,
    tb_numer: u64,
    tb_denom: u64,
    /// Samples since the last module reload — bounds reload frequency so a
    /// persistently-unmappable frame (JIT, etc.) can't reload every sample.
    since_reload: u64,
    /// Reused per-sample scratch: `idw` builds the InternedData delta, `tp` the
    /// TracePacket, `fids` the frame-iid list — cleared, never reallocated.
    idw: ProtoWriter,
    tp: ProtoWriter,
    fids: Vec<u64>,
}

impl PerfEmitter {
    fn new(ds_slot: u32, task: MachPort, timebase_name: &'static [u8]) -> Self {
        let (tb_numer, tb_denom) = timebase();
        PerfEmitter {
            ds_slot,
            task,
            timebase_name,
            modules: load_modules(task),
            interner: Interner::new(),
            need_defaults: true,
            tb_numer,
            tb_denom,
            since_reload: 0,
            idw: ProtoWriter::with_capacity(2048),
            tp: ProtoWriter::with_capacity(256),
            fids: Vec::with_capacity(128),
        }
    }

    /// Emit `s` weighted by `weight_ns` (the sample's timebase_count).
    fn emit(&mut self, s: &DecodedStack, weight_ns: u64) {
        // Disjoint field borrows so the interner + both scratch writers + the
        // module table can all be used in one pass with no per-sample alloc.
        let PerfEmitter {
            ds_slot, task, timebase_name, modules, interner, need_defaults, tb_numer, tb_denom, since_reload, idw, tp, fids,
        } = self;
        let ds_slot = *ds_slot;

        if *need_defaults {
            *interner = Interner::new();
            tp.clear();
            tp.write_perf_defaults_packet(
                *timebase_name,
                0,
                &[],
                SAMPLE_SCOPE_THREAD,
                BUILTIN_CLOCK_MONOTONIC,
                SEQ_INCREMENTAL_STATE_CLEARED,
            );
            unsafe { sismo_ds_emit(ds_slot, tp.bytes().as_ptr(), tp.bytes().len()) };
            *need_defaults = false;
        }

        // A dlopen after startup can leave frames unmapped — re-enumerate, but at
        // most once every 512 samples so an always-unmappable frame can't reload
        // on every sample.
        *since_reload = since_reload.saturating_add(1);
        if *since_reload > 512 && s.frames.iter().any(|&pc| pc != 0 && find_module(modules, pc).is_none()) {
            *modules = load_modules(*task);
            *since_reload = 0;
        }

        idw.clear();
        fids.clear();
        // Build the combined stack leaf-first: kernel frames (deepest execution
        // point) then user frames. Reversed below to Perfetto's root-first order,
        // giving user-root -> ... -> user-leaf(syscall) -> kernel -> kernel-leaf.
        if !s.kernel_frames.is_empty() {
            let kmap = interner.intern_mapping(idw, KERNEL_MAP_BASE, KERNEL_MAP_END, KERNEL_PATH, &[]);
            for &pc in &s.kernel_frames {
                if pc == 0 {
                    continue;
                }
                let frame_iid = interner.intern_frame(idw, kmap, pc);
                fids.push(frame_iid);
            }
        }
        for &pc in &s.frames {
            if pc == 0 {
                continue;
            }
            if let Some(i) = find_module(modules, pc) {
                let (base, end) = (modules[i].base, modules[i].end);
                let m = &modules[i];
                let mapping_iid = interner.intern_mapping(idw, base, end, &m.path, &m.uuid);
                let frame_iid = interner.intern_frame(idw, mapping_iid, pc);
                fids.push(frame_iid);
            }
        }
        let cs_iid = if fids.is_empty() {
            0
        } else {
            fids.reverse(); // combined leaf-first -> root-first
            interner.intern_callstack(idw, fids)
        };

        let ts_ns = s.ts_ticks.wrapping_mul(*tb_numer) / *tb_denom;
        tp.clear();
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
            weight_ns, // timebase_count = the weight (off-CPU duration or timer period)
            &[],
            0,
            None,
        );
        unsafe { sismo_ds_emit(ds_slot, tp.bytes().as_ptr(), tp.bytes().len()) };
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
            unused: 0,
        }
    }

    // A consumer with a bogus (unused-in-test) emitter: decode is exercised
    // directly, never emit, so the ds_slot / task never touch the C shim.
    fn offcpu() -> OffCpuConsumer {
        OffCpuConsumer {
            ctl: Arc::new(ConsumerCtl::new()),
            emitter: PerfEmitter { ds_slot: u32::MAX, task: 0, timebase_name: b"", modules: Vec::new(), interner: Interner::new(), need_defaults: false, tb_numer: 1, tb_denom: 1, since_reload: 0, idw: ProtoWriter::new(), tp: ProtoWriter::new(), fids: Vec::new() },
            stacks: UserStacks::default(),
            pending_wait: HashMap::new(),
        }
    }

    fn oncpu() -> OnCpuConsumer {
        OnCpuConsumer {
            ctl: Arc::new(ConsumerCtl::new()),
            emitter: PerfEmitter { ds_slot: u32::MAX, task: 0, timebase_name: b"", modules: Vec::new(), interner: Interner::new(), need_defaults: false, tb_numer: 1, tb_denom: 1, since_reload: 0, idw: ProtoWriter::new(), tp: ProtoWriter::new(), fids: Vec::new() },
            stacks: UserStacks::default(),
            pending_fire: HashMap::new(),
            period_ns: 1_000_000,
        }
    }

    #[test]
    fn offcpu_pairs_waitsample_with_stack() {
        let mut d = offcpu();
        // WAITSAMPLE: wait_time=1000 ticks, wake ts=42; tid (arg5) = 7.
        assert!(d.decode(&mk(PERF_LAZY, PERF_LZ_WAITSAMPLE, 42, 1000, 0, 0, 0, 7)).is_none());
        assert!(d.decode(&mk(PERF_THREADINFO, PERF_TI_DATA, 0, 1234, 7, 0, 0, 7)).is_none());
        assert!(d.decode(&mk(PERF_CALLSTACK, PERF_CS_UHDR, 0, 0, 2, 0, 0, 7)).is_none());
        let (s, weight) = d.decode(&mk(PERF_CALLSTACK, PERF_CS_UDATA, 0, 0xaaaa, 0xbbbb, 0, 0, 7)).unwrap();
        assert_eq!((s.pid, s.tid, s.ts_ticks), (1234, 7, 42));
        assert_eq!(s.frames, vec![0xaaaa, 0xbbbb]);
        assert!(weight > 0); // 1000 ticks -> some ns
    }

    #[test]
    fn offcpu_drops_stack_without_wait() {
        // A timer-triggered stack (no WAITSAMPLE) must NOT become an off-CPU
        // sample — that's how the two consumers demux off one stream.
        let mut d = offcpu();
        d.decode(&mk(PERF_THREADINFO, PERF_TI_DATA, 0, 1, 9, 0, 0, 9));
        d.decode(&mk(PERF_CALLSTACK, PERF_CS_UHDR, 0, 0, 1, 0, 0, 9));
        assert!(d.decode(&mk(PERF_CALLSTACK, PERF_CS_UDATA, 0, 0xc0de, 0, 0, 0, 9)).is_none());
    }

    #[test]
    fn oncpu_pairs_timerfire_with_stack() {
        let mut d = oncpu();
        assert!(d.decode(&mk(PERF_TIMER, PERF_TM_FIRE, 99, 0, 0, 0, 0, 5)).is_none());
        assert!(d.decode(&mk(PERF_THREADINFO, PERF_TI_DATA, 0, 4321, 5, 0, 0, 5)).is_none());
        assert!(d.decode(&mk(PERF_CALLSTACK, PERF_CS_UHDR, 0, 0, 1, 0, 0, 5)).is_none());
        let s = d.decode(&mk(PERF_CALLSTACK, PERF_CS_UDATA, 0, 0xf00d, 0, 0, 0, 5)).unwrap();
        assert_eq!((s.pid, s.tid, s.ts_ticks), (4321, 5, 99));
        assert_eq!(s.frames, vec![0xf00d]);
    }

    #[test]
    fn oncpu_captures_kernel_and_user_stack() {
        let mut d = oncpu();
        assert!(d.decode(&mk(PERF_TIMER, PERF_TM_FIRE, 7, 0, 0, 0, 0, 3)).is_none());
        assert!(d.decode(&mk(PERF_THREADINFO, PERF_TI_DATA, 0, 111, 3, 0, 0, 3)).is_none());
        // Kernel stack (1 frame) arrives first and is parked.
        assert!(d.decode(&mk(PERF_CALLSTACK, PERF_CS_KHDR, 0, 0, 1, 0, 0, 3)).is_none());
        assert!(d.decode(&mk(PERF_CALLSTACK, PERF_CS_KDATA, 0, 0xffff_0000, 0, 0, 0, 3)).is_none());
        // The user stack (2 frames) closes the sample and pulls in the kernel stack.
        assert!(d.decode(&mk(PERF_CALLSTACK, PERF_CS_UHDR, 0, 0, 2, 0, 0, 3)).is_none());
        let s = d.decode(&mk(PERF_CALLSTACK, PERF_CS_UDATA, 0, 0xaaaa, 0xbbbb, 0, 0, 3)).unwrap();
        assert_eq!(s.frames, vec![0xaaaa, 0xbbbb]); // user, leaf-first
        assert_eq!(s.kernel_frames, vec![0xffff_0000]); // kernel, leaf-first
        assert_eq!((s.pid, s.tid), (111, 3));
    }

    #[test]
    fn oncpu_drops_stack_without_timerfire() {
        let mut d = oncpu();
        d.decode(&mk(PERF_THREADINFO, PERF_TI_DATA, 0, 1, 9, 0, 0, 9));
        d.decode(&mk(PERF_CALLSTACK, PERF_CS_UHDR, 0, 0, 1, 0, 0, 9));
        assert!(d.decode(&mk(PERF_CALLSTACK, PERF_CS_UDATA, 0, 0xc0de, 0, 0, 0, 9)).is_none());
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
