// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Linux BPF CPU collector — the Rust port of src/linux_bpf_capture.zig (P5,
//! the last big Zig piece). Per-thread PMU counters + timer-tick stack sampling,
//! scoped to the workload, emitted as thread-scoped Perfetto PerfSamples.
//!
//! WORK IN PROGRESS: built up across iterations against the Zig as spec, wired
//! in (and the Zig deleted) only once it passes the difftest trace case.

#![allow(dead_code)]

use std::os::raw::{c_char, c_int, c_void};

// ---- wire format (mirrors src/c/sismo_bpf/sismo_bpf.h) ---------------------

pub const SISMO_MAX_CPUS: usize = 256;
pub const SISMO_MAX_STACK: usize = 64;
pub const SISMO_MAX_KERNEL_STACK: usize = 64;
pub const SISMO_KSYM_NAME_MAX: usize = 96;
pub const SISMO_MAX_COUNTERS: usize = 12;

pub const SISMO_EVT_SAMPLE: u32 = 0;
pub const SISMO_EVT_KSYM: u32 = 1;

/// First field of every record; `type` dispatches on the leading u32.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SismoHdr {
    pub r#type: u32, // enum sismo_event_type
    pub tid: u32,
    pub pid: u32,
    pub cpu: u32,
    pub timebase: u32,
    pub nr_frames: u32,
    pub nr_kernel_frames: u32,
    pub ts: u64,
}

/// SISMO_EVT_SAMPLE. `stack` holds user PCs leaf-first; `kernel_ids` holds
/// kernel-symbol ids leaf-first (resolved in-BPF, KASLR-safe).
#[repr(C)]
pub struct SismoSampleRec {
    pub hdr: SismoHdr,
    pub data_addr: u64,
    pub counters: [u64; SISMO_MAX_COUNTERS],
    pub stack: [u64; SISMO_MAX_STACK],
    pub kernel_ids: [u32; SISMO_MAX_KERNEL_STACK],
}

/// SISMO_EVT_KSYM. One-time (id -> resolved name) mapping.
#[repr(C)]
pub struct SismoKsymRec {
    pub r#type: u32,
    pub id: u32,
    pub name: [c_char; SISMO_KSYM_NAME_MAX],
}

// ---- libbpf (system -lbpf, matching the Zig @cImport of bpf/libbpf.h) ------

// Opaque libbpf handles.
#[repr(C)]
pub struct BpfObject {
    _p: [u8; 0],
}
#[repr(C)]
pub struct BpfMap {
    _p: [u8; 0],
}
#[repr(C)]
pub struct BpfProgram {
    _p: [u8; 0],
}
#[repr(C)]
pub struct BpfLink {
    _p: [u8; 0],
}
#[repr(C)]
pub struct RingBuffer {
    _p: [u8; 0],
}

/// ring_buffer sample callback: (ctx, data, size) -> int (0 to continue).
pub type RingBufferSampleFn =
    unsafe extern "C" fn(ctx: *mut c_void, data: *mut c_void, size: usize) -> c_int;

extern "C" {
    pub fn bpf_object__open_mem(
        obj_buf: *const c_void,
        obj_buf_sz: usize,
        opts: *const c_void,
    ) -> *mut BpfObject;
    pub fn bpf_object__load(obj: *mut BpfObject) -> c_int;
    pub fn bpf_object__close(obj: *mut BpfObject);
    pub fn bpf_object__find_map_by_name(obj: *mut BpfObject, name: *const c_char) -> *mut BpfMap;
    pub fn bpf_object__find_program_by_name(
        obj: *mut BpfObject,
        name: *const c_char,
    ) -> *mut BpfProgram;
    pub fn bpf_map__fd(map: *mut BpfMap) -> c_int;
    pub fn bpf_map_update_elem(
        fd: c_int,
        key: *const c_void,
        value: *const c_void,
        flags: u64,
    ) -> c_int;
    pub fn bpf_program__attach(prog: *mut BpfProgram) -> *mut BpfLink;
    pub fn bpf_program__attach_perf_event(prog: *mut BpfProgram, pfd: c_int) -> *mut BpfLink;
    pub fn bpf_link__destroy(link: *mut BpfLink) -> c_int;
    pub fn ring_buffer__new(
        map_fd: c_int,
        sample_cb: RingBufferSampleFn,
        ctx: *mut c_void,
        opts: *const c_void,
    ) -> *mut RingBuffer;
    pub fn ring_buffer__poll(rb: *mut RingBuffer, timeout_ms: c_int) -> c_int;
    pub fn ring_buffer__consume(rb: *mut RingBuffer) -> c_int;
    pub fn ring_buffer__free(rb: *mut RingBuffer);
    pub fn libbpf_num_possible_cpus() -> c_int;
}

// ---- PMU counter selection (port of the Zig selectCounters + helpers) ------

use crate::pmu_events::{Model, Role, MODELS};

// perf_event PERF_COUNT_HW_* (config values under PERF_TYPE_HARDWARE).
const HW_CPU_CYCLES: u32 = 0;
const HW_INSTRUCTIONS: u32 = 1;
const HW_CACHE_MISSES: u32 = 3;
const HW_BRANCH_MISSES: u32 = 5;
const HW_STALLED_FRONTEND: u32 = 7;
const HW_STALLED_BACKEND: u32 = 8;

#[derive(Clone, Copy)]
enum Src {
    Hw(u32),  // PERF_TYPE_HARDWARE, config = PERF_COUNT_HW_*
    Raw(u32), // PERF_TYPE_RAW, config = raw event encoding
}

#[derive(Clone, Copy)]
struct Counter {
    group: u8,
    src: Src,
    name: &'static str,
}

// x86 fallback set (when the CPU model isn't in the perfmon table). aarch64 uses
// the architectural slot/op events; kept minimal here (primary target is x86).
#[cfg(target_arch = "x86_64")]
const COUNTERS_FALLBACK: &[Counter] = &[
    Counter { group: 0, src: Src::Hw(HW_CPU_CYCLES), name: "cpu-cycles" },
    Counter { group: 0, src: Src::Hw(HW_INSTRUCTIONS), name: "instructions" },
    Counter { group: 0, src: Src::Hw(HW_STALLED_FRONTEND), name: "stalled-cycles-frontend" },
    Counter { group: 0, src: Src::Hw(HW_STALLED_BACKEND), name: "stalled-cycles-backend" },
    Counter { group: 1, src: Src::Hw(HW_CACHE_MISSES), name: "cache-misses" },
    Counter { group: 1, src: Src::Hw(HW_BRANCH_MISSES), name: "branch-misses" },
];
#[cfg(not(target_arch = "x86_64"))]
const COUNTERS_FALLBACK: &[Counter] = &[
    Counter { group: 0, src: Src::Hw(HW_CPU_CYCLES), name: "cpu-cycles" },
    Counter { group: 0, src: Src::Hw(HW_INSTRUCTIONS), name: "instructions" },
    Counter { group: 1, src: Src::Hw(HW_CACHE_MISSES), name: "cache-misses" },
    Counter { group: 1, src: Src::Hw(HW_BRANCH_MISSES), name: "branch-misses" },
];

// STABLE sismo counter name per role (the UI's counter catalog keys on these).
fn role_name(role: Role) -> &'static str {
    match role {
        Role::cycles => "cpu-cycles",
        Role::instructions => "instructions",
        Role::slots => "slots",
        Role::retired => "topdown-slots-retired",
        Role::fetch_bubbles => "topdown-fetch-bubbles",
        Role::cache_miss => "cache-misses",
        Role::branch_miss => "branch-misses",
        Role::l3_miss_load => "mem-load-l3-miss",
    }
}

fn role_group(role: Role) -> u8 {
    match role {
        Role::cache_miss | Role::branch_miss => 1,
        _ => 0,
    }
}

// Leader-only roles (a focus sampler's leader, never a survey follower).
fn is_leader_only_role(role: Role) -> bool {
    matches!(role, Role::l3_miss_load)
}

// The slot-based Top-Down set — only meaningful with the `slots` fixed counter.
fn is_topdown_role(role: Role) -> bool {
    matches!(role, Role::slots | Role::retired | Role::fetch_bubbles)
}

struct CpuId {
    family: u16,
    model: u16,
    stepping: u8,
}

/// Read vendor/family/model/stepping from /proc/cpuinfo. None on non-Intel.
fn read_cpu_id() -> Option<CpuId> {
    let text = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    if !text.contains("GenuineIntel") {
        return None;
    }
    Some(CpuId {
        family: cpuinfo_field(&text, "cpu family")? as u16,
        model: cpuinfo_field(&text, "model")? as u16,
        stepping: cpuinfo_field(&text, "stepping").unwrap_or(0) as u8,
    })
}

// First "<key> : <int>" line, exact key match (so "model" != "model name").
fn cpuinfo_field(text: &str, key: &str) -> Option<u64> {
    for line in text.lines() {
        let (lhs, rhs) = line.split_once(':')?;
        if lhs.trim() != key {
            continue;
        }
        return rhs.trim().split_whitespace().next()?.parse().ok();
    }
    None
}

// slots fixed counter + PERF_METRICS Top-Down present (CPUID leaf 0x0A, v>=5
// with fixed-counter-3 in the ECX support bitmap). Same signal perf uses.
#[cfg(target_arch = "x86_64")]
fn topdown_enumerated() -> bool {
    let r = unsafe { std::arch::x86_64::__cpuid_count(0x0A, 0) };
    let version = r.eax & 0xff;
    version >= 5 && (r.ecx & (1 << 3)) != 0
}
#[cfg(not(target_arch = "x86_64"))]
fn topdown_enumerated() -> bool {
    false
}

// vvvvv TEMPORARY HACK — see linux_bpf_capture.zig; delete once TMA is validated
// on real ICL+ silicon. Forces slot-based counters for one spoofed dev VM
// (family 6 / model 134 / stepping 0 under a hypervisor). A lie about the PMU.
#[cfg(target_arch = "x86_64")]
const VM_HACK_COUNTERS: &[Counter] = &[
    Counter { group: 0, src: Src::Raw(0x3c), name: "cpu-cycles" },
    Counter { group: 0, src: Src::Raw(0xc0), name: "instructions" },
    Counter { group: 0, src: Src::Raw(0x400), name: "slots" },
    Counter { group: 0, src: Src::Raw(0x2c2), name: "topdown-slots-retired" },
    Counter { group: 0, src: Src::Raw(0x19c), name: "topdown-fetch-bubbles" },
    Counter { group: 1, src: Src::Raw(0x412e), name: "cache-misses" },
    Counter { group: 1, src: Src::Raw(0xc5), name: "branch-misses" },
];
#[cfg(target_arch = "x86_64")]
fn vm_slots_hack_counters() -> Option<&'static [Counter]> {
    let id = read_cpu_id()?;
    if id.family != 6 || id.model != 134 || id.stepping != 0 {
        return None;
    }
    let hyp = unsafe { std::arch::x86_64::__cpuid_count(1, 0) };
    if (hyp.ecx & (1 << 31)) == 0 {
        return None; // hypervisor bit
    }
    Some(VM_HACK_COUNTERS)
}
#[cfg(not(target_arch = "x86_64"))]
fn vm_slots_hack_counters() -> Option<&'static [Counter]> {
    None
}
// ^^^^^ TEMPORARY HACK ^^^^^

// This host's perfmon-table row (matched by CPUID). Prefers the non-Atom row.
fn match_model() -> Option<&'static Model> {
    let id = read_cpu_id()?;
    let mut best: Option<&'static Model> = None;
    for m in MODELS {
        if m.family != id.family || m.model != id.model {
            continue;
        }
        if !m.steppings.is_empty() && !m.steppings.contains(&id.stepping) {
            continue;
        }
        best = Some(m);
        if m.core != "Atom" {
            break; // prefer P-core / non-hybrid
        }
    }
    best
}

// Raw PMU config for a role on this host (the focus sampler's leader event).
fn config_for_role(role: Role) -> Option<u64> {
    let m = match_model()?;
    m.events.iter().find(|ev| ev.role == role).map(|ev| ev.config)
}

// Build the counter list from the perfmon table (role → name + group + config).
fn counters_from_table() -> Option<Vec<Counter>> {
    let m = match_model()?;
    let td = topdown_enumerated();
    let mut out = Vec::new();
    for ev in m.events {
        if out.len() >= SISMO_MAX_COUNTERS {
            break;
        }
        if is_leader_only_role(ev.role) || (is_topdown_role(ev.role) && !td) {
            continue;
        }
        out.push(Counter {
            group: role_group(ev.role),
            src: Src::Raw(ev.config as u32),
            name: role_name(ev.role),
        });
    }
    Some(out)
}

/// The active candidate counters for this host: the VM hack, else the perfmon
/// table by CPUID (x86), else the arch fallback.
fn select_counters() -> Vec<Counter> {
    if let Some(list) = vm_slots_hack_counters() {
        return list.to_vec();
    }
    #[cfg(target_arch = "x86_64")]
    if let Some(list) = counters_from_table() {
        return list;
    }
    COUNTERS_FALLBACK.to_vec()
}

// ---- focus presets (port of src/focus_presets.zig) -------------------------

#[derive(Clone, Copy, PartialEq)]
pub enum FocusPreset {
    Cache,
}

enum Leader {
    Cycles,
    Role(Role),
}

struct FocusSpec {
    leader: Leader,
    precise_ip: u8, // u2
    period: u64,
    sample_data_addr: bool,
}

pub fn focus_from_name(name: &[u8]) -> Option<FocusPreset> {
    match name {
        b"cache" => Some(FocusPreset::Cache),
        _ => None,
    }
}

fn focus_spec(p: FocusPreset) -> FocusSpec {
    match p {
        // Sample on retired loads that missed L3 (precise, carries Data_LA).
        FocusPreset::Cache => FocusSpec {
            leader: Leader::Role(Role::l3_miss_load),
            precise_ip: 2,
            period: 2003,
            sample_data_addr: true,
        },
    }
}

// ---- perf_event_open (port of openCounter / resolveSampler / openSampler) ---

use perf_event_open_sys as sys;

extern "C" {
    fn close(fd: c_int) -> c_int;
}

/// Open a counting perf event as part of `group_fd`'s group (-1 = new leader),
/// per-CPU. Returns the fd, or None if the PMU can't schedule it.
fn open_counter(cpu: u32, src: Src, group_fd: i32) -> Option<i32> {
    let mut attr: sys::bindings::perf_event_attr = unsafe { std::mem::zeroed() };
    attr.size = std::mem::size_of::<sys::bindings::perf_event_attr>() as u32;
    match src {
        Src::Hw(h) => {
            attr.type_ = sys::bindings::PERF_TYPE_HARDWARE;
            attr.config = h as u64;
        }
        Src::Raw(r) => {
            attr.type_ = sys::bindings::PERF_TYPE_RAW;
            attr.config = r as u64;
        }
    }
    let rc = unsafe { sys::perf_event_open(&mut attr, -1, cpu as i32, group_fd, 0) };
    if rc < 0 {
        None
    } else {
        Some(rc as i32)
    }
}

/// The resolved sampler leader: what to overflow on, period, PEBS precision.
struct SamplerCfg {
    typ: u32,
    config: u64,
    period: u64,
    precise_ip: u8,
    sample_data_addr: bool,
}

fn scale_period(default_period: u64, density: Option<f64>) -> u64 {
    match density {
        None => default_period,
        Some(d) => {
            let scaled = default_period as f64 / d;
            if scaled < 1.0 {
                1
            } else {
                scaled as u64
            }
        }
    }
}

/// Resolve the sampler from the optional focus preset. Survey = cycles/~1M/no
/// PEBS. A focus preset supplies the event/period/precision; None if an event
/// leader can't be resolved on this CPU (never silently falls back to cycles).
fn resolve_sampler(focus: Option<FocusPreset>, density: Option<f64>) -> Option<SamplerCfg> {
    let cycles_config = HW_CPU_CYCLES as u64;
    let p = match focus {
        None => {
            return Some(SamplerCfg {
                typ: sys::bindings::PERF_TYPE_HARDWARE,
                config: cycles_config,
                period: 1_000_003,
                precise_ip: 0,
                sample_data_addr: false,
            })
        }
        Some(p) => p,
    };
    let s = focus_spec(p);
    let period = scale_period(s.period, density);
    match s.leader {
        Leader::Cycles => Some(SamplerCfg {
            typ: sys::bindings::PERF_TYPE_HARDWARE,
            config: cycles_config,
            period,
            precise_ip: s.precise_ip,
            sample_data_addr: false,
        }),
        Leader::Role(role) => {
            let cfg = config_for_role(role)?;
            Some(SamplerCfg {
                typ: sys::bindings::PERF_TYPE_RAW,
                config: cfg,
                period,
                precise_ip: s.precise_ip,
                sample_data_addr: s.sample_data_addr,
            })
        }
    }
}

struct SamplerHandle {
    fd: i32,
    link: *mut BpfLink,
    precise_ip: u8,
}

/// Open the per-CPU sampler perf event AND attach on_tick to it, trying the
/// requested precise_ip and falling back through lower levels as one unit
/// (both the open and the BPF attach can reject a precise event).
fn open_sampler(cpu: u32, cfg: &SamplerCfg, tick_prog: *mut BpfProgram) -> Option<SamplerHandle> {
    let mut want = cfg.precise_ip;
    loop {
        let mut attr: sys::bindings::perf_event_attr = unsafe { std::mem::zeroed() };
        attr.type_ = cfg.typ;
        attr.size = std::mem::size_of::<sys::bindings::perf_event_attr>() as u32;
        attr.config = cfg.config;
        attr.__bindgen_anon_1.sample_period = cfg.period;
        attr.set_precise_ip(want as u64);
        // bpf_get_stack on a PEBS event needs the callchain sample (else -EPROTO).
        if want > 0 {
            attr.sample_type |= sys::bindings::PERF_SAMPLE_CALLCHAIN as u64;
        }
        // Data_LA only resolves on a precise event.
        if cfg.sample_data_addr && want > 0 {
            attr.sample_type |= sys::bindings::PERF_SAMPLE_ADDR as u64;
        }
        let rc = unsafe { sys::perf_event_open(&mut attr, -1, cpu as i32, -1, 0) };
        if rc >= 0 {
            let fd = rc as i32;
            let link = unsafe { bpf_program__attach_perf_event(tick_prog, fd) };
            if !link.is_null() {
                return Some(SamplerHandle { fd, link, precise_ip: want });
            }
            unsafe { close(fd) }; // attach refused this event; retry lower
        }
        if want == 0 {
            return None;
        }
        want -= 1;
    }
}

// ---- InternedData interner (port of the Zig Interner + intern* methods) -----

use crate::proto::ProtoWriter;
use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FrameKey {
    mapping_iid: u64,
    rel_pc: u64,
    name_iid: u64,
}

/// Per-sequence callstack interning state. Mirrors the iids written into the
/// trace's InternedData tables so each entry is emitted once; reset whenever a
/// fresh incremental-state-cleared sequence begins. Worker-thread only.
#[derive(Default)]
struct Interner {
    paths: HashMap<Vec<u8>, u64>,
    build_ids: HashMap<Vec<u8>, u64>,
    func_names: HashMap<Vec<u8>, u64>,
    mappings: HashMap<u64, u64>, // map.start -> iid
    frames: HashMap<FrameKey, u64>,
    callstacks: HashMap<Vec<u8>, u64>, // frame-id bytes -> iid
    next_path: u64,
    next_build_id: u64,
    next_func_name: u64,
    next_mapping: u64,
    next_frame: u64,
    next_callstack: u64,
}

impl Interner {
    fn new() -> Self {
        Interner {
            next_path: 1,
            next_build_id: 1,
            next_func_name: 1,
            next_mapping: 1,
            next_frame: 1,
            next_callstack: 1,
            ..Default::default()
        }
    }

    fn reset(&mut self) {
        *self = Interner::new();
    }

    /// Intern `bytes` into `map`, emitting InternedString{iid=1,str=2} under
    /// `field` (17 = mapping_paths, 16 = build_ids, 5 = function_names).
    fn intern_string(
        map: &mut HashMap<Vec<u8>, u64>,
        next: &mut u64,
        field: u32,
        bytes: &[u8],
        idw: &mut ProtoWriter,
    ) -> u64 {
        if let Some(&iid) = map.get(bytes) {
            return iid;
        }
        let iid = *next;
        *next += 1;
        map.insert(bytes.to_vec(), iid);
        let mut s = ProtoWriter::new();
        s.write_uint64(1, iid);
        s.write_string(2, bytes);
        idw.write_message(field, s.bytes());
        iid
    }

    fn intern_path(&mut self, path: &[u8], idw: &mut ProtoWriter) -> u64 {
        Self::intern_string(&mut self.paths, &mut self.next_path, 17, path, idw)
    }
    fn intern_build_id(&mut self, raw: &[u8], idw: &mut ProtoWriter) -> u64 {
        Self::intern_string(&mut self.build_ids, &mut self.next_build_id, 16, raw, idw)
    }
    fn intern_func_name(&mut self, name: &[u8], idw: &mut ProtoWriter) -> u64 {
        Self::intern_string(&mut self.func_names, &mut self.next_func_name, 5, name, idw)
    }

    /// InternedData.mappings (19): Mapping{iid=1, build_id=2, start=4, end=5,
    /// load_bias=6, exact_offset=8, path_string_ids=7}. load_bias = base avma.
    fn intern_mapping(
        &mut self,
        start: u64,
        end: u64,
        offset: u64,
        base_avma: u64,
        path: &[u8],
        build_id: &[u8],
        idw: &mut ProtoWriter,
    ) -> u64 {
        if let Some(&iid) = self.mappings.get(&start) {
            return iid;
        }
        let iid = self.next_mapping;
        self.next_mapping += 1;
        self.mappings.insert(start, iid);
        let path_iid = self.intern_path(path, idw);
        let build_id_iid = if !build_id.is_empty() {
            self.intern_build_id(build_id, idw)
        } else {
            0
        };
        let mut mp = ProtoWriter::new();
        mp.write_uint64(1, iid);
        if build_id_iid != 0 {
            mp.write_uint64(2, build_id_iid);
        }
        mp.write_uint64(4, start);
        mp.write_uint64(5, end);
        mp.write_uint64(6, base_avma);
        mp.write_uint64(8, offset);
        mp.write_uint64(7, path_iid);
        idw.write_message(19, mp.bytes());
        iid
    }

    /// The synthetic "[kernel.kallsyms]" mapping every kernel frame shares
    /// (keyed by sentinel start 0 — real mappings never start at 0).
    fn intern_kernel_mapping(&mut self, idw: &mut ProtoWriter) -> u64 {
        if let Some(&iid) = self.mappings.get(&0) {
            return iid;
        }
        let iid = self.next_mapping;
        self.next_mapping += 1;
        self.mappings.insert(0, iid);
        let path_iid = self.intern_path(b"[kernel.kallsyms]", idw);
        let mut mp = ProtoWriter::new();
        mp.write_uint64(1, iid);
        mp.write_uint64(7, path_iid);
        idw.write_message(19, mp.bytes());
        iid
    }

    /// InternedData.frames (6): Frame{iid=1, function_name_id=2, mapping_id=3,
    /// rel_pc=4}. function_name_id set only for inline-named (kernel) frames.
    fn intern_frame(&mut self, key: FrameKey, idw: &mut ProtoWriter) -> u64 {
        if let Some(&iid) = self.frames.get(&key) {
            return iid;
        }
        let iid = self.next_frame;
        self.next_frame += 1;
        self.frames.insert(key, iid);
        let mut f = ProtoWriter::new();
        f.write_uint64(1, iid);
        if key.name_iid != 0 {
            f.write_uint64(2, key.name_iid);
        }
        f.write_uint64(3, key.mapping_iid);
        f.write_uint64(4, key.rel_pc);
        idw.write_message(6, f.bytes());
        iid
    }

    /// InternedData.callstacks (7): Callstack{iid=1, frame_ids=2}. `fids` is
    /// bottom-frame-first (the caller reverses the leaf-first BPF stack).
    fn intern_callstack_ids(&mut self, fids: &[u64], idw: &mut ProtoWriter) -> u64 {
        let key: Vec<u8> = fids.iter().flat_map(|f| f.to_ne_bytes()).collect();
        if let Some(&iid) = self.callstacks.get(&key) {
            return iid;
        }
        let iid = self.next_callstack;
        self.next_callstack += 1;
        self.callstacks.insert(key, iid);
        let mut cs = ProtoWriter::new();
        cs.write_uint64(1, iid);
        for &fid in fids {
            cs.write_uint64(2, fid);
        }
        idw.write_message(7, cs.bytes());
        iid
    }
}

// ---- Capture: the collector object (output half) ---------------------------

use crate::data_regions::DataRegions;
use crate::proc_maps::ProcMaps;
use crate::proto::sismo_encode_perf_sample;
use crate::worker_sdk::sismo_ds_emit;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// TracePacket / defaults field tags + constants (perfetto_proto.zig).
const TP_FIELD_PERF_SAMPLE: u32 = 66;
const SEQ_INCREMENTAL_STATE_CLEARED: u32 = 1;
const SEQ_NEEDS_INCREMENTAL_STATE: u32 = 2;
const BUILTIN_CLOCK_MONOTONIC: u32 = 3;
const SAMPLE_SCOPE_THREAD: u32 = 2;
// x86-64 user space tops out at the 47-bit canonical boundary.
const USER_ADDR_MAX: u64 = 0x0000_7fff_ffff_ffff;

pub struct Capture {
    obj: *mut BpfObject,
    rb: *mut RingBuffer,
    links: Vec<*mut BpfLink>,
    perf_fds: Vec<i32>,
    worker: Option<std::thread::JoinHandle<()>>,
    exit_requested: AtomicBool,
    acc: HashMap<u32, u64>, // tid -> latest cumulative cpu-cycles
    samples: u64,
    target_pid: u32,
    maps: Option<ProcMaps>, // None = not parsed
    maps_tried: bool,
    last_maps_ns: u64,
    interner: Interner,
    ksym_names: HashMap<u32, Vec<u8>>, // id -> bare function name
    counters: Vec<Counter>,
    active_slots: Vec<u8>, // indices into `counters`; [0] is the timebase
    focus: Option<FocusPreset>,
    data_regions: Option<DataRegions>,
    last_data_parse_ns: u64,
    data_frames: u64,
    sampler_precise_ip: u8,
    ds_slot: u32,
    active: AtomicBool,
    need_defaults: AtomicBool,
    flush_req: AtomicUsize,
    stop_req: AtomicUsize,
}

impl Capture {
    fn ensure_maps(&mut self, now_ns: u64) {
        if self.maps_tried {
            return;
        }
        self.maps_tried = true;
        self.maps = ProcMaps::parse(self.target_pid);
        self.last_maps_ns = now_ns;
    }

    fn reparse_maps(&mut self, now_ns: u64) {
        if now_ns.wrapping_sub(self.last_maps_ns) < 1_000_000_000 {
            return;
        }
        self.last_maps_ns = now_ns;
        if let Some(fresh) = ProcMaps::parse(self.target_pid) {
            self.maps = Some(fresh);
        }
    }

    /// Resolve a data address to its memory-region label (owned copy).
    fn data_region_label(&mut self, addr: u64, now_ns: u64) -> Vec<u8> {
        if addr > USER_ADDR_MAX {
            return b"[kernel]".to_vec();
        }
        if self.data_regions.is_none() {
            self.data_regions = DataRegions::parse(self.target_pid);
            if self.data_regions.is_none() {
                return b"[unmapped]".to_vec();
            }
            self.last_data_parse_ns = now_ns;
        }
        if let Some(r) = self.data_regions.as_ref().and_then(|dr| dr.find(addr)) {
            return r.label.as_bytes().to_vec();
        }
        if now_ns.wrapping_sub(self.last_data_parse_ns) > 100_000_000 {
            self.last_data_parse_ns = now_ns;
            if let Some(fresh) = DataRegions::parse(self.target_pid) {
                self.data_regions = Some(fresh);
                if let Some(r) = self.data_regions.as_ref().and_then(|dr| dr.find(addr)) {
                    return r.label.as_bytes().to_vec();
                }
            }
        }
        b"[unmapped]".to_vec()
    }

    /// Intern the sample's full callstack (user leaf-first reversed to root-
    /// first, then kernel above), returning the callstack iid (0 if empty).
    fn intern_callstack(&mut self, rec: &SismoSampleRec, idw: &mut ProtoWriter) -> u64 {
        let mut combined: Vec<u64> = Vec::new();

        self.ensure_maps(rec.hdr.ts);
        if self.maps.is_some() {
            let nr = (rec.hdr.nr_frames as usize).min(SISMO_MAX_STACK);
            let mut fids: Vec<u64> = Vec::new();
            let mut reparsed = false;
            for i in 0..nr {
                let pc = rec.stack[i];
                if pc == 0 {
                    continue;
                }
                // First lookup; on a miss, reparse once (the binary may have
                // dlopen'd since) and retry. The reparse needs `&mut self.maps`,
                // so this probe must not hold a borrow of it.
                if self.maps.as_ref().and_then(|m| m.find(pc)).is_none() && !reparsed {
                    reparsed = true;
                    self.reparse_maps(rec.hdr.ts);
                }
                let Some(m) = self.maps.as_ref().and_then(|mp| mp.find(pc)) else {
                    continue;
                };
                let mapping_iid = self.interner.intern_mapping(
                    m.start,
                    m.end,
                    m.offset,
                    m.base_avma,
                    m.path.as_bytes(),
                    &m.build_id,
                    idw,
                );
                let frame_iid = self.interner.intern_frame(
                    FrameKey { mapping_iid, rel_pc: pc, name_iid: 0 },
                    idw,
                );
                fids.push(frame_iid);
            }
            fids.reverse();
            combined.extend_from_slice(&fids);
        }

        let knr = (rec.hdr.nr_kernel_frames as usize).min(SISMO_MAX_KERNEL_STACK);
        if knr > 0 {
            let mut kfids: Vec<u64> = Vec::new();
            let mut kmap = 0u64;
            for i in 0..knr {
                let id = rec.kernel_ids[i];
                if id == 0 {
                    continue;
                }
                if kmap == 0 {
                    kmap = self.interner.intern_kernel_mapping(idw);
                }
                let name = self
                    .ksym_names
                    .get(&id)
                    .cloned()
                    .unwrap_or_else(|| b"[kernel]".to_vec());
                let name_iid = self.interner.intern_func_name(&name, idw);
                let frame_iid = self
                    .interner
                    .intern_frame(FrameKey { mapping_iid: kmap, rel_pc: 0, name_iid }, idw);
                kfids.push(frame_iid);
            }
            kfids.reverse();
            combined.extend_from_slice(&kfids);
        }

        if combined.is_empty() {
            return 0;
        }
        self.interner.intern_callstack_ids(&combined, idw)
    }

    fn emit_defaults(&mut self) {
        let mut followers: Vec<&[u8]> = Vec::new();
        let mut timebase_name: &[u8] = b"cpu-clock";
        if !self.active_slots.is_empty() {
            timebase_name = self.counters[self.active_slots[0] as usize].name.as_bytes();
            for &slot in &self.active_slots[1..] {
                followers.push(self.counters[slot as usize].name.as_bytes());
            }
        }
        let packet = crate::proto::encode_perf_defaults_packet(
            timebase_name,
            0,
            &followers,
            SAMPLE_SCOPE_THREAD,
            BUILTIN_CLOCK_MONOTONIC,
            SEQ_INCREMENTAL_STATE_CLEARED,
        );
        unsafe { sismo_ds_emit(self.ds_slot, packet.as_ptr(), packet.len()) };
    }

    fn emit_sample(&mut self, rec: &SismoSampleRec) {
        let mut idw = ProtoWriter::new();
        let cs_iid = self.intern_callstack(rec, &mut idw);

        // Project the cumulative counters onto the active set.
        let mut follower_buf = [0u64; SISMO_MAX_COUNTERS];
        let mut nf = 0usize;
        let mut timebase_count = 0u64;
        if !self.active_slots.is_empty() {
            timebase_count = rec.counters[self.active_slots[0] as usize];
            for &slot in &self.active_slots[1..] {
                follower_buf[nf] = rec.counters[slot as usize];
                nf += 1;
            }
        }

        // Cache focus: resolve the sampled access's data address to its region.
        let mut data_address = 0u64;
        let mut data_symbol: Option<Vec<u8>> = None;
        if self.focus == Some(FocusPreset::Cache) && rec.data_addr != 0 {
            data_address = rec.data_addr;
            data_symbol = Some(self.data_region_label(rec.data_addr, rec.hdr.ts));
            self.data_frames += 1;
        }

        let mut ps_buf = [0u8; 8192];
        let (ds_ptr, ds_len) = match &data_symbol {
            Some(s) => (s.as_ptr(), s.len()),
            None => (std::ptr::null(), 0),
        };
        let ps_len = unsafe {
            sismo_encode_perf_sample(
                rec.hdr.cpu,
                rec.hdr.pid,
                rec.hdr.tid,
                cs_iid,
                timebase_count,
                if nf > 0 { follower_buf.as_ptr() } else { std::ptr::null() },
                nf,
                data_address,
                ds_ptr,
                ds_len,
                ps_buf.as_mut_ptr(),
                ps_buf.len(),
            )
        };
        if ps_len == 0 {
            return;
        }

        // TracePacket { timestamp, sequence_flags, interned_data?, perf_sample }.
        let mut tp = ProtoWriter::new();
        tp.write_uint64(8, rec.hdr.ts);
        tp.write_uint32(13, SEQ_NEEDS_INCREMENTAL_STATE);
        if !idw.bytes().is_empty() {
            tp.write_message(12, idw.bytes());
        }
        tp.write_message(TP_FIELD_PERF_SAMPLE, &ps_buf[..ps_len]);
        unsafe { sismo_ds_emit(self.ds_slot, tp.bytes().as_ptr(), tp.bytes().len()) };
    }

    fn handle(&mut self, hdr: &SismoHdr) {
        if hdr.r#type == SISMO_EVT_KSYM {
            let rec = unsafe { &*(hdr as *const SismoHdr as *const SismoKsymRec) };
            self.handle_ksym(rec);
            return;
        }
        if hdr.r#type != SISMO_EVT_SAMPLE {
            return;
        }
        self.samples += 1;
        let rec = unsafe { &*(hdr as *const SismoHdr as *const SismoSampleRec) };
        self.acc.insert(hdr.tid, rec.counters[0]);

        if !self.active.load(Ordering::Acquire) {
            return;
        }
        if self.need_defaults.swap(false, Ordering::AcqRel) {
            self.interner.reset();
            self.emit_defaults();
        }
        self.emit_sample(rec);
    }

    fn handle_ksym(&mut self, rec: &SismoKsymRec) {
        if self.ksym_names.contains_key(&rec.id) {
            return;
        }
        // NUL-terminated, strip a trailing "+0xoff/0xsize".
        let raw: &[u8] =
            unsafe { std::slice::from_raw_parts(rec.name.as_ptr() as *const u8, SISMO_KSYM_NAME_MAX) };
        let mut name = &raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())];
        if let Some(p) = name.iter().position(|&b| b == b'+') {
            name = &name[..p];
        }
        self.ksym_names.insert(rec.id, name.to_vec());
    }
}

// ---- init / worker / DS lifecycle / C ABI ----------------------------------

use crate::worker_sdk::{sismo_ds_register, sismo_flush_done, sismo_stop_done};
use std::ptr;
use std::time::Duration;

/// Kernel-side BPF object, compiled by the sismo-sys crate (Linux only).
use sismo_sys::BPF_OBJ;
const DS_NAME: &[u8] = b"sismo.linux_cpu_samples";

/// Recording stats handed back to the record runner (matches cmd_record).
#[repr(C)]
pub struct LinuxBpfStats {
    pub samples: u64,
    pub threads: u64,
    pub busiest_cycles: u64,
    pub data_frames: u64,
}

fn preset_name(p: FocusPreset) -> &'static str {
    match p {
        FocusPreset::Cache => "cache",
    }
}

// A raw Capture pointer smuggled into the worker thread. The Capture is heap-
// stable for the collector's lifetime and the worker is the sole owner of its
// non-atomic fields between ring_buffer callbacks, so the crossing is sound.
struct SendPtr(*mut Capture);
unsafe impl Send for SendPtr {}

extern "C" fn on_setup(_user: *mut c_void, _cfg: *const c_void, _cfg_len: usize) {}

extern "C" fn on_start(user: *mut c_void) {
    let c = unsafe { &*(user as *mut Capture) };
    c.need_defaults.store(true, Ordering::Release);
    c.active.store(true, Ordering::Release);
}

extern "C" fn on_stop(user: *mut c_void, stopper: *mut c_void) {
    let c = unsafe { &*(user as *mut Capture) };
    if stopper.is_null() {
        c.active.store(false, Ordering::Release);
    } else {
        c.stop_req.store(stopper as usize, Ordering::Release);
    }
}

extern "C" fn on_flush(user: *mut c_void, flusher: *mut c_void) {
    let c = unsafe { &*(user as *mut Capture) };
    if !flusher.is_null() {
        c.flush_req.store(flusher as usize, Ordering::Release);
    }
}

unsafe extern "C" fn on_event(ctx: *mut c_void, data: *mut c_void, _size: usize) -> c_int {
    let c = &mut *(ctx as *mut Capture);
    let hdr = &*(data as *const SismoHdr);
    c.handle(hdr);
    0
}

/// Drain a pending flush/stop ack requested by the tracing thread. Runs on the
/// worker so the final ring-buffer records are emitted before we ack.
fn service_acks(cap: *mut Capture) {
    let c = unsafe { &*cap };
    let fh = c.flush_req.swap(0, Ordering::AcqRel);
    if fh != 0 {
        unsafe { ring_buffer__consume(c.rb) };
        unsafe { sismo_flush_done(fh as *mut c_void) };
    }
    let sh = c.stop_req.swap(0, Ordering::AcqRel);
    if sh != 0 {
        unsafe { ring_buffer__consume(c.rb) };
        c.active.store(false, Ordering::Release);
        unsafe { sismo_stop_done(sh as *mut c_void) };
    }
}

fn worker_entry(cap: *mut Capture) {
    let exit = unsafe { &(*cap).exit_requested };
    let rb = unsafe { (*cap).rb };
    while !exit.load(Ordering::Acquire) {
        unsafe { ring_buffer__consume(rb) };
        service_acks(cap);
        std::thread::sleep(Duration::from_millis(20));
    }
    unsafe { ring_buffer__consume(rb) };
    service_acks(cap);
}

fn map_fd(obj: *mut BpfObject, name: &std::ffi::CStr) -> Option<c_int> {
    let m = unsafe { bpf_object__find_map_by_name(obj, name.as_ptr()) };
    if m.is_null() {
        return None;
    }
    Some(unsafe { bpf_map__fd(m) })
}

fn capture_init(pid: u32, focus: Option<FocusPreset>, density: Option<f64>) -> *mut Capture {
    let cap = Box::into_raw(Box::new(Capture {
        obj: ptr::null_mut(),
        rb: ptr::null_mut(),
        links: Vec::new(),
        perf_fds: Vec::new(),
        worker: None,
        exit_requested: AtomicBool::new(false),
        acc: HashMap::new(),
        samples: 0,
        target_pid: pid,
        maps: None,
        maps_tried: false,
        last_maps_ns: 0,
        interner: Interner::new(),
        ksym_names: HashMap::new(),
        counters: Vec::new(),
        active_slots: Vec::new(),
        focus,
        data_regions: None,
        last_data_parse_ns: 0,
        data_frames: 0,
        sampler_precise_ip: 0,
        ds_slot: u32::MAX,
        active: AtomicBool::new(false),
        need_defaults: AtomicBool::new(false),
        flush_req: AtomicUsize::new(0),
        stop_req: AtomicUsize::new(0),
    }));
    let c = unsafe { &mut *cap };
    c.counters = select_counters();

    let mut desc = [0u8; 2048];
    let desc_len = unsafe {
        crate::session_config::sismo_encode_data_source_descriptor(
            DS_NAME.as_ptr(),
            DS_NAME.len(),
            false,
            false,
            ptr::null(),
            0,
            desc.as_mut_ptr(),
            desc.len(),
        )
    };
    if desc_len == 0 {
        drop(unsafe { Box::from_raw(cap) });
        return ptr::null_mut();
    }
    let slot = unsafe {
        sismo_ds_register(
            desc.as_ptr(),
            desc_len,
            on_setup,
            on_start,
            on_stop,
            on_flush,
            cap as *mut c_void,
        )
    };
    if slot == u32::MAX {
        drop(unsafe { Box::from_raw(cap) });
        return ptr::null_mut();
    }
    c.ds_slot = slot;

    let obj = unsafe { bpf_object__open_mem(BPF_OBJ.as_ptr() as *const c_void, BPF_OBJ.len(), ptr::null()) };
    if obj.is_null() {
        drop(unsafe { Box::from_raw(cap) });
        return ptr::null_mut();
    }
    if unsafe { bpf_object__load(obj) } != 0 {
        unsafe { bpf_object__close(obj) };
        drop(unsafe { Box::from_raw(cap) });
        return ptr::null_mut();
    }
    c.obj = obj;

    let (counters_fd, cfg_fd, events_fd) = match (
        map_fd(obj, c"counters_pe"),
        map_fd(obj, c"cfg"),
        map_fd(obj, c"events"),
    ) {
        (Some(a), Some(b), Some(d)) => (a, b, d),
        _ => {
            unsafe { bpf_object__close(obj) };
            drop(unsafe { Box::from_raw(cap) });
            return ptr::null_mut();
        }
    };

    let max_cpus = SISMO_MAX_CPUS as u32;
    let ncpu = (unsafe { libbpf_num_possible_cpus() } as u32).min(max_cpus);
    let counters = c.counters.clone();
    let mut opened = [false; SISMO_MAX_COUNTERS];
    if !counters.is_empty() {
        for cpu in 0..ncpu {
            let mut group_leader: i32 = -1;
            let mut cur_group = counters[0].group;
            for (cslot, ctr) in counters.iter().enumerate() {
                if ctr.group != cur_group {
                    cur_group = ctr.group;
                    group_leader = -1;
                }
                let fd = match open_counter(cpu, ctr.src, group_leader) {
                    Some(f) => f,
                    None => continue,
                };
                if group_leader == -1 {
                    group_leader = fd;
                }
                c.perf_fds.push(fd);
                let idx: u32 = (cslot as u32) * max_cpus + cpu;
                let fd_u = fd as u32;
                unsafe {
                    bpf_map_update_elem(
                        counters_fd,
                        &idx as *const u32 as *const c_void,
                        &fd_u as *const u32 as *const c_void,
                        0,
                    )
                };
                if cpu == 0 {
                    opened[cslot] = true;
                }
            }
        }
    }
    for (cslot, &on) in opened.iter().enumerate() {
        if on {
            c.active_slots.push(cslot as u8);
        }
    }

    let zero: u32 = 0;
    unsafe {
        bpf_map_update_elem(
            cfg_fd,
            &zero as *const u32 as *const c_void,
            &pid as *const u32 as *const c_void,
            0,
        )
    };

    let ss = unsafe { bpf_object__find_program_by_name(obj, c"on_sched_switch".as_ptr()) };
    if !ss.is_null() {
        let link = unsafe { bpf_program__attach(ss) };
        if !link.is_null() {
            c.links.push(link);
        }
    }

    let sampler_cfg = resolve_sampler(focus, density);
    if sampler_cfg.is_none() {
        if let Some(p) = focus {
            eprintln!(
                "sismo record: --focus {}: leader event unavailable on this CPU (model not in the PMU table); no CPU samples recorded",
                preset_name(p)
            );
        }
    }
    let tick_prog = unsafe { bpf_object__find_program_by_name(obj, c"on_tick".as_ptr()) };
    if let Some(scfg) = &sampler_cfg {
        if !tick_prog.is_null() {
            let mut any = false;
            for cpu in 0..ncpu {
                if let Some(h) = open_sampler(cpu, scfg, tick_prog) {
                    c.links.push(h.link);
                    c.perf_fds.push(h.fd);
                    if !any || h.precise_ip < c.sampler_precise_ip {
                        c.sampler_precise_ip = h.precise_ip;
                    }
                    any = true;
                }
            }
            if focus.is_some() && any && c.sampler_precise_ip < scfg.precise_ip {
                eprintln!(
                    "sismo record: focus sampler could not get PEBS (precise_ip {} < {}); samples will skid",
                    c.sampler_precise_ip, scfg.precise_ip
                );
            }
        }
    }

    c.rb = unsafe { ring_buffer__new(events_fd, on_event, cap as *mut c_void, ptr::null()) };
    if c.rb.is_null() {
        // Undo attaches + fds, then free. Worker never started.
        for &l in &c.links {
            unsafe { bpf_link__destroy(l) };
        }
        for &fd in &c.perf_fds {
            unsafe { close(fd) };
        }
        unsafe { bpf_object__close(obj) };
        drop(unsafe { Box::from_raw(cap) });
        return ptr::null_mut();
    }

    let send = SendPtr(cap);
    c.worker = Some(std::thread::spawn(move || {
        let send = send;
        worker_entry(send.0)
    }));
    cap
}

/// Start the Linux CPU collector for `pid`, or None if init failed. The worker
/// thread keeps a raw pointer into the returned box for its lifetime, so the box
/// must live until [`Capture::shutdown`] (which joins the worker first).
pub fn init(pid: u32, focus: Option<FocusPreset>, density: Option<f64>) -> Option<Box<Capture>> {
    let p = capture_init(pid, focus, density);
    if p.is_null() {
        None
    } else {
        // capture_init handed off ownership via Box::into_raw; reclaim it.
        Some(unsafe { Box::from_raw(p) })
    }
}

impl Capture {
    /// The lowest precise_ip the samplers actually got (2 = full PEBS).
    pub fn precise_ip(&self) -> u8 {
        self.sampler_precise_ip
    }

    /// Stop the worker, tear down BPF, and return the run stats. Consumes self.
    pub fn shutdown(mut self: Box<Self>) -> LinuxBpfStats {
        self.exit_requested.store(true, Ordering::Release);
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
        let stats = LinuxBpfStats {
            samples: self.samples,
            threads: self.acc.len() as u64,
            busiest_cycles: self.acc.values().copied().max().unwrap_or(0),
            data_frames: self.data_frames,
        };
        // The worker has joined, so the raw-pointer aliasing is over.
        unsafe {
            if !self.rb.is_null() {
                ring_buffer__free(self.rb);
            }
            for &l in &self.links {
                bpf_link__destroy(l);
            }
            for &fd in &self.perf_fds {
                close(fd);
            }
            if !self.obj.is_null() {
                bpf_object__close(self.obj);
            }
        }
        stats
        // maps / data_regions dropped with self.
    }
}
