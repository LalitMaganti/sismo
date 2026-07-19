// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Linux BPF CPU collector. Per-thread PMU counters + timer-tick stack sampling,
//! scoped to the workload, emitted as thread-scoped Perfetto PerfSamples.

use std::os::raw::{c_char, c_int, c_void};

// ---- wire format (mirrors src/c/sismo_bpf/sismo_bpf.h) ---------------------

pub const SISMO_MAX_CPUS: usize = 256;
pub const SISMO_MAX_STACK: usize = 64;
pub const SISMO_MAX_KERNEL_STACK: usize = 64;
pub const SISMO_MAX_PY_FRAMES: usize = 16;
pub const SISMO_KSYM_NAME_MAX: usize = 96;
pub const SISMO_PY_NAME_MAX: usize = 128;
pub const SISMO_MAX_COUNTERS: usize = 12;

pub const SISMO_EVT_SAMPLE: u32 = 0;
pub const SISMO_EVT_KSYM: u32 = 1;
pub const SISMO_EVT_OFFCPU: u32 = 2;
pub const SISMO_EVT_FILE: u32 = 3;
pub const SISMO_EVT_SAMPLE_UNWIND: u32 = 4;
pub const SISMO_EVT_PYFRAME: u32 = 5;
pub const SISMO_EVT_MODULE: u32 = 6;

/// Bytes of a module's mapped-image prefix in `SismoModuleRec` (one page).
pub const SISMO_MODULE_PREFIX: usize = 4096;

/// Bytes of the raw user-stack snapshot in `SismoUnwindRec` (perf's default
/// PERF_SAMPLE_STACK_USER size).
pub const SISMO_STACK_SNAP_MAX: usize = 8192;

// block_id (off-CPU slot 0) tag bits: which kind of thing the block waits on.
const BLOCK_ID_NET: u64 = 1 << 63; // TCP peer (rest of the bits: packed 5-tuple)
const BLOCK_ID_FILE: u64 = 1 << 62; // interned file id (low bits)

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
    pub nr_py_frames: u32, // CAP-1; fills the former pad before `ts`
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
    pub py_ids: [u32; SISMO_MAX_PY_FRAMES], // CAP-1: Python frame-name ids, leaf-first
}

/// SISMO_EVT_SAMPLE_UNWIND. Composes `SismoSampleRec` verbatim (byte-identical
/// leading bytes) plus the user pt_regs at sample time and a bounded raw copy
/// of the user stack from the captured stack pointer — captured for a later
/// host-side DWARF-unwind step. Not yet consumed: today's processing runs the
/// embedded `sample` through the exact same path as SISMO_EVT_SAMPLE.
#[repr(C)]
pub struct SismoUnwindRec {
    pub sample: SismoSampleRec,
    pub regs_ip: u64,
    pub regs_sp: u64,
    pub regs_bp: u64,
    pub stack_len: u32,
    pub stack_trunc: u32,
    pub stack_bytes: [u8; SISMO_STACK_SNAP_MAX],
}

/// SISMO_EVT_KSYM. One-time (id -> resolved name) mapping.
#[repr(C)]
pub struct SismoKsymRec {
    pub r#type: u32,
    pub id: u32,
    pub name: [c_char; SISMO_KSYM_NAME_MAX],
}

/// SISMO_EVT_PYFRAME. One-time (id -> CPython qualname) mapping (CAP-1).
#[repr(C)]
pub struct SismoPyframeRec {
    pub r#type: u32,
    pub id: u32,
    pub name: [c_char; SISMO_PY_NAME_MAX],
}

/// SISMO_EVT_MODULE. A module's image base + the first mapped page of its image,
/// read from the target in-band at sample time (CAP-2); the host parses the
/// build-id from `prefix`.
#[repr(C)]
pub struct SismoModuleRec {
    pub r#type: u32,
    pub prefix_len: u32,
    pub base: u64,
    pub prefix: [u8; SISMO_MODULE_PREFIX],
}

/// CAP-1 config pushed into the BPF `py_cfg` map: `_PyRuntime` avma + the
/// `_Py_DebugOffsets` field offsets the in-BPF interpreter walk reads. Mirrors
/// `struct sismo_py_cfg`. `runtime == 0` disables the walk.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SismoPyCfg {
    pub runtime: u64,
    pub interpreters_head: u64,
    pub threads_head: u64,
    pub current_frame: u64,
    pub frame_previous: u64,
    pub frame_executable: u64,
    pub code_qualname: u64,
    pub unicode_length: u64,
    pub unicode_data: u64,
}

// ---- libbpf (system -lbpf, from bpf/libbpf.h) -----------------------------

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

// ---- PMU counter selection ------------------------------------------------

use crate::cpu::pmu_events::{Model, Role, MODELS};

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
        return rhs.split_whitespace().next()?.parse().ok();
    }
    None
}

// slots fixed counter + PERF_METRICS Top-Down present (CPUID leaf 0x0A, v>=5
// with fixed-counter-3 in the ECX support bitmap). Same signal perf uses.
#[cfg(target_arch = "x86_64")]
fn topdown_enumerated() -> bool {
    let r = std::arch::x86_64::__cpuid_count(0x0A, 0);
    let version = r.eax & 0xff;
    version >= 5 && (r.ecx & (1 << 3)) != 0
}
#[cfg(not(target_arch = "x86_64"))]
fn topdown_enumerated() -> bool {
    false
}

// vvvvv TEMPORARY HACK — delete once TMA is validated
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
    let hyp = std::arch::x86_64::__cpuid_count(1, 0);
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

// ---- focus presets ---------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
pub enum FocusPreset {
    Cache,
}

enum Leader {
    // Cycles-leader sampler path: `open_focus_sampler` handles it, but no
    // `FocusPreset` constructs it yet (the planned stalls preset would). Kept as
    // the wired integration point, not deleted — see sismo_focus_mode.
    #[allow(dead_code)]
    Cycles,
    Role(Role),
}

struct FocusSpec {
    leader: Leader,
    precise_ip: u8, // u2
    period: u64,
    sample_data_addr: bool,
}

impl FocusPreset {
    pub fn from_name(name: &[u8]) -> Option<FocusPreset> {
        match name {
            b"cache" => Some(FocusPreset::Cache),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            FocusPreset::Cache => "cache",
        }
    }

    fn spec(self) -> FocusSpec {
        match self {
            // Sample on retired loads that missed L3 (precise, carries Data_LA).
            FocusPreset::Cache => FocusSpec {
                leader: Leader::Role(Role::l3_miss_load),
                precise_ip: 2,
                period: 2003,
                sample_data_addr: true,
            },
        }
    }
}

// ---- perf_event_open (port of openCounter / resolveSampler / openSampler) ---

use libc::close;
use perf_event_open_sys as sys;

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
    let s = p.spec();
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
            attr.sample_type |= sys::bindings::PERF_SAMPLE_CALLCHAIN;
        }
        // Data_LA only resolves on a precise event.
        if cfg.sample_data_addr && want > 0 {
            attr.sample_type |= sys::bindings::PERF_SAMPLE_ADDR;
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

// ---- InternedData interner -------------------------------------------------

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
    // CAP-2: enough of each interned mapping to re-emit its definition, keyed by
    // image base. When the in-band module record lands after the mapping was
    // already interned with a synthetic build-id, we re-emit the same iid with
    // the real one — the build-id lives on the mapping, so every sample that
    // references it resolves to the corrected id. (iid, start, end, offset, path_iid)
    mapping_reemit: HashMap<u64, Vec<(u64, u64, u64, u64, u64)>>,
    // The build-id each base was interned with, so re-emit is skipped when the
    // in-band id matches what the host read already supplied (the live-binary case).
    mapping_reemit_bid: HashMap<u64, Vec<u8>>,
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
        idw.message(field, |s| {
            s.write_uint64(1, iid);
            s.write_string(2, bytes);
        });
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
    #[allow(clippy::too_many_arguments)]
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
        idw.message(19, |mp| {
            mp.write_uint64(1, iid);
            if build_id_iid != 0 {
                mp.write_uint64(2, build_id_iid);
            }
            mp.write_uint64(4, start);
            mp.write_uint64(5, end);
            mp.write_uint64(6, base_avma);
            mp.write_uint64(8, offset);
            mp.write_uint64(7, path_iid);
        });
        self.mapping_reemit
            .entry(base_avma)
            .or_default()
            .push((iid, start, end, offset, path_iid));
        self.mapping_reemit_bid.insert(base_avma, build_id.to_vec());
        iid
    }

    /// CAP-2: re-emit every mapping sharing `base` with `build_id`, reusing the
    /// original iid so trace_processor rebinds the build-id on the existing
    /// mapping. Called when the in-band module record arrives after the mapping
    /// was interned with a synthetic id. Returns whether anything was emitted.
    fn reemit_build_id(&mut self, base: u64, build_id: &[u8], idw: &mut ProtoWriter) -> bool {
        if self.mapping_reemit_bid.get(&base).map(|b| b.as_slice()) == Some(build_id) {
            return false; // host read already interned this id — nothing to correct
        }
        let params = match self.mapping_reemit.get(&base) {
            Some(p) if !p.is_empty() => p.clone(),
            _ => return false,
        };
        let build_id_iid = self.intern_build_id(build_id, idw);
        for (iid, start, end, offset, path_iid) in params {
            idw.message(19, |mp| {
                mp.write_uint64(1, iid);
                mp.write_uint64(2, build_id_iid);
                mp.write_uint64(4, start);
                mp.write_uint64(5, end);
                mp.write_uint64(6, base);
                mp.write_uint64(8, offset);
                mp.write_uint64(7, path_iid);
            });
        }
        true
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
        idw.message(19, |mp| {
            mp.write_uint64(1, iid);
            mp.write_uint64(7, path_iid);
        });
        iid
    }

    /// A synthetic mapping for a residual-frame label (`[jit:node]`,
    /// `[anon-exec]`, `[anon]`, `[unmapped]`), keyed by the label so each is
    /// interned once. Like the kernel mapping it carries only a path, so the
    /// frame renders as the label.
    fn intern_residual_mapping(&mut self, label: &[u8], idw: &mut ProtoWriter) -> u64 {
        // Path strings are interned by bytes, so an already-seen label returns
        // the same path iid; guard the mapping itself on that iid.
        let path_iid = self.intern_path(label, idw);
        // Reuse the mappings map keyed by a sentinel derived from the path iid
        // (path iids are >=1 and never collide with real mapping starts, which
        // are page-aligned user addresses, nor with the kernel sentinel 0).
        let key = u64::MAX - path_iid;
        if let Some(&iid) = self.mappings.get(&key) {
            return iid;
        }
        let iid = self.next_mapping;
        self.next_mapping += 1;
        self.mappings.insert(key, iid);
        idw.message(19, |mp| {
            mp.write_uint64(1, iid);
            mp.write_uint64(7, path_iid);
        });
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
        idw.message(6, |f| {
            f.write_uint64(1, iid);
            if key.name_iid != 0 {
                f.write_uint64(2, key.name_iid);
            }
            f.write_uint64(3, key.mapping_iid);
            f.write_uint64(4, key.rel_pc);
        });
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
        idw.message(7, |cs| {
            cs.write_uint64(1, iid);
            for &fid in fids {
                cs.write_uint64(2, fid);
            }
        });
        iid
    }
}

// ---- Capture: the collector object (output half) ---------------------------

use crate::cpu::module_registry::{KeepPolicy, ModuleRegistry};
use crate::symbolize::data_regions::DataRegions;
use crate::symbolize::gopclntab::GoPclntab;
use crate::symbolize::proc_maps::{ProcMaps, ResidualMap};
use crate::symbolize::python_offsets::PyDebugOffsets;
use crate::symbolize::unwinder::{StackRegs, Unwinder};
use crate::ffi::{sismo_ds_emit, sismo_ds_emit_offcpu};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// TracePacket / defaults field tags + constants.
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
    // Full-address-space view (incl. anon/[vdso]) for labeling residual PCs that
    // fall outside any file-backed mapping (DIA-6). Built alongside `maps`.
    residual_map: Option<ResidualMap>,
    maps_tried: bool,
    last_maps_ns: u64,
    interner: Interner,
    // The off-CPU stream is a second perf sequence with its own timebase, so it
    // interns into its own iid space.
    offcpu_interner: Interner,
    ksym_names: HashMap<u32, Vec<u8>>, // id -> bare function name
    file_names: HashMap<u32, Vec<u8>>, // interned file id -> base name
    py_names: HashMap<u32, Vec<u8>>,   // CAP-1: id -> Python qualname
    py_cfg_fd: c_int,                  // CAP-1: fd of the py_cfg BPF map (-1 if absent)
    python_bpf: bool,                  // CAP-1: in-BPF walk armed (py_cfg pushed)
    bpf_build_ids: HashMap<u64, Vec<u8>>, // CAP-2: base avma -> in-band build-id
    // CAP-3(b): the module files this recording sampled. Per policy it holds an
    // fd open to each (from first sight to the post-record symbolize pass) so a
    // binary deleted or rebuilt mid-run still resolves via /proc/self/fd. Handed
    // out by `shutdown` so its fds outlive the capture until symbolization runs.
    modules: ModuleRegistry,
    counters: Vec<Counter>,
    active_slots: Vec<u8>, // indices into `counters`; [0] is the timebase
    focus: Option<FocusPreset>,
    data_regions: Option<DataRegions>,
    last_data_parse_ns: u64,
    data_frames: u64,
    offcpu_samples: u64,
    offcpu_ns: u64,
    // NAT-1: count of SISMO_EVT_SAMPLE_UNWIND records seen, for the
    // SISMO_DEBUG_UNWIND verification hook.
    unwind_snapshots: u64,
    // NAT-1 host-side DWARF unwinder (framehop, x86-64/ELF) fed the captured
    // regs + stack snapshot, plus the set of module base avmas already
    // registered into it. Built lazily on the first unwind sample.
    unwinder: Option<Unwinder>,
    unwind_registered: HashSet<u64>,
    // NAT-1b: per-module Go unwinders (base avma -> parsed .gopclntab, None when
    // the module isn't Go / didn't parse). Go carries no .eh_frame, so framehop
    // can't unwind it; this walks Go frames from the pcsp frame-size tables.
    go_unwinders: HashMap<u64, Option<GoPclntab>>,
    // JIT-1: the target's JIT symbol map (`/tmp/perf-<pid>.map`, e.g. node
    // --perf-basic-prof), sorted by start address, mapping an anon-exec JIT PC
    // to its runtime method name. None until first loaded; empty when absent.
    jit_syms: Option<Vec<(u64, u64, String)>>,
    jit_map_size: u64,
    // PY-1: `_PyRuntime`'s runtime address + parsed `_Py_DebugOffsets`,
    // located and parsed once per run (the layout never changes for a live
    // interpreter). `python_tried` gates the one-time locate/parse attempt;
    // `python_runtime` stays None when the target isn't Python 3.14, or the
    // locate/parse failed.
    python_tried: bool,
    python_runtime: Option<(u64, PyDebugOffsets)>,
    python_debug_count: u64,
    sampler_precise_ip: u8,
    ds_slot: u32,
    active: AtomicBool,
    need_defaults: AtomicBool,
    offcpu_need_defaults: AtomicBool,
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
        self.residual_map = ResidualMap::parse(self.target_pid);
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
        // JIT code is mmap'd late and churns, so refresh the residual view too.
        if let Some(fresh) = ResidualMap::parse(self.target_pid) {
            self.residual_map = Some(fresh);
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
    /// Intern a sample's callstack. `user_pcs` are the leaf-first user PCs —
    /// either the BPF frame-pointer walk (`rec.stack`) or, for a NAT-1 unwind
    /// sample, framehop's DWARF-recovered return addresses. Kernel frames come
    /// from `rec.kernel_ids` regardless.
    fn intern_callstack(
        &mut self,
        user_pcs: &[u64],
        rec: &SismoSampleRec,
        idw: &mut ProtoWriter,
    ) -> u64 {
        let mut combined: Vec<u64> = Vec::new();

        self.ensure_maps(rec.hdr.ts);
        if self.maps.is_some() {
            let mut fids: Vec<u64> = Vec::new();

            // PY-1: splice in the live-recovered Python call chain, leaf
            // first, ahead of the native frames below — reversed together
            // with them, this lands Python as the leaf-most frames (CPython
            // 3.11+ runs the bytecode loop without one native frame per
            // Python call, so the FP walk alone never sees these).
            if self.residual_map.as_ref().and_then(|r| r.runtime()) == Some("python") {
                // Arm the in-BPF walk on first sight (idempotent); pushes py_cfg.
                self.ensure_python_runtime();
                // CAP-1: in BPF mode use the frame ids the in-BPF walk attached
                // to this exact sample — no host `/proc/<pid>/mem` walk at all,
                // so nothing is stale and no per-sample memory read happens. A
                // handful of samples captured before py_cfg was armed carry no
                // ids and simply show no Python frames. Only SISMO_PYSTACK_BPF=0
                // takes the legacy host walk.
                let py_frames: Vec<Vec<u8>> = if self.python_bpf {
                    let n = (rec.hdr.nr_py_frames as usize).min(SISMO_MAX_PY_FRAMES);
                    rec.py_ids[..n]
                        .iter()
                        .filter_map(|id| self.py_names.get(id).cloned())
                        .collect()
                } else {
                    self.python_frames().into_iter().map(String::into_bytes).collect()
                };
                if !py_frames.is_empty() {
                    let mapping_iid = self.interner.intern_residual_mapping(b"[python]", idw);
                    for name in &py_frames {
                        let name_iid = self.interner.intern_func_name(name, idw);
                        let frame_iid = self.interner.intern_frame(
                            FrameKey { mapping_iid, rel_pc: 0, name_iid },
                            idw,
                        );
                        fids.push(frame_iid);
                    }
                }
            }

            let mut reparsed = false;
            for &pc in user_pcs {
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
                    // Residual PC: no file-backed mapping. In a process running a
                    // recognized JIT runtime, label and record it (a JIT method in
                    // an anon exec page, etc.) instead of dropping it; a native
                    // process has no runtime, so this is a no-op and its capture
                    // is unchanged.
                    let label = self.residual_map.as_ref().and_then(|r| r.residual_label(pc));
                    if let Some(label) = label {
                        // JIT-1: if the runtime published a symbol map (node
                        // --perf-basic-prof et al.), name the method instead of
                        // recording a bare [jit:*] placeholder.
                        let name = self.jit_name(pc);
                        let mapping_iid =
                            self.interner.intern_residual_mapping(label.as_bytes(), idw);
                        let name_iid = match &name {
                            Some(n) => self.interner.intern_func_name(n.as_bytes(), idw),
                            None => 0,
                        };
                        let frame_iid = self.interner.intern_frame(
                            FrameKey { mapping_iid, rel_pc: pc, name_iid },
                            idw,
                        );
                        fids.push(frame_iid);
                    }
                    continue;
                };
                // CAP-2: prefer the build-id the BPF captured in-band from mapped
                // memory (it matches the file read for a live binary, and is the
                // only real id for one deleted before symbolization).
                let real_id: &[u8] = match self.bpf_build_ids.get(&m.base_avma) {
                    Some(id) => id,
                    None => &m.build_id,
                };
                // CAP-3(b): register this module the first time we see it so its
                // bytes stay reachable (per --keep-module-files policy) if the file
                // is deleted before symbolization. The registry also supplies the
                // effective build-id — a synthetic magic+random one when the module
                // has no GNU note — memoized per (dev,inode) so it is stable.
                let build_id = self.modules.observe(&m.path, real_id);
                let mapping_iid = self.interner.intern_mapping(
                    m.start,
                    m.end,
                    m.offset,
                    m.base_avma,
                    m.path.as_bytes(),
                    &build_id,
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
        let mut w = ProtoWriter::new();
        w.write_perf_defaults_packet(
            timebase_name,
            0,
            &followers,
            SAMPLE_SCOPE_THREAD,
            BUILTIN_CLOCK_MONOTONIC,
            SEQ_INCREMENTAL_STATE_CLEARED,
        );
        unsafe { sismo_ds_emit(self.ds_slot, w.bytes().as_ptr(), w.bytes().len()) };
    }

    fn emit_sample(&mut self, rec: &SismoSampleRec, user_pcs: &[u64]) {
        let mut idw = ProtoWriter::new();
        let cs_iid = self.intern_callstack(user_pcs, rec, &mut idw);

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

        // TracePacket { timestamp, sequence_flags, interned_data?, perf_sample }.
        let mut tp = ProtoWriter::new();
        tp.write_uint64(8, rec.hdr.ts);
        tp.write_uint32(13, SEQ_NEEDS_INCREMENTAL_STATE);
        if !idw.bytes().is_empty() {
            tp.write_message(12, idw.bytes());
        }
        tp.write_perf_sample(
            TP_FIELD_PERF_SAMPLE,
            rec.hdr.cpu,
            rec.hdr.pid,
            rec.hdr.tid,
            cs_iid,
            timebase_count,
            &follower_buf[..nf],
            data_address,
            data_symbol.as_deref(),
        );
        unsafe { sismo_ds_emit(self.ds_slot, tp.bytes().as_ptr(), tp.bytes().len()) };
    }

    // The off-CPU sequence's PerfSampleDefaults: the same thread-scoped setup,
    // but its own timebase (off-cpu-ns) and no follower counters.
    fn emit_offcpu_defaults(&mut self) {
        let mut w = ProtoWriter::new();
        w.write_perf_defaults_packet(
            b"off-cpu-ns",
            0,
            &[],
            SAMPLE_SCOPE_THREAD,
            BUILTIN_CLOCK_MONOTONIC,
            SEQ_INCREMENTAL_STATE_CLEARED,
        );
        unsafe { sismo_ds_emit_offcpu(self.ds_slot, w.bytes().as_ptr(), w.bytes().len()) };
    }

    // Emit an off-CPU sample: the blocking stack, weighted by the off-CPU
    // duration (rec.data_addr) as the timebase count, on the off-CPU sequence.
    // Interning goes into that sequence's own iid space (swap the active
    // interner around the shared intern_callstack).
    fn emit_offcpu_sample(&mut self, rec: &SismoSampleRec) {
        if self.offcpu_need_defaults.swap(false, Ordering::AcqRel) {
            self.offcpu_interner.reset();
            self.emit_offcpu_defaults();
        }

        std::mem::swap(&mut self.interner, &mut self.offcpu_interner);
        let mut idw = ProtoWriter::new();
        let nr = (rec.hdr.nr_frames as usize).min(SISMO_MAX_STACK);
        let user_pcs: Vec<u64> = rec.stack[..nr].to_vec();
        let cs_iid = self.intern_callstack(&user_pcs, rec, &mut idw);
        std::mem::swap(&mut self.interner, &mut self.offcpu_interner);

        let mut tp = ProtoWriter::new();
        tp.write_uint64(8, rec.hdr.ts);
        tp.write_uint32(13, SEQ_NEEDS_INCREMENTAL_STATE);
        if !idw.bytes().is_empty() {
            tp.write_message(12, idw.bytes());
        }
        // For a disk block, slot 0 is a bit-62-tagged file id: resolve it to the
        // file name and ship it as data_symbol (the queryable label), like the
        // cache focus does for a memory region.
        let block_id = rec.counters[0];
        let data_symbol: Option<&[u8]> = if block_id & BLOCK_ID_FILE != 0 {
            let fid = (block_id & 0x3fff_ffff) as u32;
            self.file_names.get(&fid).map(|v| v.as_slice())
        } else {
            None
        };
        tp.write_perf_sample(
            TP_FIELD_PERF_SAMPLE,
            rec.hdr.cpu,
            rec.hdr.pid,
            rec.hdr.tid,
            cs_iid,
            rec.data_addr, // timebase_count = off-CPU duration (ns) = the weight
            &[],
            block_id,     // data_address = block identity (futex uaddr / peer / file id)
            data_symbol,  // set only for disk blocks (the file name)
        );
        unsafe { sismo_ds_emit_offcpu(self.ds_slot, tp.bytes().as_ptr(), tp.bytes().len()) };
    }

    /// Counter/run bookkeeping every sample needs, then whether a session is
    /// active (and defaults emitted) so the caller should emit the sample.
    fn begin_sample(&mut self, rec: &SismoSampleRec) -> bool {
        self.samples += 1;
        self.acc.insert(rec.hdr.tid, rec.counters[0]);
        if !self.active.load(Ordering::Acquire) {
            return false;
        }
        if self.need_defaults.swap(false, Ordering::AcqRel) {
            self.interner.reset();
            self.emit_defaults();
        }
        true
    }

    /// A plain SISMO_EVT_SAMPLE: emit its frame-pointer-walked stack.
    fn process_sample(&mut self, rec: &SismoSampleRec) {
        if !self.begin_sample(rec) {
            return;
        }
        let nr = (rec.hdr.nr_frames as usize).min(SISMO_MAX_STACK);
        let user_pcs: Vec<u64> = rec.stack[..nr].to_vec();
        self.emit_sample(rec, &user_pcs);
    }

    /// A SISMO_EVT_SAMPLE_UNWIND: DWARF-unwind the captured snapshot host-side
    /// and emit that chain instead of the FP walk (falling back to the FP walk
    /// when the snapshot is empty or the unwind doesn't beat it).
    fn process_unwind_sample(&mut self, urec: &SismoUnwindRec) {
        if !self.begin_sample(&urec.sample) {
            return;
        }
        let user_pcs = self.unwind_user_stack(urec);
        self.emit_sample(&urec.sample, &user_pcs);
    }

    /// Framehop-recovered user PCs for an unwind sample, or the FP walk as a
    /// fallback. Empty `stack_len` (a kernel-context sample, or a failed copy)
    /// has no user snapshot to walk; a walk that recovers no more than the FP
    /// walk isn't worth preferring.
    fn unwind_user_stack(&mut self, urec: &SismoUnwindRec) -> Vec<u64> {
        let nr = (urec.sample.hdr.nr_frames as usize).min(SISMO_MAX_STACK);
        let fp: Vec<u64> = urec.sample.stack[..nr].to_vec();
        if urec.stack_len == 0 {
            return fp;
        }
        self.ensure_maps(urec.sample.hdr.ts);
        let sp0 = urec.regs_sp;
        let len = (urec.stack_len as usize).min(SISMO_STACK_SNAP_MAX);
        let bytes = &urec.stack_bytes[..len];
        let read_stack = |addr: u64| -> Option<u64> {
            let off = addr.checked_sub(sp0)? as usize;
            let end = off.checked_add(8)?;
            bytes.get(off..end).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        };

        // Go carries no .eh_frame, so framehop can't unwind it; when the leaf is
        // in a Go module walk it from the pcsp frame-size tables instead. Prefer
        // whichever recovered more than the frame-pointer walk (which truncates
        // on FP-less code), so a module neither can unwind keeps the FP frames.
        if let Some(pcs) = self.go_unwind(urec.regs_ip, sp0, read_stack) {
            if pcs.len() > fp.len() {
                return pcs;
            }
        }

        self.ensure_unwinder();
        let Some(unw) = self.unwinder.as_mut() else {
            return fp;
        };
        let regs = StackRegs {
            pc: urec.regs_ip,
            fp: urec.regs_bp,
            lr: 0,
            sp: sp0,
        };
        let pcs = unw.walk_snapshot(regs, bytes, sp0, SISMO_MAX_STACK);
        if pcs.len() > fp.len() {
            pcs
        } else {
            fp
        }
    }

    /// Go-unwind from the snapshot when `pc` is in a Go module (has a parseable
    /// `.gopclntab`), else `None`. The per-module `GoPclntab` is parsed once and
    /// cached (including the negative result for non-Go modules).
    fn go_unwind(
        &mut self,
        pc: u64,
        sp: u64,
        read_stack: impl FnMut(u64) -> Option<u64>,
    ) -> Option<Vec<u64>> {
        let (base, path) = {
            let m = self.maps.as_ref()?.find(pc)?;
            (m.base_avma, m.path.clone())
        };
        if !self.go_unwinders.contains_key(&base) {
            let parsed = GoPclntab::from_path(&path);
            self.go_unwinders.insert(base, parsed);
        }
        let go = self.go_unwinders.get(&base)?.as_ref()?;
        Some(go.unwind(base, pc, sp, read_stack, SISMO_MAX_STACK))
    }

    /// JIT-1: the runtime method name for an anon-exec PC from the target's
    /// `/tmp/perf-<pid>.map`, or None. The runtime appends to the map as it
    /// compiles (V8 writes builtins at startup, then each JS method when it
    /// tiers up), so reload whenever the file has grown — a load-once would
    /// cache a map taken before the hot methods existed.
    fn jit_name(&mut self, pc: u64) -> Option<String> {
        let size = std::fs::metadata(format!("/tmp/perf-{}.map", self.target_pid))
            .map(|m| m.len())
            .unwrap_or(0);
        if self.jit_syms.is_none() || size != self.jit_map_size {
            self.jit_syms = Some(load_perf_map(self.target_pid));
            self.jit_map_size = size;
        }
        let syms = self.jit_syms.as_ref()?;
        // The last entry whose start is <= pc, if that entry still covers pc.
        let i = syms.partition_point(|&(start, _, _)| start <= pc);
        syms.get(i.checked_sub(1)?)
            .filter(|(start, size, _)| pc < start.wrapping_add(*size))
            .map(|(_, _, name)| name.clone())
    }

    /// Build the host-side unwinder on first use and register every target
    /// module not yet registered (new ones appear as the target dlopen's).
    fn ensure_unwinder(&mut self) {
        if self.unwinder.is_none() {
            self.unwinder = Some(Unwinder::new_x86_64());
        }
        let Some(maps) = self.maps.as_ref() else {
            return;
        };
        let to_add: Vec<(u64, String)> = maps
            .modules()
            .into_iter()
            .filter(|(base, path)| {
                // Anonymous regions ([vdso]/[stack]/…) have no ELF to parse.
                !self.unwind_registered.contains(base) && !path.starts_with('[')
            })
            .map(|(base, path)| (base, path.to_string()))
            .collect();
        for (base, path) in to_add {
            self.unwind_registered.insert(base);
            if let Ok(bytes) = std::fs::read(&path) {
                if let Some(unw) = self.unwinder.as_mut() {
                    unw.add_module(base, &bytes);
                }
            }
        }
    }

    /// Locate + parse `_PyRuntime`'s `_Py_DebugOffsets` once per run, when the
    /// target is running a recognized Python interpreter. A no-op on every
    /// call after the first (whether it succeeded or not) — the layout is
    /// fixed for the life of the interpreter, so there's nothing to refresh.
    fn ensure_python_runtime(&mut self) {
        if self.python_tried {
            return;
        }
        self.python_tried = true;
        if self.residual_map.as_ref().and_then(|r| r.runtime()) != Some("python") {
            return;
        }
        let Some(maps) = self.maps.as_ref() else { return };
        let Some(avma) = crate::symbolize::python_stack::locate_py_runtime(self.target_pid, maps)
        else {
            return;
        };
        let Some(blob) =
            crate::symbolize::python_stack::read_debug_offsets_blob(self.target_pid, avma)
        else {
            return;
        };
        let Some(offs) = crate::symbolize::python_offsets::parse(&blob) else {
            return;
        };

        // CAP-1: push the offsets + _PyRuntime avma into the BPF `py_cfg` map so
        // the in-BPF walk (on_tick) recovers Python frames at sample time, exact
        // and race-free, instead of the host `/proc/<pid>/mem` walk. Gated by
        // SISMO_PYSTACK_BPF (default on); off falls back to the host walk.
        let bpf_walk = std::env::var("SISMO_PYSTACK_BPF").as_deref() != Ok("0");
        if bpf_walk && self.py_cfg_fd >= 0 {
            let cfg = SismoPyCfg {
                runtime: avma,
                interpreters_head: offs.interpreters_head,
                threads_head: offs.threads_head,
                current_frame: offs.current_frame,
                frame_previous: offs.frame_previous,
                frame_executable: offs.frame_executable,
                code_qualname: offs.code_qualname,
                unicode_length: offs.unicode_length,
                unicode_data: offs.unicode_asciiobject_size,
            };
            let zero: u32 = 0;
            let rc = unsafe {
                bpf_map_update_elem(
                    self.py_cfg_fd,
                    &zero as *const u32 as *const c_void,
                    &cfg as *const SismoPyCfg as *const c_void,
                    0,
                )
            };
            self.python_bpf = rc == 0;
        }

        self.python_runtime = Some((avma, offs));
    }

    /// Live-walk the target's Python interpreter frame chain (leaf-first
    /// qualnames), or an empty vec when no Python runtime was located.
    /// Behind `SISMO_DEBUG_PYTHON`, dumps the first few walks' recovered
    /// names to stderr — the debugging hook for a walk that isn't recovering
    /// frames.
    fn python_frames(&mut self) -> Vec<String> {
        self.ensure_python_runtime();
        let Some((avma, offs)) = self.python_runtime else {
            return Vec::new();
        };
        let frames = crate::symbolize::python_stack::walk_python_stack(self.target_pid, avma, &offs);
        if self.python_debug_count < 5 && std::env::var_os("SISMO_DEBUG_PYTHON").is_some() {
            self.python_debug_count += 1;
            eprintln!(
                "sismo: python walk #{} recovered {} frame(s): {:?}",
                self.python_debug_count,
                frames.len(),
                frames
            );
        }
        frames
    }

    fn handle(&mut self, hdr: &SismoHdr) {
        if hdr.r#type == SISMO_EVT_KSYM {
            let rec = unsafe { &*(hdr as *const SismoHdr as *const SismoKsymRec) };
            self.handle_ksym(rec);
            return;
        }
        if hdr.r#type == SISMO_EVT_FILE {
            let rec = unsafe { &*(hdr as *const SismoHdr as *const SismoKsymRec) };
            self.handle_file(rec);
            return;
        }
        if hdr.r#type == SISMO_EVT_PYFRAME {
            let rec = unsafe { &*(hdr as *const SismoHdr as *const SismoPyframeRec) };
            self.handle_pyframe(rec);
            return;
        }
        if hdr.r#type == SISMO_EVT_MODULE {
            let rec = unsafe { &*(hdr as *const SismoHdr as *const SismoModuleRec) };
            self.handle_module(rec);
            return;
        }
        if hdr.r#type == SISMO_EVT_OFFCPU {
            // The blocking stack + off-CPU duration (in data_addr). Emitted onto
            // the off-CPU sequence — same data source, own timebase.
            let rec = unsafe { &*(hdr as *const SismoHdr as *const SismoSampleRec) };
            self.offcpu_samples += 1;
            self.offcpu_ns = self.offcpu_ns.saturating_add(rec.data_addr);
            if self.active.load(Ordering::Acquire) {
                self.emit_offcpu_sample(rec);
            }
            return;
        }
        if hdr.r#type == SISMO_EVT_SAMPLE_UNWIND {
            let rec = unsafe { &*(hdr as *const SismoHdr as *const SismoUnwindRec) };
            self.unwind_snapshots += 1;
            if self.unwind_snapshots <= 3 && std::env::var_os("SISMO_DEBUG_UNWIND").is_some() {
                eprintln!(
                    "sismo: unwind snapshot #{} regs_ip=0x{:x} regs_sp=0x{:x} stack_len={} stack_trunc={}",
                    self.unwind_snapshots, rec.regs_ip, rec.regs_sp, rec.stack_len, rec.stack_trunc
                );
            }
            self.process_unwind_sample(rec);
            return;
        }
        if hdr.r#type != SISMO_EVT_SAMPLE {
            return;
        }
        let rec = unsafe { &*(hdr as *const SismoHdr as *const SismoSampleRec) };
        self.process_sample(rec);
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

    // A file-name definition (reuses the ksym rec layout): the base name for an
    // interned file id, referenced by disk off-CPU blocks.
    fn handle_file(&mut self, rec: &SismoKsymRec) {
        if self.file_names.contains_key(&rec.id) {
            return;
        }
        let raw: &[u8] =
            unsafe { std::slice::from_raw_parts(rec.name.as_ptr() as *const u8, SISMO_KSYM_NAME_MAX) };
        let name = &raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())];
        self.file_names.insert(rec.id, name.to_vec());
    }

    // CAP-2: a module identity page the BPF captured in-band. Parse the build-id
    // from its mapped prefix (the same parser used for a file) and key it by base
    // avma, so a mapping whose file is gone can still be named. Once per base.
    fn handle_module(&mut self, rec: &SismoModuleRec) {
        if rec.prefix_len == 0 || self.bpf_build_ids.contains_key(&rec.base) {
            return;
        }
        let n = (rec.prefix_len as usize).min(SISMO_MODULE_PREFIX);
        let Some(id) = crate::symbolize::proc_maps::build_id_from_image_prefix(&rec.prefix[..n])
        else {
            return;
        };
        // Correct any mapping already interned with a synthetic id: re-emit its
        // definition with the real build-id on the same iid. If the mapping is
        // not yet interned, the pending bpf_build_ids entry supplies the real id
        // at intern time, so nothing to re-emit here.
        let mut idw = ProtoWriter::new();
        if self.interner.reemit_build_id(rec.base, &id, &mut idw) {
            let mut tp = ProtoWriter::new();
            tp.write_uint32(13, SEQ_NEEDS_INCREMENTAL_STATE);
            tp.write_message(12, idw.bytes());
            unsafe { sismo_ds_emit(self.ds_slot, tp.bytes().as_ptr(), tp.bytes().len()) };
        }
        self.bpf_build_ids.insert(rec.base, id);
    }

    // CAP-1: a CPython qualname definition (id -> name) the BPF walk emitted the
    // first time it saw a code object. Same intern-by-id pattern as ksym.
    fn handle_pyframe(&mut self, rec: &SismoPyframeRec) {
        if self.py_names.contains_key(&rec.id) {
            return;
        }
        let raw: &[u8] =
            unsafe { std::slice::from_raw_parts(rec.name.as_ptr() as *const u8, SISMO_PY_NAME_MAX) };
        let name = &raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())];
        self.py_names.insert(rec.id, name.to_vec());
    }
}

// ---- init / worker / DS lifecycle / C ABI ----------------------------------

use crate::ffi::{sismo_ds_flush_offcpu, sismo_ds_register, sismo_flush_done, sismo_stop_done};
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
    pub offcpu_samples: u64,
    pub offcpu_ns: u64,
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
    c.offcpu_need_defaults.store(true, Ordering::Release);
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
        // Commit the off-CPU writer's tail before acking — the SDK flushes the
        // primary sequence for us, but the off-CPU writer is ours.
        unsafe { sismo_ds_flush_offcpu(c.ds_slot) };
        unsafe { sismo_flush_done(fh as *mut c_void) };
    }
    let sh = c.stop_req.swap(0, Ordering::AcqRel);
    if sh != 0 {
        unsafe { ring_buffer__consume(c.rb) };
        unsafe { sismo_ds_flush_offcpu(c.ds_slot) };
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

/// Parse a Linux perf JIT symbol map (`/tmp/perf-<pid>.map`): one
/// `<hex start> <hex size> <name>` line per JIT method, the name running to end
/// of line. Returns `(start, size, name)` sorted by start; empty when the file
/// is absent (no JIT map published) or unreadable.
fn load_perf_map(pid: u32) -> Vec<(u64, u64, String)> {
    let Ok(text) = std::fs::read_to_string(format!("/tmp/perf-{pid}.map")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let mut it = line.splitn(3, ' ');
        let (Some(a), Some(sz), Some(name)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        if let (Ok(start), Ok(size)) =
            (u64::from_str_radix(a, 16), u64::from_str_radix(sz, 16))
        {
            out.push((start, size, name.to_string()));
        }
    }
    out.sort_by_key(|&(start, _, _)| start);
    out
}

fn capture_init(
    pid: u32,
    focus: Option<FocusPreset>,
    density: Option<f64>,
    offcpu: bool,
    keep_policy: KeepPolicy,
) -> *mut Capture {
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
        residual_map: None,
        maps_tried: false,
        last_maps_ns: 0,
        interner: Interner::new(),
        offcpu_interner: Interner::new(),
        ksym_names: HashMap::new(),
        file_names: HashMap::new(),
        py_names: HashMap::new(),
        py_cfg_fd: -1,
        python_bpf: false,
        bpf_build_ids: HashMap::new(),
        modules: ModuleRegistry::new(keep_policy),
        counters: Vec::new(),
        active_slots: Vec::new(),
        focus,
        data_regions: None,
        last_data_parse_ns: 0,
        data_frames: 0,
        offcpu_samples: 0,
        offcpu_ns: 0,
        unwind_snapshots: 0,
        unwinder: None,
        unwind_registered: HashSet::new(),
        go_unwinders: HashMap::new(),
        jit_syms: None,
        jit_map_size: 0,
        python_tried: false,
        python_runtime: None,
        python_debug_count: 0,
        sampler_precise_ip: 0,
        ds_slot: u32::MAX,
        active: AtomicBool::new(false),
        need_defaults: AtomicBool::new(false),
        offcpu_need_defaults: AtomicBool::new(false),
        flush_req: AtomicUsize::new(0),
        stop_req: AtomicUsize::new(0),
    }));
    let c = unsafe { &mut *cap };
    c.counters = select_counters();

    let desc = crate::proto::session_config::encode_data_source_descriptor(DS_NAME, false, false, &[]);
    let slot = unsafe {
        sismo_ds_register(
            desc.as_ptr(),
            desc.len(),
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
    // CAP-1: the Python-offsets config map (populated later, once the target's
    // interpreter is located). Best-effort — absent on a pre-CAP-1 object.
    c.py_cfg_fd = map_fd(obj, c"py_cfg").unwrap_or(-1);

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

    // NAT-1: cfg[1] gates the BPF unwind-capture path (regs + raw user-stack
    // snapshot alongside the FP-walked sample), which the host-side unwinder
    // turns into a DWARF-recovered chain. On by default on x86-64 — it is what
    // recovers stacks for frame-pointer-less binaries. The 8 KiB/sample cost is
    // the framehop-offline baseline (NAT-2's in-kernel tables shrink it later);
    // SISMO_UNWIND_CAPTURE=0 forces it off to fall back to the pure FP walk.
    #[cfg(target_arch = "x86_64")]
    let unwind_flag: u32 = match std::env::var("SISMO_UNWIND_CAPTURE").as_deref() {
        Ok("0") => 0,
        _ => 1,
    };
    #[cfg(not(target_arch = "x86_64"))]
    let unwind_flag: u32 = 0;
    let one: u32 = 1;
    unsafe {
        bpf_map_update_elem(
            cfg_fd,
            &one as *const u32 as *const c_void,
            &unwind_flag as *const u32 as *const c_void,
            0,
        )
    };

    // Off-CPU capture: the sched_switch blocking-stack program plus the
    // futex/tcp/vfs probes that tag each block with what it waits on. Gated so a
    // CPU-only recording (`--only cpu`) does no scheduler work at all.
    if offcpu {
        let ss = unsafe { bpf_object__find_program_by_name(obj, c"on_sched_switch".as_ptr()) };
        if !ss.is_null() {
            let link = unsafe { bpf_program__attach(ss) };
            if !link.is_null() {
                c.links.push(link);
            }
        }

        // Best effort — a kernel that refuses any of these just loses that
        // identity, not the off-CPU stacks.
        for name in [
            c"on_futex_enter".as_ptr(),
            c"on_futex_exit".as_ptr(),
            c"on_tcp_recvmsg".as_ptr(),
            c"on_tcp_recvmsg_ret".as_ptr(),
            c"on_vfs_read".as_ptr(),
            c"on_vfs_read_ret".as_ptr(),
        ] {
            let prog = unsafe { bpf_object__find_program_by_name(obj, name) };
            if !prog.is_null() {
                let link = unsafe { bpf_program__attach(prog) };
                if !link.is_null() {
                    c.links.push(link);
                }
            }
        }
    }

    let sampler_cfg = resolve_sampler(focus, density);
    if sampler_cfg.is_none() {
        if let Some(p) = focus {
            eprintln!(
                "sismo record: --focus {}: leader event unavailable on this CPU (model not in the PMU table); no CPU samples recorded",
                p.name()
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
pub fn init(
    pid: u32,
    focus: Option<FocusPreset>,
    density: Option<f64>,
    offcpu: bool,
    keep_policy: KeepPolicy,
) -> Option<Box<Capture>> {
    let p = capture_init(pid, focus, density, offcpu, keep_policy);
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

    /// Stop the worker, tear down BPF, and return the run stats plus the module
    /// registry (whose held fds must outlive the capture until symbolization).
    /// Consumes self.
    pub fn shutdown(mut self: Box<Self>) -> (LinuxBpfStats, ModuleRegistry) {
        self.exit_requested.store(true, Ordering::Release);
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
        // The worker has joined, so no one else touches the registry; move it out.
        let modules = std::mem::replace(&mut self.modules, ModuleRegistry::new(KeepPolicy::None));
        let stats = LinuxBpfStats {
            samples: self.samples,
            threads: self.acc.len() as u64,
            busiest_cycles: self.acc.values().copied().max().unwrap_or(0),
            data_frames: self.data_frames,
            offcpu_samples: self.offcpu_samples,
            offcpu_ns: self.offcpu_ns,
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
        (stats, modules)
        // maps / data_regions dropped with self.
    }
}
