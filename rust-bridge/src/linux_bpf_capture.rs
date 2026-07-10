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
