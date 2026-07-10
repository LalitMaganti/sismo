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
