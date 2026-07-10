// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Heap profile assembly + serialization.
//!
//! Given the target's loaded images and the aggregated allocation sites (each a
//! callstack of PCs plus its byte/count totals), this builds the Perfetto
//! ProfilePacket — interning function names (symbolized via the Rust wholesym
//! symbolizer) and mapping paths into one string pool, deduping frames by PC,
//! and emitting one HeapSample per site — plus the ClockSnapshot the heap
//! parser needs. Each is returned already wrapped in a TracePacket body
//! (timestamp + optional sequence_flags + payload field), as a heap buffer the
//! caller emits via the C++ SDK shim and then frees with `sismo_heap_free`.
//!
//! Building the bytes here (rather than emitting) keeps this module free of the
//! C++ `sismo_ds_emit` symbol, so `cargo test` still links standalone.

#[cfg(target_os = "macos")]
pub mod heap_protocol;
#[cfg(target_os = "macos")]
pub mod heap_ring;
#[cfg(target_os = "macos")]
pub mod macos_heap_capture;

use crate::proto::ProtoWriter;
use crate::symbolize::symbolizer::{sismo_symbolizer_resolve, Symbolizer};
use std::collections::HashMap;
use std::slice;

// ---- Field number constants (from the vendored protos) --------------------

// TracePacket
const TP_CLOCK_SNAPSHOT: u32 = 6;
const TP_PROFILE_PACKET: u32 = 37;
const TP_FIELD_TIMESTAMP: u32 = 8;
const TP_FIELD_SEQUENCE_FLAGS: u32 = 13;
const SEQ_INCREMENTAL_STATE_CLEARED: u32 = 1;

// ClockSnapshot / Clock
const CS_CLOCKS: u32 = 1;
const CLOCK_CLOCK_ID: u32 = 1;
const CLOCK_TIMESTAMP: u32 = 2;
const BUILTIN_CLOCK_BOOTTIME: u32 = 6;
const BUILTIN_CLOCK_MONOTONIC_COARSE: u32 = 4;

// InternedString
const IS_IID: u32 = 1;
const IS_STR: u32 = 2;

// Mapping
const MAP_IID: u32 = 1;
const MAP_START: u32 = 4;
const MAP_END: u32 = 5;
const MAP_LOAD_BIAS: u32 = 6;
const MAP_PATH_STRING_IDS: u32 = 7;

// Frame
const FRAME_IID: u32 = 1;
const FRAME_FUNCTION_NAME_ID: u32 = 2;
const FRAME_MAPPING_ID: u32 = 3;
const FRAME_REL_PC: u32 = 4;

// Callstack
const CS_IID: u32 = 1;
const CS_FRAME_IDS: u32 = 2;

// ProfilePacket — legacy Android-Q-style embedded interned tables. All strings
// (function names AND mapping paths) share one iid space in PP_STRINGS.
const PP_STRINGS: u32 = 1;
const PP_FRAMES: u32 = 2;
const PP_CALLSTACKS: u32 = 3;
const PP_MAPPINGS: u32 = 4;
const PP_PROCESS_DUMPS: u32 = 5;

// ProcessHeapSamples
const PHS_PID: u32 = 1;
const PHS_SAMPLES: u32 = 2;
const PHS_TIMESTAMP: u32 = 9;
const PHS_HEAP_NAME: u32 = 11;
const PHS_SAMPLING_INTERVAL_BYTES: u32 = 12;

// HeapSample
const HS_CALLSTACK_ID: u32 = 1;
const HS_SELF_ALLOCATED: u32 = 2;
const HS_ALLOC_COUNT: u32 = 5;

const HEAP_NAME: &[u8] = b"libc.malloc";

// ---- FFI input types -------------------------------------------------------

/// A loaded mach-o image: its load address and (borrowed) path bytes. Passed
/// sorted ascending by `base_avma`, matching heap_capture's ordering.
#[repr(C)]
pub struct HeapImage {
    pub base_avma: u64,
    pub path_ptr: *const u8,
    pub path_len: usize,
}

/// An aggregated allocation site: a callstack (leaf-first PCs) with its total
/// sampled bytes and allocation count.
#[repr(C)]
pub struct HeapSite {
    pub pcs: *const u64,
    pub pc_count: usize,
    pub count: u64,
    pub total_size: u64,
}

// ---- Internal assembled tables --------------------------------------------

struct Mapping {
    iid: u64,
    path_string_iid: u64,
    start: u64,
    end: u64,
    load_bias: u64,
}

struct Frame {
    iid: u64,
    function_name_iid: u64,
    mapping_iid: u64,
    rel_pc: u64,
}

struct Callstack {
    iid: u64,
    frame_iids: Vec<u64>,
}

struct Sample {
    callstack_iid: u64,
    self_allocated: u64,
    alloc_count: u64,
}

struct TraceData {
    // One unified string pool; iid = index + 1. Both Frame.function_name_iid
    // and Mapping.path_string_iid reference it.
    strings: Vec<Vec<u8>>,
    mappings: Vec<Mapping>,
    frames: Vec<Frame>,
    callstacks: Vec<Callstack>,
    samples: Vec<Sample>,
}

/// Resolve `pc` to a function name via the symbolizer, returning "?" when the
/// symbolizer is absent or has no match. Mirrors heap_capture's use of
/// `symbolizer.resolve` (name only — file/line are unused for heap frames).
///
/// # Safety
/// `symbolizer` must be a valid `*mut Symbolizer` or null.
unsafe fn resolve_name(symbolizer: *mut Symbolizer, pc: u64) -> Vec<u8> {
    let mut name_buf = [0u8; 256];
    let mut file_buf = [0u8; 1024];
    let mut file_len: usize = 0;
    let mut line: u32 = 0;
    let n = unsafe {
        sismo_symbolizer_resolve(
            symbolizer,
            pc,
            name_buf.as_mut_ptr(),
            name_buf.len(),
            file_buf.as_mut_ptr(),
            file_buf.len(),
            &mut file_len,
            &mut line,
        )
    };
    if n > 0 {
        name_buf[..n].to_vec()
    } else {
        b"?".to_vec()
    }
}

/// Build the interned tables from images + sites, including iid ordering (image
/// paths first in the string pool, then function names as unique PCs resolve).
///
/// # Safety
/// `symbolizer` valid-or-null; `images`/`sites` and their embedded pointers
/// valid for their lengths.
unsafe fn build_trace_data(
    symbolizer: *mut Symbolizer,
    images: &[HeapImage],
    sites: &[HeapSite],
) -> TraceData {
    // Image paths occupy the head of the string pool (iid 1..=N); mappings
    // reference those iids.
    let mut strings: Vec<Vec<u8>> = Vec::with_capacity(images.len());
    let mut mappings: Vec<Mapping> = Vec::with_capacity(images.len());
    for (idx, img) in images.iter().enumerate() {
        let path: &[u8] = if img.path_ptr.is_null() {
            &[]
        } else {
            unsafe { slice::from_raw_parts(img.path_ptr, img.path_len) }
        };
        strings.push(path.to_vec());
        let iid = (idx + 1) as u64;
        mappings.push(Mapping {
            iid,
            path_string_iid: iid,
            start: img.base_avma,
            end: img.base_avma,
            load_bias: 0,
        });
    }

    let mut frames: Vec<Frame> = Vec::new();
    let mut frame_by_pc: HashMap<u64, u64> = HashMap::new();
    let mut callstacks: Vec<Callstack> = Vec::new();
    let mut samples: Vec<Sample> = Vec::new();
    let mut next_callstack_iid: u64 = 1;

    for site in sites {
        let pcs: &[u64] = if site.pcs.is_null() {
            &[]
        } else {
            unsafe { slice::from_raw_parts(site.pcs, site.pc_count) }
        };

        let mut frame_iids: Vec<u64> = Vec::with_capacity(pcs.len());
        for &pc in pcs {
            let frame_iid = match frame_by_pc.get(&pc) {
                Some(&fid) => fid,
                None => {
                    let name = unsafe { resolve_name(symbolizer, pc) };
                    strings.push(name);
                    let fn_iid = strings.len() as u64; // 1-based index of just-pushed

                    // First image whose base is strictly above pc; the mapping
                    // is the one just below it (images are base-sorted).
                    let mut j = 0usize;
                    while j < images.len() && images[j].base_avma <= pc {
                        j += 1;
                    }
                    let map_iid: u64 = if j > 0 { j as u64 } else { 1 };
                    let map_base = if j > 0 { images[j - 1].base_avma } else { 0 };

                    let frame_iid = frames.len() as u64 + 1;
                    frames.push(Frame {
                        iid: frame_iid,
                        function_name_iid: fn_iid,
                        mapping_iid: map_iid,
                        rel_pc: pc.wrapping_sub(map_base),
                    });
                    frame_by_pc.insert(pc, frame_iid);
                    frame_iid
                }
            };
            frame_iids.push(frame_iid);
        }

        let cs_iid = next_callstack_iid;
        next_callstack_iid += 1;
        callstacks.push(Callstack {
            iid: cs_iid,
            frame_iids,
        });
        samples.push(Sample {
            callstack_iid: cs_iid,
            self_allocated: site.total_size,
            alloc_count: site.count,
        });
    }

    TraceData {
        strings,
        mappings,
        frames,
        callstacks,
        samples,
    }
}

/// Serialize a ProfilePacket payload from the interned tables. Field emission
/// order is fixed (strings → mappings → frames → callstacks →
/// process_dumps) so the wire bytes are deterministic.
fn encode_profile_packet(
    pid: u32,
    sampling_interval: u64,
    timestamp_ns: u64,
    td: &TraceData,
) -> Vec<u8> {
    let mut w = ProtoWriter::new();

    for (i, s) in td.strings.iter().enumerate() {
        let mut c = ProtoWriter::new();
        c.write_uint64(IS_IID, (i + 1) as u64);
        c.write_string(IS_STR, s);
        w.write_message(PP_STRINGS, c.bytes());
    }
    for m in &td.mappings {
        let mut c = ProtoWriter::new();
        c.write_uint64(MAP_IID, m.iid);
        c.write_uint64(MAP_START, m.start);
        c.write_uint64(MAP_END, m.end);
        c.write_uint64(MAP_LOAD_BIAS, m.load_bias);
        c.write_uint64(MAP_PATH_STRING_IDS, m.path_string_iid);
        w.write_message(PP_MAPPINGS, c.bytes());
    }
    for f in &td.frames {
        let mut c = ProtoWriter::new();
        c.write_uint64(FRAME_IID, f.iid);
        c.write_uint64(FRAME_FUNCTION_NAME_ID, f.function_name_iid);
        c.write_uint64(FRAME_MAPPING_ID, f.mapping_iid);
        c.write_uint64(FRAME_REL_PC, f.rel_pc);
        w.write_message(PP_FRAMES, c.bytes());
    }
    for cs in &td.callstacks {
        let mut c = ProtoWriter::new();
        c.write_uint64(CS_IID, cs.iid);
        for &fid in &cs.frame_iids {
            c.write_uint64(CS_FRAME_IDS, fid);
        }
        w.write_message(PP_CALLSTACKS, c.bytes());
    }

    // process_dumps: a single ProcessHeapSamples.
    let mut phs = ProtoWriter::new();
    phs.write_uint64(PHS_PID, pid as u64);
    phs.write_uint64(PHS_TIMESTAMP, timestamp_ns);
    phs.write_string(PHS_HEAP_NAME, HEAP_NAME);
    phs.write_uint64(PHS_SAMPLING_INTERVAL_BYTES, sampling_interval);
    for s in &td.samples {
        let mut c = ProtoWriter::new();
        c.write_uint64(HS_CALLSTACK_ID, s.callstack_iid);
        c.write_uint64(HS_SELF_ALLOCATED, s.self_allocated);
        c.write_uint64(HS_ALLOC_COUNT, s.alloc_count);
        phs.write_message(PHS_SAMPLES, c.bytes());
    }
    w.write_message(PP_PROCESS_DUMPS, phs.bytes());
    w.bytes().to_vec()
}

/// Build the ClockSnapshot payload: map MONOTONIC_COARSE 1:1 to BOOTTIME at
/// `ts_ns` (the heap parser reads ProcessHeapSamples.timestamp as
/// MONOTONIC_COARSE and needs a registered snapshot to convert it).
fn encode_clock_snapshot(ts_ns: u64) -> Vec<u8> {
    let mut w = ProtoWriter::new();
    for &clock_id in &[BUILTIN_CLOCK_BOOTTIME, BUILTIN_CLOCK_MONOTONIC_COARSE] {
        let mut c = ProtoWriter::new();
        c.write_uint32(CLOCK_CLOCK_ID, clock_id);
        c.write_uint64(CLOCK_TIMESTAMP, ts_ns);
        w.write_message(CS_CLOCKS, c.bytes());
    }
    w.bytes().to_vec()
}

/// Wrap a payload in a TracePacket body: timestamp + optional sequence_flags +
/// payload as length-delimited field `payload_field_tag`.
fn wrap_trace_packet(
    timestamp_ns: u64,
    sequence_flags: u32,
    payload_field_tag: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut w = ProtoWriter::new();
    if timestamp_ns != 0 {
        w.write_uint64(TP_FIELD_TIMESTAMP, timestamp_ns);
    }
    if sequence_flags != 0 {
        w.write_uint32(TP_FIELD_SEQUENCE_FLAGS, sequence_flags);
    }
    w.write_message(payload_field_tag, payload);
    w.bytes().to_vec()
}

/// Hand a heap buffer to the caller: writes its length to `*out_len` and
/// returns a pointer freed with `sismo_heap_free`.
fn into_raw(v: Vec<u8>, out_len: *mut usize) -> *mut u8 {
    let boxed = v.into_boxed_slice(); // capacity == length
    let len = boxed.len();
    unsafe {
        *out_len = len;
    }
    Box::into_raw(boxed) as *mut u8
}

// ---- FFI entry points ------------------------------------------------------

/// Build the ProfilePacket, wrapped in a TracePacket body, from the aggregated
/// sites + images. Returns a heap buffer (free with `sismo_heap_free`) and
/// writes its length to `*out_len`.
///
/// # Safety
/// `symbolizer` must be a valid `*mut Symbolizer` or null. `images`/`sites`
/// must be valid for their lengths, as must every embedded `path_ptr`/`pcs`
/// pointer. `out_len` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_heap_build_profile_packet(
    pid: u32,
    sampling_interval: u64,
    timestamp_ns: u64,
    symbolizer: *mut Symbolizer,
    images: *const HeapImage,
    images_len: usize,
    sites: *const HeapSite,
    sites_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    let images: &[HeapImage] = if images.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(images, images_len) }
    };
    let sites: &[HeapSite] = if sites.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(sites, sites_len) }
    };
    let td = unsafe { build_trace_data(symbolizer, images, sites) };
    let payload = encode_profile_packet(pid, sampling_interval, timestamp_ns, &td);
    let body = wrap_trace_packet(
        timestamp_ns,
        SEQ_INCREMENTAL_STATE_CLEARED,
        TP_PROFILE_PACKET,
        &payload,
    );
    into_raw(body, out_len)
}

/// Build the ClockSnapshot TracePacket body for `timestamp_ns`. Returns a heap
/// buffer (free with `sismo_heap_free`) and writes its length to `*out_len`.
///
/// # Safety
/// `out_len` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_heap_build_clock_snapshot_packet(
    timestamp_ns: u64,
    out_len: *mut usize,
) -> *mut u8 {
    let payload = encode_clock_snapshot(timestamp_ns);
    let body = wrap_trace_packet(timestamp_ns, 0, TP_CLOCK_SNAPSHOT, &payload);
    into_raw(body, out_len)
}

/// Free a buffer returned by the `sismo_heap_build_*` functions.
///
/// # Safety
/// `ptr`/`len` must be exactly what a `sismo_heap_build_*` call returned, freed
/// at most once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_heap_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    let slice = unsafe { slice::from_raw_parts_mut(ptr, len) };
    drop(unsafe { Box::from_raw(slice as *mut [u8]) });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_snapshot_packet_bytes_are_exact() {
        // ts=150. Payload: two Clock submessages under CS_CLOCKS(1).
        // Each clock: clock_id(1)=id, timestamp(2)=150 -> 08 <id> 10 96 01.
        //   BOOTTIME=6:          08 06 10 96 01  (5 bytes)
        //   MONOTONIC_COARSE=4:  08 04 10 96 01  (5 bytes)
        // CS_CLOCKS tag = 1<<3|2 = 0x0A, len 5 each.
        // payload = 0A 05 08 06 10 96 01  0A 05 08 04 10 96 01
        // Wrapped: timestamp(8)=150: 40 96 01; clock_snapshot(6) tag=6<<3|2=0x32,
        //   len 14 (0x0E), then payload.
        let mut len: usize = 0;
        let ptr = unsafe { sismo_heap_build_clock_snapshot_packet(150, &mut len) };
        let got = unsafe { slice::from_raw_parts(ptr, len) };
        assert_eq!(
            got,
            &[
                0x40, 0x96, 0x01, // timestamp
                0x32, 0x0E, // clock_snapshot, len 14
                0x0A, 0x05, 0x08, 0x06, 0x10, 0x96, 0x01, // BOOTTIME
                0x0A, 0x05, 0x08, 0x04, 0x10, 0x96, 0x01, // MONOTONIC_COARSE
            ]
        );
        unsafe { sismo_heap_free(ptr, len) };
    }

    #[test]
    fn profile_packet_contains_interned_tables_and_sample() {
        // One image ("img" at base 0x1000), one site with one pc=0x1010,
        // count=5, total=100. Null symbolizer -> function name "?".
        let path = b"img";
        let images = [HeapImage {
            base_avma: 0x1000,
            path_ptr: path.as_ptr(),
            path_len: path.len(),
        }];
        let pcs = [0x1010u64];
        let sites = [HeapSite {
            pcs: pcs.as_ptr(),
            pc_count: pcs.len(),
            count: 5,
            total_size: 100,
        }];
        let mut len: usize = 0;
        let ptr = unsafe {
            sismo_heap_build_profile_packet(
                4242,
                4096,
                150,
                std::ptr::null_mut(),
                images.as_ptr(),
                images.len(),
                sites.as_ptr(),
                sites.len(),
                &mut len,
            )
        };
        let got = unsafe { slice::from_raw_parts(ptr, len) }.to_vec();
        unsafe { sismo_heap_free(ptr, len) };

        // String pool: image path "img" (iid 1) then function name "?" (iid 2).
        assert!(got.windows(3).any(|w| w == b"img"));
        assert!(got.contains(&b'?'));
        // Heap name in ProcessHeapSamples.
        assert!(
            got.windows(HEAP_NAME.len()).any(|w| w == HEAP_NAME),
            "profile packet should carry the heap name"
        );
        // pid 4242 = 0x1092 -> varint 92 21, under PHS_PID(1)=tag 08.
        assert!(got.windows(3).any(|w| w == [0x08, 0x92, 0x21]));
        // Wrapped with SEQ_INCREMENTAL_STATE_CLEARED(1) at field 13 (tag 0x68).
        assert!(got.windows(2).any(|w| w == [0x68, 0x01]));
    }

    #[test]
    fn frames_dedupe_by_pc_across_sites() {
        // Two sites sharing pc 0x2000; a third distinct pc 0x3000. Expect 2
        // unique frames, 2 callstacks, 2 samples. Null symbolizer.
        let img = b"m";
        let images = [HeapImage {
            base_avma: 0x1000,
            path_ptr: img.as_ptr(),
            path_len: img.len(),
        }];
        let pcs_a = [0x2000u64];
        let pcs_b = [0x2000u64, 0x3000u64];
        let sites = [
            HeapSite {
                pcs: pcs_a.as_ptr(),
                pc_count: 1,
                count: 1,
                total_size: 10,
            },
            HeapSite {
                pcs: pcs_b.as_ptr(),
                pc_count: 2,
                count: 2,
                total_size: 20,
            },
        ];
        let td = unsafe { build_trace_data(std::ptr::null_mut(), &images, &sites) };
        assert_eq!(td.frames.len(), 2, "pc 0x2000 shared -> deduped");
        assert_eq!(td.callstacks.len(), 2);
        assert_eq!(td.samples.len(), 2);
        // strings: 1 image path + 2 function names.
        assert_eq!(td.strings.len(), 3);
        // rel_pc for 0x2000 against base 0x1000 = 0x1000.
        assert_eq!(td.frames[0].rel_pc, 0x1000);
    }
}
