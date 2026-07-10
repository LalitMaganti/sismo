// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Session-setup proto encoders, migrated from perfetto_proto.zig.
//!
//! Two messages:
//!   - `DataSourceDescriptor` (common/data_source_descriptor.proto) — each
//!     producer registers one via `sismo_ds_register`.
//!   - `TraceConfig` (config/trace_config.proto) — the consumer builds one to
//!     set up the tracing session.
//!
//! The C++ side only parses these; every byte on the wire is built here. Field
//! numbers come from the vendored proto schemas.

use crate::proto::ProtoWriter;
use std::slice;

// ---- DataSourceConfig field numbers ----
const DSC_NAME: u32 = 1;
const DSC_TRACK_EVENT_CONFIG: u32 = 113;
const DSC_FTRACE_CONFIG: u32 = 100;
const DSC_PROTOVM_CONFIG: u32 = 12;
const DSC_SISMO_CONFIG: u32 = 2000;

// ---- Helpers ---------------------------------------------------------------

fn ffi_slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(ptr, len) }
    }
}

/// Copy `bytes` into `out[..cap]`; return the length, or 0 if too small.
///
/// # Safety
/// `out` must be writable for `cap` bytes.
unsafe fn emit(bytes: &[u8], out: *mut u8, cap: usize) -> usize {
    if bytes.len() > cap {
        return 0;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
    }
    bytes.len()
}

// ---- DataSourceDescriptor --------------------------------------------------

/// Encode a DataSourceDescriptor: name (1), will_notify_on_stop (2),
/// will_notify_on_start (3), and — when `protovm_program_len > 0` — the
/// serialized VmProgram at field 10. Writes into out[..cap]; returns bytes
/// written or 0 if too small.
///
/// # Safety
/// `name`/`protovm_program` valid for their lengths or null; `out` writable
/// for `cap`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_encode_data_source_descriptor(
    name: *const u8,
    name_len: usize,
    will_notify_on_stop: bool,
    will_notify_on_start: bool,
    protovm_program: *const u8,
    protovm_program_len: usize,
    out: *mut u8,
    cap: usize,
) -> usize {
    let mut w = ProtoWriter::new();
    w.write_string(1, ffi_slice(name, name_len));
    if will_notify_on_stop {
        w.write_uint32(2, 1);
    }
    if will_notify_on_start {
        w.write_uint32(3, 1);
    }
    let program = ffi_slice(protovm_program, protovm_program_len);
    if !program.is_empty() {
        w.write_message(10, program);
    }
    unsafe { emit(w.bytes(), out, cap) }
}

// ---- TraceConfig -----------------------------------------------------------

/// TraceConfig mode. Maps to fill_policy + write_into_file / duration_ms.
const MODE_RING: u32 = 0;
const MODE_CAPPED: u32 = 1;
const MODE_FILE: u32 = 2;

/// DataSourceEntry kind tags.
const KIND_TRACK_EVENT: u32 = 0;
const KIND_SISMO_VENDOR: u32 = 1;
const KIND_LINUX_FTRACE: u32 = 2;

/// Flattened `data_sources[*]` entry passed across FFI. `kind` selects which
/// fields are read: track_event/linux_ftrace need none (their configs are
/// fixed), sismo_vendor uses name + sismo_config + protovm_memory_limit_kb.
#[repr(C)]
pub struct DataSourceEntryC {
    pub kind: u32,
    pub name: *const u8,
    pub name_len: usize,
    pub sismo_config: *const u8,
    pub sismo_config_len: usize,
    pub protovm_memory_limit_kb: u32,
}

fn encode_track_event_config() -> Vec<u8> {
    // TrackEventConfig.enabled_categories = repeated string field 2. "*" = all.
    // (Field 1 is disabled_categories — the exact inverse.)
    let mut w = ProtoWriter::new();
    w.write_string(2, b"*");
    w.bytes().to_vec()
}

fn encode_ftrace_config() -> Vec<u8> {
    // ftrace_events = 1 (repeated string); compact_sched = 12 (.enabled = 1).
    let mut w = ProtoWriter::new();
    for e in [
        b"sched/sched_switch".as_slice(),
        b"sched/sched_waking".as_slice(),
        b"sched/sched_wakeup".as_slice(),
        b"sched/sched_process_exit".as_slice(),
        b"power/cpu_frequency".as_slice(),
        b"power/cpu_idle".as_slice(),
    ] {
        w.write_string(1, e);
    }
    let mut compact = ProtoWriter::new();
    compact.write_uint32(1, 1); // CompactSchedConfig.enabled
    w.write_message(12, compact.bytes());
    w.bytes().to_vec()
}

fn encode_data_source_config(entry: &DataSourceEntryC) -> Vec<u8> {
    let mut w = ProtoWriter::new();
    match entry.kind {
        KIND_TRACK_EVENT => {
            w.write_string(DSC_NAME, b"track_event");
            w.write_message(DSC_TRACK_EVENT_CONFIG, &encode_track_event_config());
        }
        KIND_LINUX_FTRACE => {
            w.write_string(DSC_NAME, b"linux.ftrace");
            w.write_message(DSC_FTRACE_CONFIG, &encode_ftrace_config());
        }
        KIND_SISMO_VENDOR | _ => {
            // sismo_vendor (any unrecognized kind is treated as vendor).
            w.write_string(DSC_NAME, ffi_slice(entry.name, entry.name_len));
            let cfg = ffi_slice(entry.sismo_config, entry.sismo_config_len);
            if !cfg.is_empty() {
                w.write_message(DSC_SISMO_CONFIG, cfg);
            }
            if entry.protovm_memory_limit_kb > 0 {
                let mut pvc = ProtoWriter::new();
                pvc.write_uint32(1, entry.protovm_memory_limit_kb); // memory_limit_kb
                w.write_message(DSC_PROTOVM_CONFIG, pvc.bytes());
            }
        }
    }
    w.bytes().to_vec()
}

fn encode_buffer_config(size_kb: u32, fill_policy: u32) -> Vec<u8> {
    let mut w = ProtoWriter::new();
    w.write_uint32(1, size_kb);
    if fill_policy != 0 {
        w.write_uint32(4, fill_policy);
    }
    w.write_uint32(8, 1); // experimental_mode = TRACE_BUFFER_V2 (always V2)
    w.bytes().to_vec()
}

/// Encode a TraceConfig. `mode` is one of MODE_{RING,CAPPED,FILE}; `entries`
/// are the flattened data sources. Writes into out[..cap]; returns bytes
/// written or 0 if too small.
///
/// # Safety
/// `output_path`/`session_name` valid for their lengths or null; `entries`
/// valid for `entries_len`, as are the pointers inside each entry; `out`
/// writable for `cap`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_encode_trace_config(
    mode: u32,
    buffer_size_kb: u32,
    duration_ms: u32,
    output_path: *const u8,
    output_path_len: usize,
    max_file_size_bytes: u64,
    session_name: *const u8,
    session_name_len: usize,
    entries: *const DataSourceEntryC,
    entries_len: usize,
    out: *mut u8,
    cap: usize,
) -> usize {
    let mut w = ProtoWriter::new();

    // buffers (field 1). Single buffer, always V2 (ProtoVM requires it).
    // Capped mode uses DISCARD (2); otherwise RING_BUFFER (1) — DISCARD +
    // write_into_file causes silent data loss.
    let fill_policy = if mode == MODE_CAPPED { 2 } else { 1 };
    w.write_message(1, &encode_buffer_config(buffer_size_kb, fill_policy));

    // data_sources (field 2); each DataSource.config = field 1.
    let entries = if entries.is_null() {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(entries, entries_len) }
    };
    for entry in entries {
        let dsc = encode_data_source_config(entry);
        let mut ds = ProtoWriter::new();
        ds.write_message(1, &dsc);
        w.write_message(2, ds.bytes());
    }

    // unique_session_name (field 22).
    w.write_string(22, ffi_slice(session_name, session_name_len));

    match mode {
        MODE_RING => {} // nothing extra
        MODE_CAPPED => w.write_uint32(3, duration_ms),
        MODE_FILE => {
            w.write_uint32(8, 1); // write_into_file
            w.write_uint64(10, max_file_size_bytes);
            w.write_uint32(9, 1000); // file_write_period_ms
            w.write_string(29, ffi_slice(output_path, output_path_len));
        }
        _ => {}
    }

    unsafe { emit(w.bytes(), out, cap) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_bytes_are_exact() {
        // name="x", will_notify_on_stop=true.
        let mut out = [0u8; 64];
        let n = unsafe {
            sismo_encode_data_source_descriptor(
                b"x".as_ptr(),
                1,
                true,
                false,
                std::ptr::null(),
                0,
                out.as_mut_ptr(),
                out.len(),
            )
        };
        // name(1) len 1 "x": 0A 01 78; will_notify_on_stop(2)=1: 10 01.
        assert_eq!(&out[..n], &[0x0A, 0x01, 0x78, 0x10, 0x01]);
    }

    #[test]
    fn descriptor_with_protovm_program() {
        let mut out = [0u8; 64];
        let n = unsafe {
            sismo_encode_data_source_descriptor(
                b"s".as_ptr(),
                1,
                true,
                false,
                [0xDEu8, 0xAD].as_ptr(),
                2,
                out.as_mut_ptr(),
                out.len(),
            )
        };
        // ...protovm_program(10) len 2: tag=10<<3|2=0x52, 02, DE AD.
        let got = &out[..n];
        assert!(got.windows(4).any(|w| w == [0x52, 0x02, 0xDE, 0xAD]));
    }

    #[test]
    fn buffer_config_is_v2() {
        let b = encode_buffer_config(1024, 1);
        // size_kb(1)=1024: 08 80 08; fill_policy(4)=1: 20 01; exp_mode(8)=1: 40 01.
        assert_eq!(b, &[0x08, 0x80, 0x08, 0x20, 0x01, 0x40, 0x01]);
    }

    #[test]
    fn track_event_uses_enabled_categories_field_2() {
        let te = encode_track_event_config();
        // enabled_categories(2) len 1 "*": 12 01 2A. NOT field 1 (disabled).
        assert_eq!(te, &[0x12, 0x01, 0x2A]);
    }

    #[test]
    fn trace_config_ring_with_track_event() {
        // ring mode, one track_event source, session "s", 8 MB buffer.
        let entries = [DataSourceEntryC {
            kind: KIND_TRACK_EVENT,
            name: std::ptr::null(),
            name_len: 0,
            sismo_config: std::ptr::null(),
            sismo_config_len: 0,
            protovm_memory_limit_kb: 0,
        }];
        let mut out = [0u8; 256];
        let n = unsafe {
            sismo_encode_trace_config(
                MODE_RING,
                8192,
                0,
                std::ptr::null(),
                0,
                0,
                b"s".as_ptr(),
                1,
                entries.as_ptr(),
                entries.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        let got = &out[..n];
        // Contains a buffer (field 1) with V2 marker (40 01) and the
        // track_event data source name, plus session_name(22) "s" (tag 0xB2 0x01).
        assert!(got.windows(2).any(|w| w == [0x40, 0x01]), "buffer V2 marker");
        assert!(
            got.windows(11).any(|w| w == b"track_event"),
            "track_event source name"
        );
        assert!(
            got.windows(3).any(|w| w == [0xB2, 0x01, 0x01]),
            "session_name field 22, len 1"
        );
        // Ring mode: no write_into_file(8) / duration(3) at the top level.
    }

    #[test]
    fn trace_config_file_mode_and_sismo_vendor_with_protovm() {
        let cfg = [0x08u8, 0x2A]; // a stand-in sismo_config payload
        let entries = [DataSourceEntryC {
            kind: KIND_SISMO_VENDOR,
            name: b"sismo.macos_sched".as_ptr(),
            name_len: b"sismo.macos_sched".len(),
            sismo_config: cfg.as_ptr(),
            sismo_config_len: cfg.len(),
            protovm_memory_limit_kb: 4096,
        }];
        let mut out = [0u8; 256];
        let n = unsafe {
            sismo_encode_trace_config(
                MODE_FILE,
                8192,
                0,
                b"/tmp/t.pftrace".as_ptr(),
                b"/tmp/t.pftrace".len(),
                1024,
                b"sismo_record".as_ptr(),
                b"sismo_record".len(),
                entries.as_ptr(),
                entries.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        let got = &out[..n];
        assert!(got.windows(17).any(|w| w == b"sismo.macos_sched"));
        // sismo_config at field 2000: tag=2000<<3|2=0x3E82 -> 82 7D.
        assert!(got.windows(2).any(|w| w == [0x82, 0x7D]), "sismo_config field 2000");
        // write_into_file(8)=1: 40 01.
        assert!(got.windows(2).any(|w| w == [0x40, 0x01]));
        // output_path(29) "/tmp/t.pftrace": tag=29<<3|2=0xEA 0x01.
        assert!(got.windows(2).any(|w| w == [0xEA, 0x01]));
    }

    #[test]
    fn trace_config_returns_zero_when_cap_too_small() {
        let entries = [DataSourceEntryC {
            kind: KIND_LINUX_FTRACE,
            name: std::ptr::null(),
            name_len: 0,
            sismo_config: std::ptr::null(),
            sismo_config_len: 0,
            protovm_memory_limit_kb: 0,
        }];
        let mut out = [0u8; 4];
        let n = unsafe {
            sismo_encode_trace_config(
                MODE_RING,
                8192,
                0,
                std::ptr::null(),
                0,
                0,
                b"s".as_ptr(),
                1,
                entries.as_ptr(),
                entries.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(n, 0);
    }
}
