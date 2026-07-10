// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Temporary privileged-pid marker for `sismo record`.
//!
//! THIS IS A HACK bridging the gap until a proper JSON-in-zip sidecar lands;
//! this whole file + its cmd_record caller should die together then. It appends
//! a TrackDescriptor + a TYPE_INSTANT TrackEvent (carrying the privileged pids
//! and optional focus-preset metadata) to an already-written trace file. The
//! Sismo UI matches on the deliberately-ugly event name below.

use sismo_core::proto::ProtoWriter;
use std::io::Write;
use std::slice;

// TracePacket / TrackEvent / TrackDescriptor / DebugAnnotation field tags.
const TP_FIELD_TRACE_PACKET: u32 = 1;
const TP_FIELD_TIMESTAMP: u32 = 8;
const TP_FIELD_TRUSTED_PACKET_SEQUENCE_ID: u32 = 10;
const TP_FIELD_TRACK_EVENT: u32 = 11;
const TP_FIELD_TIMESTAMP_CLOCK_ID: u32 = 58;
const TP_FIELD_TRACK_DESCRIPTOR: u32 = 60;
const BUILTIN_CLOCK_BOOTTIME: u32 = 6;

const TE_FIELD_TYPE: u32 = 9;
const TE_FIELD_TRACK_UUID: u32 = 11;
const TE_FIELD_NAME: u32 = 23;
const TE_FIELD_DEBUG_ANNOTATIONS: u32 = 4;
const TE_TYPE_INSTANT: u32 = 3;

const TD_FIELD_UUID: u32 = 1;
const TD_FIELD_NAME: u32 = 2;

const DA_FIELD_INT_VALUE: u32 = 4;
const DA_FIELD_STRING_VALUE: u32 = 6;
const DA_FIELD_NAME: u32 = 10;

const MARKER_NAME: &[u8] = b"sismo_temporary_privileged_pid_marker";
const MARKER_TRACK_UUID: u64 = 0xC0DE_CAFE_5151_1010;
const MARKER_SEQUENCE_ID: u32 = 0xC0DE_CAFE;

// sismo labels this MONOTONIC value as BOOTTIME to line up with the rest of the
// trace (heap registers a 1:1 MONOTONIC↔BOOTTIME snapshot). libc::CLOCK_MONOTONIC
// already carries the right per-OS id (1 on Linux, 6 on macOS).
fn now_monotonic_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn track_descriptor_packet(timestamp_ns: u64) -> Vec<u8> {
    let mut td = ProtoWriter::new();
    td.write_uint64(TD_FIELD_UUID, MARKER_TRACK_UUID);
    td.write_string(TD_FIELD_NAME, MARKER_NAME);

    let mut tp = ProtoWriter::new();
    tp.write_uint64(TP_FIELD_TIMESTAMP, timestamp_ns);
    tp.write_uint32(TP_FIELD_TIMESTAMP_CLOCK_ID, BUILTIN_CLOCK_BOOTTIME);
    tp.write_uint32(TP_FIELD_TRUSTED_PACKET_SEQUENCE_ID, MARKER_SEQUENCE_ID);
    tp.write_message(TP_FIELD_TRACK_DESCRIPTOR, td.bytes());
    tp.bytes().to_vec()
}

fn track_event_packet(pids: &[i32], focus_preset: Option<&[u8]>, focus_precise: bool, timestamp_ns: u64) -> Vec<u8> {
    let mut te = ProtoWriter::new();
    te.write_uint32(TE_FIELD_TYPE, TE_TYPE_INSTANT);
    te.write_uint64(TE_FIELD_TRACK_UUID, MARKER_TRACK_UUID);
    te.write_string(TE_FIELD_NAME, MARKER_NAME);
    for &pid in pids {
        let mut ann = ProtoWriter::new();
        ann.write_string(DA_FIELD_NAME, b"pid");
        ann.write_uint64(DA_FIELD_INT_VALUE, pid as u64);
        te.write_message(TE_FIELD_DEBUG_ANNOTATIONS, ann.bytes());
    }
    if let Some(preset) = focus_preset {
        let mut ann = ProtoWriter::new();
        ann.write_string(DA_FIELD_NAME, b"focus_preset");
        ann.write_string(DA_FIELD_STRING_VALUE, preset);
        te.write_message(TE_FIELD_DEBUG_ANNOTATIONS, ann.bytes());

        let mut pann = ProtoWriter::new();
        pann.write_string(DA_FIELD_NAME, b"focus_precise");
        pann.write_uint64(DA_FIELD_INT_VALUE, if focus_precise { 1 } else { 0 });
        te.write_message(TE_FIELD_DEBUG_ANNOTATIONS, pann.bytes());
    }

    let mut tp = ProtoWriter::new();
    tp.write_uint64(TP_FIELD_TIMESTAMP, timestamp_ns);
    tp.write_uint32(TP_FIELD_TIMESTAMP_CLOCK_ID, BUILTIN_CLOCK_BOOTTIME);
    tp.write_uint32(TP_FIELD_TRUSTED_PACKET_SEQUENCE_ID, MARKER_SEQUENCE_ID);
    tp.write_message(TP_FIELD_TRACK_EVENT, te.bytes());
    tp.bytes().to_vec()
}

/// The two Trace-wrapped packets (descriptor + event), concatenated.
fn build_marker(pids: &[i32], focus_preset: Option<&[u8]>, focus_precise: bool, timestamp_ns: u64) -> Vec<u8> {
    let desc = track_descriptor_packet(timestamp_ns);
    let event = track_event_packet(pids, focus_preset, focus_precise, timestamp_ns);
    let mut out = ProtoWriter::new();
    out.write_message(TP_FIELD_TRACE_PACKET, &desc);
    out.write_message(TP_FIELD_TRACE_PACKET, &event);
    out.bytes().to_vec()
}

/// Append the privileged-pid marker to the trace file at `path`. No-op if
/// `n_pids == 0`. Returns true on success, false on any I/O failure.
///
/// # Safety
/// `path`/`pids`/`focus_preset` must be valid for their lengths (focus_preset
/// null = absent).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_append_privileged_marker(
    path: *const u8,
    path_len: usize,
    pids: *const i32,
    n_pids: usize,
    focus_preset: *const u8,
    focus_preset_len: usize,
    focus_precise: bool,
) -> bool {
    if n_pids == 0 {
        return true; // nothing to mark — success
    }
    let pids = unsafe { slice::from_raw_parts(pids, n_pids) };
    let focus = if focus_preset.is_null() || focus_preset_len == 0 {
        None
    } else {
        Some(unsafe { slice::from_raw_parts(focus_preset, focus_preset_len) })
    };
    let path_bytes = unsafe { slice::from_raw_parts(path, path_len) };
    let path_str = match std::str::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let bytes = build_marker(pids, focus, focus_precise, now_monotonic_ns());

    // Append to the existing trace file (perfetto streams are just concatenated
    // length-delimited TracePackets).
    match std::fs::OpenOptions::new().append(true).open(path_str) {
        Ok(mut f) => f.write_all(&bytes).is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn event_carries_marker_name_once_and_pid_varints() {
        let ev = track_event_packet(&[1234, 5678], None, false, 0);
        let occurrences = ev.windows(MARKER_NAME.len()).filter(|w| *w == MARKER_NAME).count();
        assert_eq!(occurrences, 1);
        // 1234 = d2 09, 5678 = ae 2c.
        assert!(contains(&ev, &[0xd2, 0x09]));
        assert!(contains(&ev, &[0xae, 0x2c]));
    }

    #[test]
    fn event_stamps_focus_preset_and_precision_when_present() {
        let without = track_event_packet(&[42], None, false, 0);
        assert!(!contains(&without, b"focus_preset"));

        let with = track_event_packet(&[42], Some(b"stalls"), true, 0);
        assert!(contains(&with, b"focus_preset"));
        assert!(contains(&with, b"stalls"));
        assert!(contains(&with, b"focus_precise"));
    }

    #[test]
    fn marker_wraps_two_trace_packets() {
        // Two field-1 (0x0a) TracePacket submessages at the top level.
        let m = build_marker(&[1], None, false, 0);
        let count = m.iter().filter(|&&b| b == 0x0a).count();
        assert!(count >= 2, "expected two Trace.packet submessages");
    }
}
