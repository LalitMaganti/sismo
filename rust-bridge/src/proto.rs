// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Minimal protobuf wire-format encoder (Rust port of proto_writer.zig) plus
//! the trace-packet encoders migrated off perfetto_proto.zig. Field tags come
//! from the Perfetto protos; see the Zig comments in perfetto_proto.zig.
//!
//! wire types: 0 = VARINT, 2 = LEN (length-delimited).

use std::slice;

/// Length-delimited protobuf encoder over a growable byte buffer. Nested
/// messages are encoded into their own writer, then `write_message`'d into the
/// parent with a length prefix.
pub struct ProtoWriter {
    buf: Vec<u8>,
}

impl ProtoWriter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    fn write_varint(&mut self, mut v: u64) {
        while v >= 0x80 {
            self.buf.push(((v & 0x7f) | 0x80) as u8);
            v >>= 7;
        }
        self.buf.push((v & 0x7f) as u8);
    }

    fn write_tag(&mut self, field: u32, wire: u8) {
        self.write_varint(((field as u64) << 3) | wire as u64);
    }

    pub fn write_uint64(&mut self, field: u32, value: u64) {
        self.write_tag(field, 0);
        self.write_varint(value);
    }

    pub fn write_uint32(&mut self, field: u32, value: u32) {
        self.write_tag(field, 0);
        self.write_varint(value as u64);
    }

    pub fn write_string(&mut self, field: u32, bytes: &[u8]) {
        self.write_tag(field, 2);
        self.write_varint(bytes.len() as u64);
        self.buf.extend_from_slice(bytes);
    }

    pub fn write_message(&mut self, field: u32, msg: &[u8]) {
        self.write_tag(field, 2);
        self.write_varint(msg.len() as u64);
        self.buf.extend_from_slice(msg);
    }
}

impl Default for ProtoWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// A borrowed byte string passed across FFI (e.g. a follower counter name).
#[repr(C)]
pub struct SismoStr {
    pub ptr: *const u8,
    pub len: usize,
}

impl SismoStr {
    unsafe fn as_slice(&self) -> &[u8] {
        if self.ptr.is_null() {
            &[]
        } else {
            unsafe { slice::from_raw_parts(self.ptr, self.len) }
        }
    }
}

unsafe fn opt_slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(ptr, len) }
    }
}

/// Build a TracePacket carrying PerfSampleDefaults, ready to hand to
/// sismo_ds_emit. Replaces the encodePerfSampleDefaults + encodeTracePacket
/// Defaults + encodeTracePacketBody chain in linux_bpf_capture's emitDefaults.
///
/// Layout:
///   TracePacket {
///     sequence_flags = 13 (omitted if 0),
///     trace_packet_defaults = 59 : TracePacketDefaults {
///       timestamp_clock_id = 58 (omitted if 0),
///       perf_sample_defaults = 12 : PerfSampleDefaults {
///         timebase = 1 : Timebase { frequency = 2 (omitted if 0), name = 10 },
///         followers = 4 (repeated) : FollowerEvent { name = 4 },
///         sample_scope = 5 (omitted if 0),
///       },
///     },
///   }
///
/// Writes into out[..cap]; returns bytes written, or 0 if cap is too small.
///
/// # Safety
/// `timebase_name`/`followers` must be valid for their lengths (or null);
/// `out` must be writable for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_encode_perf_defaults_packet(
    timebase_name: *const u8,
    timebase_name_len: usize,
    timebase_freq: u64,
    followers: *const SismoStr,
    followers_count: usize,
    sample_scope: u32,
    timestamp_clock_id: u32,
    sequence_flags: u32,
    out: *mut u8,
    cap: usize,
) -> usize {
    let mut psd = ProtoWriter::new();
    {
        let mut tb = ProtoWriter::new();
        if timebase_freq != 0 {
            tb.write_uint64(2, timebase_freq);
        }
        tb.write_string(10, unsafe { opt_slice(timebase_name, timebase_name_len) });
        psd.write_message(1, tb.bytes());
    }
    let follower_slice = if followers.is_null() {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(followers, followers_count) }
    };
    for f in follower_slice {
        let mut fe = ProtoWriter::new();
        fe.write_string(4, unsafe { f.as_slice() });
        psd.write_message(4, fe.bytes());
    }
    if sample_scope != 0 {
        psd.write_uint32(5, sample_scope);
    }

    let mut tpd = ProtoWriter::new();
    if timestamp_clock_id != 0 {
        tpd.write_uint32(58, timestamp_clock_id);
    }
    tpd.write_message(12, psd.bytes());

    let mut body = ProtoWriter::new();
    if sequence_flags != 0 {
        body.write_uint32(13, sequence_flags);
    }
    body.write_message(59, tpd.bytes());

    let b = body.bytes();
    if b.len() > cap {
        return 0;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(b.as_ptr(), out, b.len());
    }
    b.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        let mut w = ProtoWriter::new();
        w.write_uint64(1, 150);
        // tag = 1<<3|0 = 0x08; varint(150) = 0x96 0x01
        assert_eq!(w.bytes(), &[0x08, 0x96, 0x01]);
    }

    #[test]
    fn perf_defaults_packet_bytes_are_exact() {
        // timebase name "x", no freq, no followers, scope=thread(2),
        // clock=MONOTONIC(3), seq=INCREMENTAL_STATE_CLEARED(1).
        let mut out = [0u8; 256];
        let n = unsafe {
            sismo_encode_perf_defaults_packet(
                b"x".as_ptr(),
                1,
                0,
                std::ptr::null(),
                0,
                2,
                3,
                1,
                out.as_mut_ptr(),
                out.len(),
            )
        };
        // Hand-computed wire bytes (see the layout doc above):
        //   seq_flags(13,varint)=1                -> 68 01
        //   trace_packet_defaults(59,len=12)      -> DA 03 0C
        //     timestamp_clock_id(58,varint)=3     -> D0 03 03
        //     perf_sample_defaults(12,len=7)      -> 62 07
        //       timebase(1,len=3)                 -> 0A 03
        //         name(10,len=1)="x"              -> 52 01 78
        //       sample_scope(5,varint)=2          -> 28 02
        let expected: &[u8] = &[
            0x68, 0x01, 0xDA, 0x03, 0x0C, 0xD0, 0x03, 0x03, 0x62, 0x07, 0x0A, 0x03, 0x52, 0x01,
            0x78, 0x28, 0x02,
        ];
        assert_eq!(&out[..n], expected);
    }

    #[test]
    fn perf_defaults_packet_with_followers() {
        let followers = [
            SismoStr { ptr: b"a".as_ptr(), len: 1 },
            SismoStr { ptr: b"bb".as_ptr(), len: 2 },
        ];
        let mut out = [0u8; 256];
        let n = unsafe {
            sismo_encode_perf_defaults_packet(
                b"tb".as_ptr(),
                2,
                0,
                followers.as_ptr(),
                followers.len(),
                2,
                3,
                1,
                out.as_mut_ptr(),
                out.len(),
            )
        };
        // Each follower is FollowerEvent{name(4)}: "a" -> 22 03 22 01 61,
        // "bb" -> 22 04 22 02 62 62 (field 4 = 0x22).
        let got = &out[..n];
        assert!(got.windows(5).any(|w| w == [0x22, 0x03, 0x22, 0x01, 0x61]));
        assert!(got.windows(6).any(|w| w == [0x22, 0x04, 0x22, 0x02, 0x62, 0x62]));
    }

    #[test]
    fn returns_zero_when_buffer_too_small() {
        let mut out = [0u8; 4];
        let n = unsafe {
            sismo_encode_perf_defaults_packet(
                b"x".as_ptr(), 1, 0, std::ptr::null(), 0, 2, 3, 1, out.as_mut_ptr(), out.len(),
            )
        };
        assert_eq!(n, 0);
    }
}
