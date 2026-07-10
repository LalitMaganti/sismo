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

    /// proto `int32`: matches proto_writer.zig's writeInt32, which bit-casts
    /// to u32 and varint-encodes that (so -1 is the 5-byte 0xFFFFFFFF, NOT the
    /// 10-byte 64-bit sign-extension the proto spec nominally uses for int32).
    pub fn write_int32(&mut self, field: u32, value: i32) {
        self.write_uint32(field, value as u32);
    }

    pub fn write_int64(&mut self, field: u32, value: i64) {
        self.write_uint64(field, value as u64);
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

/// The value of a single protobuf field, borrowed from the source buffer.
pub enum WireValue<'a> {
    Varint(u64),
    Fixed64([u8; 8]),
    Len(&'a [u8]),
    Fixed32([u8; 4]),
}

/// Iterator over the fields of a protobuf message: yields `(field_number,
/// WireValue)` for each field in order. Malformed/truncated input simply ends
/// iteration (no panic). Nest by calling `ProtoReader::new` on a `Len` payload.
pub struct ProtoReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ProtoReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_varint(&mut self) -> Option<u64> {
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        while self.pos < self.buf.len() {
            let b = self.buf[self.pos];
            self.pos += 1;
            value |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Some(value);
            }
            shift += 7;
            if shift >= 64 {
                return None;
            }
        }
        None
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Some(s)
    }
}

impl<'a> Iterator for ProtoReader<'a> {
    type Item = (u32, WireValue<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        let tag = self.read_varint()?;
        let field = (tag >> 3) as u32;
        let value = match tag & 0x07 {
            0 => WireValue::Varint(self.read_varint()?),
            1 => WireValue::Fixed64(self.take(8)?.try_into().ok()?),
            2 => {
                let len = self.read_varint()? as usize;
                WireValue::Len(self.take(len)?)
            }
            5 => WireValue::Fixed32(self.take(4)?.try_into().ok()?),
            _ => return None, // unknown wire type — stop
        };
        Some((field, value))
    }
}

#[cfg(test)]
mod reader_tests {
    use super::*;

    #[test]
    fn reads_back_what_the_writer_wrote() {
        let mut w = ProtoWriter::new();
        w.write_uint64(1, 150);
        w.write_string(2, b"hi");
        w.write_uint32(3, 7);
        let mut seen = vec![];
        for (f, v) in ProtoReader::new(w.bytes()) {
            match (f, v) {
                (1, WireValue::Varint(n)) => seen.push(format!("v1={n}")),
                (2, WireValue::Len(s)) => seen.push(format!("s2={}", std::str::from_utf8(s).unwrap())),
                (3, WireValue::Varint(n)) => seen.push(format!("v3={n}")),
                _ => panic!("unexpected field"),
            }
        }
        assert_eq!(seen, vec!["v1=150", "s2=hi", "v3=7"]);
    }

    #[test]
    fn nested_messages_and_truncation() {
        let mut inner = ProtoWriter::new();
        inner.write_string(1, b"name");
        let mut outer = ProtoWriter::new();
        outer.write_message(2, inner.bytes());
        let mut names = vec![];
        for (f, v) in ProtoReader::new(outer.bytes()) {
            if let (2, WireValue::Len(msg)) = (f, v) {
                for (f2, v2) in ProtoReader::new(msg) {
                    if let (1, WireValue::Len(s)) = (f2, v2) {
                        names.push(s.to_vec());
                    }
                }
            }
        }
        assert_eq!(names, vec![b"name".to_vec()]);
        // Truncated input ends iteration without panicking.
        let count = ProtoReader::new(&[0x0a, 0x05, 0x01]).count(); // len=5 but only 1 byte
        assert_eq!(count, 0);
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
/// Returns the encoded TracePacket bytes.
pub fn encode_perf_defaults_packet(
    timebase_name: &[u8],
    timebase_freq: u64,
    followers: &[&[u8]],
    sample_scope: u32,
    timestamp_clock_id: u32,
    sequence_flags: u32,
) -> Vec<u8> {
    let mut psd = ProtoWriter::new();
    {
        let mut tb = ProtoWriter::new();
        if timebase_freq != 0 {
            tb.write_uint64(2, timebase_freq);
        }
        tb.write_string(10, timebase_name);
        psd.write_message(1, tb.bytes());
    }
    for f in followers {
        let mut fe = ProtoWriter::new();
        fe.write_string(4, f);
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
    body.bytes().to_vec()
}

/// Encode a PerfSample (TracePacket field 66 body). Fields: cpu=1, pid=2,
/// tid=3, callstack_iid=4, timebase_count=6, follower_counts=7 (repeated),
/// data_address=20, data_symbol=21 (the last two are sismo extensions).
/// Fields are omitted when 0 / absent (null pointer). Writes into out[..cap];
/// returns bytes written, or 0 if cap is too small.
///
/// # Safety
/// `follower_counts`/`data_symbol` must be valid for their lengths or null;
/// `out` must be writable for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_encode_perf_sample(
    cpu: u32,
    pid: u32,
    tid: u32,
    callstack_iid: u64,
    timebase_count: u64,
    follower_counts: *const u64,
    follower_count: usize,
    data_address: u64,
    data_symbol: *const u8,
    data_symbol_len: usize,
    out: *mut u8,
    cap: usize,
) -> usize {
    let mut w = ProtoWriter::new();
    w.write_uint32(1, cpu);
    w.write_uint32(2, pid);
    w.write_uint32(3, tid);
    if callstack_iid != 0 {
        w.write_uint64(4, callstack_iid);
    }
    if timebase_count != 0 {
        w.write_uint64(6, timebase_count);
    }
    if !follower_counts.is_null() {
        for &fc in unsafe { slice::from_raw_parts(follower_counts, follower_count) } {
            w.write_uint64(7, fc);
        }
    }
    if data_address != 0 {
        w.write_uint64(20, data_address);
    }
    if !data_symbol.is_null() {
        w.write_string(21, unsafe { slice::from_raw_parts(data_symbol, data_symbol_len) });
    }

    let b = w.bytes();
    if b.len() > cap {
        return 0;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(b.as_ptr(), out, b.len());
    }
    b.len()
}

/// Encode a GenericKernelTaskStateEvent (TracePacket field 117 body). Fields:
/// cpu=1 (int32, always written), comm=2 (string, capped at 64 bytes, omitted
/// when empty), tid=3 (int64), state=4 (enum/uint32), prio=5 (int32). Writes
/// into out[..cap]; returns bytes written, or 0 if cap is too small.
///
/// # Safety
/// `comm` must be valid for `comm_len` bytes or null; `out` must be writable
/// for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_encode_kernel_task_state_event(
    cpu: i32,
    comm: *const u8,
    comm_len: usize,
    tid: i64,
    state: u32,
    prio: i32,
    out: *mut u8,
    cap: usize,
) -> usize {
    let mut w = ProtoWriter::new();
    w.write_int32(1, cpu);
    if !comm.is_null() && comm_len > 0 {
        // Cap comm at 64 bytes (Mach thread name max in practice), matching
        // the prior Zig encoder.
        let capped = comm_len.min(64);
        w.write_string(2, unsafe { slice::from_raw_parts(comm, capped) });
    }
    w.write_int64(3, tid);
    w.write_uint32(4, state);
    w.write_int32(5, prio);

    let b = w.bytes();
    if b.len() > cap {
        return 0;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(b.as_ptr(), out, b.len());
    }
    b.len()
}

/// Encode a TracePacket body: optional timestamp (field 8, omitted when 0),
/// optional sequence_flags (field 13, omitted when 0), then the already-encoded
/// `payload` wrapped as length-delimited field `payload_field_tag` (e.g. 66 =
/// perf_sample, 117 = generic_kernel_task_state_event). Writes into out[..cap];
/// returns bytes written, or 0 if cap is too small.
///
/// # Safety
/// `payload` must be valid for `payload_len` bytes or null; `out` must be
/// writable for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_encode_trace_packet_body(
    timestamp_ns: u64,
    sequence_flags: u32,
    payload_field_tag: u32,
    payload: *const u8,
    payload_len: usize,
    out: *mut u8,
    cap: usize,
) -> usize {
    let mut w = ProtoWriter::new();
    if timestamp_ns != 0 {
        w.write_uint64(8, timestamp_ns);
    }
    if sequence_flags != 0 {
        w.write_uint32(13, sequence_flags);
    }
    let payload_slice: &[u8] = if payload.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(payload, payload_len) }
    };
    w.write_message(payload_field_tag, payload_slice);

    let b = w.bytes();
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
    fn perf_sample_bytes_are_exact() {
        // cpu=1, pid=2, tid=3, callstack_iid=5; no timebase/followers/data.
        let mut out = [0u8; 64];
        let n = unsafe {
            sismo_encode_perf_sample(
                1, 2, 3, 5, 0, std::ptr::null(), 0, 0, std::ptr::null(), 0,
                out.as_mut_ptr(), out.len(),
            )
        };
        // cpu(1)=1: 08 01; pid(2)=2: 10 02; tid(3)=3: 18 03; callstack(4)=5: 20 05
        assert_eq!(&out[..n], &[0x08, 0x01, 0x10, 0x02, 0x18, 0x03, 0x20, 0x05]);
    }

    #[test]
    fn perf_sample_followers_and_data_symbol() {
        let followers = [100u64, 200u64];
        let mut out = [0u8; 64];
        let n = unsafe {
            sismo_encode_perf_sample(
                0, 0, 0, 0, 0, followers.as_ptr(), followers.len(), 0xdead,
                b"[heap]".as_ptr(), 6, out.as_mut_ptr(), out.len(),
            )
        };
        let got = &out[..n];
        // follower_counts field 7 (tag 0x38): 38 64 (100), 38 C8 01 (200).
        assert!(got.windows(2).any(|w| w == [0x38, 0x64]));
        assert!(got.windows(3).any(|w| w == [0x38, 0xC8, 0x01]));
        // data_symbol field 21 (tag 0xAA 0x01, len 6) = "[heap]".
        assert!(got.windows(3).any(|w| w == [0xAA, 0x01, 0x06]));
    }

    #[test]
    fn kernel_task_state_event_bytes_are_exact() {
        // cpu=3, comm="foo", tid=42, state=3 (running), prio=31.
        let mut out = [0u8; 64];
        let n = unsafe {
            sismo_encode_kernel_task_state_event(
                3, b"foo".as_ptr(), 3, 42, 3, 31, out.as_mut_ptr(), out.len(),
            )
        };
        // cpu(1)=3: 08 03; comm(2)="foo": 12 03 66 6F 6F; tid(3)=42: 18 2A;
        // state(4)=3: 20 03; prio(5)=31: 28 1F.
        assert_eq!(
            &out[..n],
            &[0x08, 0x03, 0x12, 0x03, 0x66, 0x6F, 0x6F, 0x18, 0x2A, 0x20, 0x03, 0x28, 0x1F],
        );
    }

    #[test]
    fn kernel_task_state_event_negative_int32_is_bitcast_not_sign_extended() {
        // cpu=-1 must encode as the 5-byte u32 bitcast (FF FF FF FF 0F), not
        // the 10-byte 64-bit sign-extension — matching proto_writer.zig.
        let mut out = [0u8; 64];
        let n = unsafe {
            sismo_encode_kernel_task_state_event(
                -1, std::ptr::null(), 0, 0, 0, 0, out.as_mut_ptr(), out.len(),
            )
        };
        // cpu(1)=-1: 08 FF FF FF FF 0F; comm omitted (null); tid(3)=0: 18 00;
        // state(4)=0: 20 00; prio(5)=0: 28 00.
        assert_eq!(
            &out[..n],
            &[0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x18, 0x00, 0x20, 0x00, 0x28, 0x00],
        );
    }

    #[test]
    fn kernel_task_state_event_comm_capped_at_64() {
        let comm = [b'a'; 100];
        let mut out = [0u8; 128];
        let n = unsafe {
            sismo_encode_kernel_task_state_event(
                0, comm.as_ptr(), comm.len(), 0, 0, 0, out.as_mut_ptr(), out.len(),
            )
        };
        let got = &out[..n];
        // comm field 2 (tag 0x12) with length 64 (0x40).
        assert!(got.windows(2).any(|w| w == [0x12, 0x40]));
    }

    #[test]
    fn trace_packet_body_wraps_payload_with_timestamp_and_flags() {
        // timestamp=150, sequence_flags=1, payload=[0xAB] under field 66.
        let mut out = [0u8; 64];
        let n = unsafe {
            sismo_encode_trace_packet_body(
                150, 1, 66, [0xABu8].as_ptr(), 1, out.as_mut_ptr(), out.len(),
            )
        };
        // timestamp(8)=150: 40 96 01; sequence_flags(13)=1: 68 01;
        // payload(66) len 1: tag=66<<3|2=0x212 -> 92 04, len 01, byte AB.
        assert_eq!(&out[..n], &[0x40, 0x96, 0x01, 0x68, 0x01, 0x92, 0x04, 0x01, 0xAB]);
    }

    #[test]
    fn trace_packet_body_omits_zero_timestamp_and_flags() {
        // timestamp=0 and sequence_flags=0 are both omitted (Into-variant case).
        let mut out = [0u8; 64];
        let n = unsafe {
            sismo_encode_trace_packet_body(
                0, 0, 117, [0x01u8, 0x02].as_ptr(), 2, out.as_mut_ptr(), out.len(),
            )
        };
        // Only payload(117) len 2: tag=117<<3|2=0x3AA -> AA 07, len 02, 01 02.
        assert_eq!(&out[..n], &[0xAA, 0x07, 0x02, 0x01, 0x02]);
    }

    #[test]
    fn trace_packet_body_returns_zero_when_cap_too_small() {
        let mut out = [0u8; 4];
        let n = unsafe {
            sismo_encode_trace_packet_body(
                150, 0, 66, [0xAAu8; 8].as_ptr(), 8, out.as_mut_ptr(), out.len(),
            )
        };
        assert_eq!(n, 0);
    }

    #[test]
    fn perf_defaults_packet_bytes_are_exact() {
        // timebase name "x", no freq, no followers, scope=thread(2),
        // clock=MONOTONIC(3), seq=INCREMENTAL_STATE_CLEARED(1).
        let got = encode_perf_defaults_packet(b"x", 0, &[], 2, 3, 1);
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
        assert_eq!(got, expected);
    }

    #[test]
    fn perf_defaults_packet_with_followers() {
        let followers: [&[u8]; 2] = [b"a", b"bb"];
        let got = encode_perf_defaults_packet(b"tb", 0, &followers, 2, 3, 1);
        // Each follower is FollowerEvent{name(4)}: "a" -> 22 03 22 01 61,
        // "bb" -> 22 04 22 02 62 62 (field 4 = 0x22).
        assert!(got.windows(5).any(|w| w == [0x22, 0x03, 0x22, 0x01, 0x61]));
        assert!(got.windows(6).any(|w| w == [0x22, 0x04, 0x22, 0x02, 0x62, 0x62]));
    }
}
