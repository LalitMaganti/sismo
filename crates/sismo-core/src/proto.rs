// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Minimal protobuf wire-format encoder (Rust port of proto_writer.zig) plus
//! the trace-packet encoders migrated off perfetto_proto.zig. Field tags come
//! from the Perfetto protos; see the Zig comments in perfetto_proto.zig.
//!
//! wire types: 0 = VARINT, 2 = LEN (length-delimited).


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

    /// Write a length-delimited sub-message built in place by `f`, with no
    /// intermediate buffer. See [`ProtoWriter::begin_message`] for how the
    /// length prefix is handled.
    pub fn message(&mut self, field: u32, f: impl FnOnce(&mut ProtoWriter)) {
        let marker = self.begin_message(field);
        f(self);
        self.end_message(marker);
    }

    /// Open a length-delimited sub-message: write the tag and reserve a fixed
    /// [`RESERVED_LEN`]-byte length slot. The body is written straight into this
    /// buffer; [`ProtoWriter::end_message`] backfills the length. Reserving a
    /// fixed width means the length can be patched in place with no memmove —
    /// at the cost of a non-minimal (redundant) varint, which protobuf readers
    /// accept. Returns a marker to pass to `end_message`.
    pub fn begin_message(&mut self, field: u32) -> usize {
        self.write_tag(field, 2);
        let marker = self.buf.len();
        self.buf.extend_from_slice(&[0u8; RESERVED_LEN]);
        marker
    }

    /// Close a sub-message opened by [`ProtoWriter::begin_message`], backfilling
    /// its content length as a fixed-width redundant varint.
    pub fn end_message(&mut self, marker: usize) {
        let len = (self.buf.len() - marker - RESERVED_LEN) as u64;
        debug_assert!(len < (1 << (7 * RESERVED_LEN)), "sub-message too large for the reserved length");
        for i in 0..RESERVED_LEN - 1 {
            self.buf[marker + i] = (((len >> (7 * i)) & 0x7f) as u8) | 0x80;
        }
        self.buf[marker + RESERVED_LEN - 1] = ((len >> (7 * (RESERVED_LEN - 1))) & 0x7f) as u8;
    }
}

/// Fixed width reserved for a sub-message length prefix. 5 bytes = 35 bits,
/// covering any packet-sized message (up to 32 GiB) as a redundant varint.
const RESERVED_LEN: usize = 5;

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


/// Write a TracePacket carrying PerfSampleDefaults into `w`, ready to hand to
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
pub fn write_perf_defaults_packet(
    w: &mut ProtoWriter,
    timebase_name: &[u8],
    timebase_freq: u64,
    followers: &[&[u8]],
    sample_scope: u32,
    timestamp_clock_id: u32,
    sequence_flags: u32,
) {
    if sequence_flags != 0 {
        w.write_uint32(13, sequence_flags);
    }
    w.message(59, |tpd| {
        if timestamp_clock_id != 0 {
            tpd.write_uint32(58, timestamp_clock_id);
        }
        tpd.message(12, |psd| {
            psd.message(1, |tb| {
                if timebase_freq != 0 {
                    tb.write_uint64(2, timebase_freq);
                }
                tb.write_string(10, timebase_name);
            });
            for f in followers {
                psd.message(4, |fe| fe.write_string(4, f));
            }
            if sample_scope != 0 {
                psd.write_uint32(5, sample_scope);
            }
        });
    });
}

/// Write a PerfSample as length-delimited field `field` of the current message.
/// PerfSample fields: cpu=1, pid=2, tid=3, callstack_iid=4, timebase_count=6,
/// follower_counts=7 (repeated), data_address=20, data_symbol=21 (the last two
/// are sismo extensions). Fields are omitted when 0 / absent.
#[allow(clippy::too_many_arguments)]
pub fn write_perf_sample(
    w: &mut ProtoWriter,
    field: u32,
    cpu: u32,
    pid: u32,
    tid: u32,
    callstack_iid: u64,
    timebase_count: u64,
    follower_counts: &[u64],
    data_address: u64,
    data_symbol: Option<&[u8]>,
) {
    w.message(field, |m| {
        m.write_uint32(1, cpu);
        m.write_uint32(2, pid);
        m.write_uint32(3, tid);
        if callstack_iid != 0 {
            m.write_uint64(4, callstack_iid);
        }
        if timebase_count != 0 {
            m.write_uint64(6, timebase_count);
        }
        for &fc in follower_counts {
            m.write_uint64(7, fc);
        }
        if data_address != 0 {
            m.write_uint64(20, data_address);
        }
        if let Some(sym) = data_symbol {
            m.write_string(21, sym);
        }
    });
}

/// Write a GenericKernelTaskStateEvent as length-delimited field `field` of the
/// current message. Event fields: cpu=1 (int32, always written), comm=2 (string,
/// capped at 64 bytes, omitted when empty), tid=3 (int64), state=4 (enum/uint32),
/// prio=5 (int32).
pub fn write_kernel_task_state_event(
    w: &mut ProtoWriter,
    field: u32,
    cpu: i32,
    comm: &[u8],
    tid: i64,
    state: u32,
    prio: i32,
) {
    w.message(field, |m| {
        m.write_int32(1, cpu);
        if !comm.is_empty() {
            // Cap comm at 64 bytes (Mach thread name max in practice).
            let capped = comm.len().min(64);
            m.write_string(2, &comm[..capped]);
        }
        m.write_int64(3, tid);
        m.write_uint32(4, state);
        m.write_int32(5, prio);
    });
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

    /// Collect all `(field, WireValue)` pairs of a message into a Vec.
    fn fields(buf: &[u8]) -> Vec<(u32, WireValue<'_>)> {
        ProtoReader::new(buf).collect()
    }

    /// Return the payload of the first LEN-typed field `field`, or panic.
    fn sub<'a>(buf: &'a [u8], field: u32) -> &'a [u8] {
        for (f, v) in ProtoReader::new(buf) {
            if f == field {
                if let WireValue::Len(s) = v {
                    return s;
                }
            }
        }
        panic!("no LEN field {field}");
    }

    /// Return the varint of the first VARINT-typed field `field`, or panic.
    fn varint(buf: &[u8], field: u32) -> u64 {
        for (f, v) in ProtoReader::new(buf) {
            if f == field {
                if let WireValue::Varint(n) = v {
                    return n;
                }
            }
        }
        panic!("no VARINT field {field}");
    }

    #[test]
    fn perf_sample_fields_round_trip() {
        // cpu=1, pid=2, tid=3, callstack_iid=5; no timebase/followers/data.
        let mut w = ProtoWriter::new();
        write_perf_sample(&mut w, 66, 1, 2, 3, 5, 0, &[], 0, None);
        let ps = sub(w.bytes(), 66);
        assert_eq!(varint(ps, 1), 1);
        assert_eq!(varint(ps, 2), 2);
        assert_eq!(varint(ps, 3), 3);
        assert_eq!(varint(ps, 4), 5);
        // callstack_iid=0 / timebase_count=0 / data are omitted.
        assert!(!fields(ps).iter().any(|(f, _)| *f == 6 || *f == 20 || *f == 21));
    }

    #[test]
    fn perf_sample_followers_and_data_symbol() {
        let mut w = ProtoWriter::new();
        write_perf_sample(&mut w, 66, 0, 0, 0, 0, 0, &[100, 200], 0xdead, Some(b"[heap]"));
        let ps = sub(w.bytes(), 66);
        let follower_counts: Vec<u64> = ProtoReader::new(ps)
            .filter_map(|(f, v)| match (f, v) {
                (7, WireValue::Varint(n)) => Some(n),
                _ => None,
            })
            .collect();
        assert_eq!(follower_counts, vec![100, 200]);
        assert_eq!(varint(ps, 20), 0xdead);
        assert_eq!(sub(ps, 21), b"[heap]");
    }

    #[test]
    fn kernel_task_state_event_fields_round_trip() {
        // cpu=3, comm="foo", tid=42, state=3 (running), prio=31.
        let mut w = ProtoWriter::new();
        write_kernel_task_state_event(&mut w, 117, 3, b"foo", 42, 3, 31);
        let ev = sub(w.bytes(), 117);
        assert_eq!(varint(ev, 1), 3);
        assert_eq!(sub(ev, 2), b"foo");
        assert_eq!(varint(ev, 3), 42);
        assert_eq!(varint(ev, 4), 3);
        assert_eq!(varint(ev, 5), 31);
    }

    #[test]
    fn kernel_task_state_event_negative_int32_is_bitcast_not_sign_extended() {
        // cpu=-1 must encode as the 5-byte u32 bitcast (FF FF FF FF 0F), not
        // the 10-byte 64-bit sign-extension. comm empty -> field 2 omitted.
        let mut w = ProtoWriter::new();
        write_kernel_task_state_event(&mut w, 117, -1, b"", 0, 0, 0);
        let ev = sub(w.bytes(), 117);
        // cpu(1)=-1: 08 FF FF FF FF 0F (5-byte varint), then tid/state/prio=0.
        assert_eq!(&ev[..6], [0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F]);
        assert!(!fields(ev).iter().any(|(f, _)| *f == 2));
        assert_eq!(varint(ev, 1) as u32, u32::MAX);
    }

    #[test]
    fn kernel_task_state_event_comm_capped_at_64() {
        let mut w = ProtoWriter::new();
        write_kernel_task_state_event(&mut w, 117, 0, &[b'a'; 100], 0, 0, 0);
        assert_eq!(sub(sub(w.bytes(), 117), 2).len(), 64);
    }

    #[test]
    fn perf_defaults_packet_round_trips() {
        // timebase name "x", no freq, no followers, scope=thread(2),
        // clock=MONOTONIC(3), seq=INCREMENTAL_STATE_CLEARED(1).
        let mut w = ProtoWriter::new();
        write_perf_defaults_packet(&mut w, b"x", 0, &[], 2, 3, 1);
        assert_eq!(varint(w.bytes(), 13), 1); // sequence_flags
        let tpd = sub(w.bytes(), 59);
        assert_eq!(varint(tpd, 58), 3); // timestamp_clock_id
        let psd = sub(tpd, 12);
        assert_eq!(varint(psd, 5), 2); // sample_scope
        let tb = sub(psd, 1);
        assert_eq!(sub(tb, 10), b"x"); // timebase name
        assert!(!fields(tb).iter().any(|(f, _)| *f == 2)); // freq=0 omitted
        assert!(!fields(psd).iter().any(|(f, _)| *f == 4)); // no followers
    }

    #[test]
    fn perf_defaults_packet_with_followers() {
        let followers: [&[u8]; 2] = [b"a", b"bb"];
        let mut w = ProtoWriter::new();
        write_perf_defaults_packet(&mut w, b"tb", 0, &followers, 2, 3, 1);
        let psd = sub(sub(w.bytes(), 59), 12);
        let names: Vec<Vec<u8>> = ProtoReader::new(psd)
            .filter_map(|(f, v)| match (f, v) {
                (4, WireValue::Len(fe)) => Some(sub(fe, 4).to_vec()),
                _ => None,
            })
            .collect();
        assert_eq!(names, vec![b"a".to_vec(), b"bb".to_vec()]);
    }
}
