// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Encodes sismo-heap's aggregated allocations into Perfetto
//! ProfilePacket TracePackets. trace_processor populates the
//! `heap_profile_allocation` table from these.
//!
//! Interned tables (strings/mappings/frames/callstacks) are embedded
//! INSIDE profile_packet using the legacy Android-Q field layout —
//! trace_processor's profile parser reads them from there, not from
//! TracePacket.interned_data.
//!
//! Field numbers cross-referenced from the vendored protos in
//! third_party/src/perfetto/protos/perfetto/trace/...

const std = @import("std");
const proto = @import("proto_writer.zig");

// ---- Field number constants (extracted from the vendored .proto files) ----

// Trace
const TRACE_PACKET = 1;

// TracePacket
const TP_CLOCK_SNAPSHOT = 6;
const TP_PROFILE_PACKET = 37;
const SEQ_INCREMENTAL_STATE_CLEARED: u32 = 1;

// ClockSnapshot
const CS_CLOCKS = 1;
// Clock
const CLOCK_CLOCK_ID = 1;
const CLOCK_TIMESTAMP = 2;
// BuiltinClock IDs (from protos/perfetto/common/builtin_clock.proto).
const BUILTIN_CLOCK_BOOTTIME: u32 = 6;
const BUILTIN_CLOCK_MONOTONIC_COARSE: u32 = 4;

// InternedString
const IS_IID = 1;
const IS_STR = 2;

// Mapping
const MAP_IID = 1;
const MAP_START = 4;
const MAP_END = 5;
const MAP_LOAD_BIAS = 6;
const MAP_PATH_STRING_IDS = 7;

// Frame
const FRAME_IID = 1;
const FRAME_FUNCTION_NAME_ID = 2;
const FRAME_MAPPING_ID = 3;
const FRAME_REL_PC = 4;

// Callstack
const CS_IID = 1;
const CS_FRAME_IDS = 2;

// ProfilePacket — legacy Android-Q-style embedded interned tables.
// trace_processor's profile parser ONLY reads these (not the modern
// TracePacket.interned_data fields). All strings (function names AND
// mapping paths) share one iid space in PP_STRINGS.
const PP_STRINGS = 1; // repeated InternedString
const PP_FRAMES = 2; // repeated Frame
const PP_CALLSTACKS = 3; // repeated Callstack
const PP_MAPPINGS = 4; // repeated Mapping
const PP_PROCESS_DUMPS = 5;

// ProcessHeapSamples
const PHS_PID = 1;
const PHS_SAMPLES = 2;
const PHS_TIMESTAMP = 9;
const PHS_HEAP_NAME = 11;
const PHS_SAMPLING_INTERVAL_BYTES = 12;

// HeapSample
const HS_CALLSTACK_ID = 1;
const HS_SELF_ALLOCATED = 2;
const HS_ALLOC_COUNT = 5;

// ---- Public input types --------------------------------------------------

pub const Mapping = struct {
    iid: u64,
    path_string_iid: u64, // ref into mapping_paths string table
    start: u64,
    end: u64,
    load_bias: u64,
};

pub const Frame = struct {
    iid: u64,
    function_name_iid: u64, // ref into function_names string table
    mapping_iid: u64,
    rel_pc: u64,
};

pub const Callstack = struct {
    iid: u64,
    frame_iids: []const u64,
};

pub const HeapSample = struct {
    callstack_iid: u64,
    self_allocated: u64,
    alloc_count: u64,
};

pub const TraceData = struct {
    pid: u32,
    sampling_interval_bytes: u64,
    timestamp_ns: u64,
    /// Single unified string pool. iid = index + 1. Frame.function_name_iid
    /// and Mapping.path_string_iid both reference this same pool.
    strings: []const []const u8,
    mappings: []const Mapping,
    frames: []const Frame,
    callstacks: []const Callstack,
    samples: []const HeapSample,
};

// ---- Encoding ------------------------------------------------------------

// Leaf encoders write their fields into a caller-owned scratch writer;
// the caller copies the result into the parent with `writeMessage`, so
// no per-submessage heap slice is allocated.

fn encodeInternedStringInto(w: *proto.ProtoWriter, iid: u64, str: []const u8) !void {
    try w.writeUint64(IS_IID, iid);
    try w.writeString(IS_STR, str);
}

fn encodeMappingInto(w: *proto.ProtoWriter, m: Mapping) !void {
    try w.writeUint64(MAP_IID, m.iid);
    try w.writeUint64(MAP_START, m.start);
    try w.writeUint64(MAP_END, m.end);
    try w.writeUint64(MAP_LOAD_BIAS, m.load_bias);
    // path_string_ids is repeated; emit one entry.
    try w.writeUint64(MAP_PATH_STRING_IDS, m.path_string_iid);
}

fn encodeFrameInto(w: *proto.ProtoWriter, f: Frame) !void {
    try w.writeUint64(FRAME_IID, f.iid);
    try w.writeUint64(FRAME_FUNCTION_NAME_ID, f.function_name_iid);
    try w.writeUint64(FRAME_MAPPING_ID, f.mapping_iid);
    try w.writeUint64(FRAME_REL_PC, f.rel_pc);
}

fn encodeCallstackInto(w: *proto.ProtoWriter, cs: Callstack) !void {
    try w.writeUint64(CS_IID, cs.iid);
    for (cs.frame_iids) |fid| try w.writeUint64(CS_FRAME_IDS, fid);
}

fn encodeHeapSampleInto(w: *proto.ProtoWriter, s: HeapSample) !void {
    try w.writeUint64(HS_CALLSTACK_ID, s.callstack_iid);
    try w.writeUint64(HS_SELF_ALLOCATED, s.self_allocated);
    try w.writeUint64(HS_ALLOC_COUNT, s.alloc_count);
}

fn encodeProcessHeapSamplesInto(
    w: *proto.ProtoWriter,
    scratch: *proto.ProtoWriter,
    td: TraceData,
) !void {
    try w.writeUint64(PHS_PID, td.pid);
    try w.writeUint64(PHS_TIMESTAMP, td.timestamp_ns);
    try w.writeString(PHS_HEAP_NAME, "libc.malloc");
    try w.writeUint64(PHS_SAMPLING_INTERVAL_BYTES, td.sampling_interval_bytes);
    for (td.samples) |s| {
        scratch.clear();
        try encodeHeapSampleInto(scratch, s);
        try w.writeMessage(PHS_SAMPLES, scratch.bytes());
    }
}

fn encodeProfilePacket(gpa: std.mem.Allocator, td: TraceData) ![]u8 {
    var w: proto.ProtoWriter = .init(gpa);
    errdefer w.deinit();

    // One scratch writer, reused (cleared) for every leaf sub-message.
    var child: proto.ProtoWriter = .init(gpa);
    defer child.deinit();

    // Embedded interned tables (legacy Android-Q layout — what
    // trace_processor's heap parser reads). Field order is
    // strings → mappings → frames → callstacks → process_dumps.
    for (td.strings, 1..) |str, i| {
        child.clear();
        try encodeInternedStringInto(&child, i, str);
        try w.writeMessage(PP_STRINGS, child.bytes());
    }
    for (td.mappings) |m| {
        child.clear();
        try encodeMappingInto(&child, m);
        try w.writeMessage(PP_MAPPINGS, child.bytes());
    }
    for (td.frames) |f| {
        child.clear();
        try encodeFrameInto(&child, f);
        try w.writeMessage(PP_FRAMES, child.bytes());
    }
    for (td.callstacks) |cs| {
        child.clear();
        try encodeCallstackInto(&child, cs);
        try w.writeMessage(PP_CALLSTACKS, child.bytes());
    }

    var phs: proto.ProtoWriter = .init(gpa);
    defer phs.deinit();
    try encodeProcessHeapSamplesInto(&phs, &child, td);
    try w.writeMessage(PP_PROCESS_DUMPS, phs.bytes());
    return w.buf.toOwnedSlice(gpa);
}

// ---- Public emission via data source -----------------------------------
//
// Build the ClockSnapshot and ProfilePacket TracePacket bodies in Zig,
// emit each via `sismo_ds_emit` (the new public-C++-SDK shim). C++
// wraps each into a NewTracePacket() handle and writes the body via
// AppendRawProtoBytes — bytes go through verbatim.

const c = @cImport({
    @cInclude("src/c/perfetto_shim.h");
});

// rust-bridge/src/proto.rs — wraps an encoded payload in a TracePacket body.
extern fn sismo_encode_trace_packet_body(
    timestamp_ns: u64,
    sequence_flags: u32,
    payload_field_tag: u32,
    payload: ?[*]const u8,
    payload_len: usize,
    out: [*]u8,
    cap: usize,
) usize;

pub fn emitToDataSource(
    gpa: std.mem.Allocator,
    ds_slot: u32,
    td: TraceData,
) !void {
    // Packet 1: ClockSnapshot mapping BUILTIN_CLOCK_MONOTONIC_COARSE 1:1
    // to BUILTIN_CLOCK_BOOTTIME at td.timestamp_ns. The heap parser
    // (ProfileModule::ParseProfilePacket) interprets ProcessHeapSamples'
    // `timestamp` field as MONOTONIC_COARSE; without a registered
    // snapshot for that clock, ToTraceTime() fails and the entire
    // process_dumps entry is skipped silently — heap_profile_allocation
    // stays empty (`clock_sync_failure_unknown_source_clock` stat fires).
    //
    // clock_gettime(CLOCK_MONOTONIC) is close enough to BOOTTIME here; the
    // 1:1 mapping tells trace_processor the two clocks share the same
    // nanosecond timeline.
    const cs_payload = try encodeClockSnapshot(gpa, td.timestamp_ns);
    defer gpa.free(cs_payload);
    const cs_body = try gpa.alloc(u8, cs_payload.len + 32);
    defer gpa.free(cs_body);
    const cs_len = sismo_encode_trace_packet_body(
        td.timestamp_ns,
        0,
        TP_CLOCK_SNAPSHOT,
        cs_payload.ptr,
        cs_payload.len,
        cs_body.ptr,
        cs_body.len,
    );
    if (cs_len != 0) c.sismo_ds_emit(ds_slot, cs_body.ptr, cs_len);

    // Packet 2: ProfilePacket. Interned tables are embedded INSIDE
    // profile_packet (legacy Android-Q fields strings/mappings/frames/
    // callstacks at field 1/4/2/3) — trace_processor's profile parser
    // reads from there, not from TracePacket.interned_data.
    const profile_payload = try encodeProfilePacket(gpa, td);
    defer gpa.free(profile_payload);
    const pp_body = try gpa.alloc(u8, profile_payload.len + 32);
    defer gpa.free(pp_body);
    const pp_len = sismo_encode_trace_packet_body(
        td.timestamp_ns,
        SEQ_INCREMENTAL_STATE_CLEARED,
        TP_PROFILE_PACKET,
        profile_payload.ptr,
        profile_payload.len,
        pp_body.ptr,
        pp_body.len,
    );
    if (pp_len != 0) c.sismo_ds_emit(ds_slot, pp_body.ptr, pp_len);
}

fn encodeClockSnapshot(gpa: std.mem.Allocator, ts_ns: u64) ![]u8 {
    var w: proto.ProtoWriter = .init(gpa);
    errdefer w.deinit();
    var clock: proto.ProtoWriter = .init(gpa);
    defer clock.deinit();
    inline for (.{ BUILTIN_CLOCK_BOOTTIME, BUILTIN_CLOCK_MONOTONIC_COARSE }) |clock_id| {
        clock.clear();
        try clock.writeUint32(CLOCK_CLOCK_ID, clock_id);
        try clock.writeUint64(CLOCK_TIMESTAMP, ts_ns);
        try w.writeMessage(CS_CLOCKS, clock.bytes());
    }
    return w.buf.toOwnedSlice(gpa);
}
