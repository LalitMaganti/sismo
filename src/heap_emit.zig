// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Encodes sismo-heap's aggregated allocations into a Perfetto
//! ProfilePacket-bearing .pftrace file. trace_processor populates the
//! `heap_profile_allocation` table from this.
//!
//! Wire format details:
//!   - Top-level Trace message has `repeated TracePacket packet = 1`,
//!     so the file is a stream of (tag=0x0a)(varint length)(packet bytes).
//!   - Two packets emitted per call:
//!       (1) TracePacket with InternedData (mappings, frames, callstacks,
//!           function names, mapping paths) and SEQ_INCREMENTAL_STATE_CLEARED
//!       (2) TracePacket with ProfilePacket → ProcessHeapSamples → HeapSample[]
//!   - Both share `trusted_packet_sequence_id = 1`.
//!
//! Field numbers cross-referenced from the vendored protos in
//! third_party/src/perfetto/protos/perfetto/trace/...

const std = @import("std");
const proto = @import("proto_writer.zig");

// ---- Field number constants (extracted from the vendored .proto files) ----

// Trace
const TRACE_PACKET = 1;

// TracePacket
const TP_TIMESTAMP = 8;
const TP_TRUSTED_PACKET_SEQUENCE_ID = 10;
const TP_INTERNED_DATA = 12;
const TP_SEQUENCE_FLAGS = 13;
const TP_CLOCK_SNAPSHOT = 6;
const TP_PROFILE_PACKET = 37;
const SEQ_INCREMENTAL_STATE_CLEARED: u32 = 1;
const SEQ_NEEDS_INCREMENTAL_STATE: u32 = 2;

// ClockSnapshot
const CS_CLOCKS = 1;
// Clock
const CLOCK_CLOCK_ID = 1;
const CLOCK_TIMESTAMP = 2;
// BuiltinClock IDs (from protos/perfetto/common/builtin_clock.proto).
const BUILTIN_CLOCK_BOOTTIME: u32 = 6;
const BUILTIN_CLOCK_MONOTONIC_COARSE: u32 = 4;

// InternedData
const ID_FUNCTION_NAMES = 5;
const ID_MAPPING_PATHS = 17;
const ID_MAPPINGS = 19;
const ID_FRAMES = 6;
const ID_CALLSTACKS = 7;

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
    path_string_iid: u64,  // ref into mapping_paths string table
    start: u64,
    end: u64,
    load_bias: u64,
};

pub const Frame = struct {
    iid: u64,
    function_name_iid: u64,  // ref into function_names string table
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

fn encodeInternedString(gpa: std.mem.Allocator, iid: u64, str: []const u8) ![]u8 {
    var w: proto.ProtoWriter = .init(gpa);
    defer w.deinit();
    try w.writeUint64(IS_IID, iid);
    try w.writeString(IS_STR, str);
    return gpa.dupe(u8, w.bytes());
}

fn encodeMapping(gpa: std.mem.Allocator, m: Mapping) ![]u8 {
    var w: proto.ProtoWriter = .init(gpa);
    defer w.deinit();
    try w.writeUint64(MAP_IID, m.iid);
    try w.writeUint64(MAP_START, m.start);
    try w.writeUint64(MAP_END, m.end);
    try w.writeUint64(MAP_LOAD_BIAS, m.load_bias);
    // path_string_ids is repeated; emit one entry.
    try w.writeUint64(MAP_PATH_STRING_IDS, m.path_string_iid);
    return gpa.dupe(u8, w.bytes());
}

fn encodeFrame(gpa: std.mem.Allocator, f: Frame) ![]u8 {
    var w: proto.ProtoWriter = .init(gpa);
    defer w.deinit();
    try w.writeUint64(FRAME_IID, f.iid);
    try w.writeUint64(FRAME_FUNCTION_NAME_ID, f.function_name_iid);
    try w.writeUint64(FRAME_MAPPING_ID, f.mapping_iid);
    try w.writeUint64(FRAME_REL_PC, f.rel_pc);
    return gpa.dupe(u8, w.bytes());
}

fn encodeCallstack(gpa: std.mem.Allocator, cs: Callstack) ![]u8 {
    var w: proto.ProtoWriter = .init(gpa);
    defer w.deinit();
    try w.writeUint64(CS_IID, cs.iid);
    for (cs.frame_iids) |fid| try w.writeUint64(CS_FRAME_IDS, fid);
    return gpa.dupe(u8, w.bytes());
}

fn encodeHeapSample(gpa: std.mem.Allocator, s: HeapSample) ![]u8 {
    var w: proto.ProtoWriter = .init(gpa);
    defer w.deinit();
    try w.writeUint64(HS_CALLSTACK_ID, s.callstack_iid);
    try w.writeUint64(HS_SELF_ALLOCATED, s.self_allocated);
    try w.writeUint64(HS_ALLOC_COUNT, s.alloc_count);
    return gpa.dupe(u8, w.bytes());
}

fn encodeProcessHeapSamples(gpa: std.mem.Allocator, td: TraceData) ![]u8 {
    var w: proto.ProtoWriter = .init(gpa);
    defer w.deinit();
    try w.writeUint64(PHS_PID, td.pid);
    try w.writeUint64(PHS_TIMESTAMP, td.timestamp_ns);
    try w.writeString(PHS_HEAP_NAME, "libc.malloc");
    try w.writeUint64(PHS_SAMPLING_INTERVAL_BYTES, td.sampling_interval_bytes);
    for (td.samples) |s| {
        const bytes = try encodeHeapSample(gpa, s);
        defer gpa.free(bytes);
        try w.writeMessage(PHS_SAMPLES, bytes);
    }
    return gpa.dupe(u8, w.bytes());
}

fn encodeProfilePacket(gpa: std.mem.Allocator, td: TraceData) ![]u8 {
    var w: proto.ProtoWriter = .init(gpa);
    defer w.deinit();

    // Embedded interned tables (legacy Android-Q layout — what
    // trace_processor's heap parser actually reads). Field order
    // matters for parser efficiency: strings → mappings → frames →
    // callstacks → process_dumps.
    for (td.strings, 1..) |str, i| {
        const bytes = try encodeInternedString(gpa, i, str);
        defer gpa.free(bytes);
        try w.writeMessage(PP_STRINGS, bytes);
    }
    for (td.mappings) |m| {
        const bytes = try encodeMapping(gpa, m);
        defer gpa.free(bytes);
        try w.writeMessage(PP_MAPPINGS, bytes);
    }
    for (td.frames) |f| {
        const bytes = try encodeFrame(gpa, f);
        defer gpa.free(bytes);
        try w.writeMessage(PP_FRAMES, bytes);
    }
    for (td.callstacks) |cs| {
        const bytes = try encodeCallstack(gpa, cs);
        defer gpa.free(bytes);
        try w.writeMessage(PP_CALLSTACKS, bytes);
    }

    const phs_bytes = try encodeProcessHeapSamples(gpa, td);
    defer gpa.free(phs_bytes);
    try w.writeMessage(PP_PROCESS_DUMPS, phs_bytes);
    return gpa.dupe(u8, w.bytes());
}

fn encodeInternedDataPacket(gpa: std.mem.Allocator, td: TraceData) ![]u8 {
    var w: proto.ProtoWriter = .init(gpa);
    defer w.deinit();

    for (td.function_names, 1..) |str, i| {
        const bytes = try encodeInternedString(gpa, i, str);
        defer gpa.free(bytes);
        try w.writeMessage(ID_FUNCTION_NAMES, bytes);
    }
    for (td.mapping_paths, 1..) |str, i| {
        const bytes = try encodeInternedString(gpa, i, str);
        defer gpa.free(bytes);
        try w.writeMessage(ID_MAPPING_PATHS, bytes);
    }
    for (td.mappings) |m| {
        const bytes = try encodeMapping(gpa, m);
        defer gpa.free(bytes);
        try w.writeMessage(ID_MAPPINGS, bytes);
    }
    for (td.frames) |f| {
        const bytes = try encodeFrame(gpa, f);
        defer gpa.free(bytes);
        try w.writeMessage(ID_FRAMES, bytes);
    }
    for (td.callstacks) |cs| {
        const bytes = try encodeCallstack(gpa, cs);
        defer gpa.free(bytes);
        try w.writeMessage(ID_CALLSTACKS, bytes);
    }

    return gpa.dupe(u8, w.bytes());
}

fn encodeTracePacketWithInternedData(gpa: std.mem.Allocator, td: TraceData) ![]u8 {
    var w: proto.ProtoWriter = .init(gpa);
    defer w.deinit();
    try w.writeUint64(TP_TIMESTAMP, td.timestamp_ns);
    try w.writeUint32(TP_TRUSTED_PACKET_SEQUENCE_ID, 1);
    try w.writeUint32(TP_SEQUENCE_FLAGS, SEQ_INCREMENTAL_STATE_CLEARED);
    const id_bytes = try encodeInternedDataPacket(gpa, td);
    defer gpa.free(id_bytes);
    try w.writeMessage(TP_INTERNED_DATA, id_bytes);
    return gpa.dupe(u8, w.bytes());
}

fn encodeTracePacketWithProfile(gpa: std.mem.Allocator, td: TraceData) ![]u8 {
    var w: proto.ProtoWriter = .init(gpa);
    defer w.deinit();
    try w.writeUint64(TP_TIMESTAMP, td.timestamp_ns);
    try w.writeUint32(TP_TRUSTED_PACKET_SEQUENCE_ID, 1);
    const pp_bytes = try encodeProfilePacket(gpa, td);
    defer gpa.free(pp_bytes);
    try w.writeMessage(TP_PROFILE_PACKET, pp_bytes);
    return gpa.dupe(u8, w.bytes());
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
const perfetto_proto = @import("perfetto_proto.zig");

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
    // We use clock_gettime(CLOCK_MONOTONIC) which is close enough to
    // BOOTTIME for our purposes; the 1:1 mapping tells trace_processor
    // the two clocks share the same nanosecond timeline.
    const cs_payload = try encodeClockSnapshot(gpa, td.timestamp_ns);
    defer gpa.free(cs_payload);
    const cs_body = try perfetto_proto.encodeTracePacketBody(
        gpa, td.timestamp_ns, TP_CLOCK_SNAPSHOT, cs_payload,
    );
    defer gpa.free(cs_body);
    c.sismo_ds_emit(ds_slot, cs_body.ptr, cs_body.len);

    // Packet 2: ProfilePacket. Interned tables are embedded INSIDE
    // profile_packet (legacy Android-Q fields strings/mappings/frames/
    // callstacks at field 1/4/2/3) — trace_processor's profile parser
    // reads from there, not from TracePacket.interned_data.
    const profile_payload = try encodeProfilePacket(gpa, td);
    defer gpa.free(profile_payload);
    const pp_body = try perfetto_proto.encodeTracePacketBodyWithFlags(
        gpa, td.timestamp_ns, SEQ_INCREMENTAL_STATE_CLEARED,
        TP_PROFILE_PACKET, profile_payload,
    );
    defer gpa.free(pp_body);
    c.sismo_ds_emit(ds_slot, pp_body.ptr, pp_body.len);
}

fn encodeClockSnapshot(gpa: std.mem.Allocator, ts_ns: u64) ![]u8 {
    var w: proto.ProtoWriter = .init(gpa);
    defer w.deinit();
    inline for (.{ BUILTIN_CLOCK_BOOTTIME, BUILTIN_CLOCK_MONOTONIC_COARSE }) |clock_id| {
        var clock: proto.ProtoWriter = .init(gpa);
        defer clock.deinit();
        try clock.writeUint32(CLOCK_CLOCK_ID, clock_id);
        try clock.writeUint64(CLOCK_TIMESTAMP, ts_ns);
        try w.writeMessage(CS_CLOCKS, clock.bytes());
    }
    return gpa.dupe(u8, w.bytes());
}
