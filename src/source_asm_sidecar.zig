// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Source-and-disassembly sidecar for `sismo record`.
//!
//! THIS IS A HACK, in the same vein as sismo_privileged_marker.zig. It bundles
//! the source-file text (and, via AsmRecord, a disassembly listing) for the
//! functions a recording actually sampled, by appending TYPE_INSTANT TrackEvent
//! packets carrying the payload in debug_annotations. trace_processor surfaces
//! those as `args` rows, which the Sismo UI's annotation loader reads
//! (cpu_data/annotation.ts) to render the Source/Assembly view.
//!
//! Do not extend this into a general metadata system. When the proper
//! JSON-in-zip sidecar lands, this file, sismo_privileged_marker.zig, and their
//! callers all get deleted together. The UI matches on the deliberately-ugly
//! track name `sismo_temporary_source_asm_sidecar` and the event names
//! `sismo_src` / `sismo_asm`.

const std = @import("std");
const ProtoWriter = @import("proto_writer.zig").ProtoWriter;

// Field tags from protos/perfetto/trace/{trace_packet,track_event,
// debug_annotation}.proto, inlined to keep this hack-file's surface narrow.
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

const TRACK_NAME: []const u8 = "sismo_temporary_source_asm_sidecar";
const TRACK_UUID: u64 = 0xC0DECAFE_5350_2020;
const SEQUENCE_ID: u32 = 0xC0DECAFF;

const SRC_EVENT_NAME: []const u8 = "sismo_src";
const ASM_EVENT_NAME: []const u8 = "sismo_asm";

// Bounds so a recording never balloons: skip any source file over 1 MiB, stop
// emitting source past a 16 MiB global budget, and split any annotation payload
// over ~192 KiB into chunked records the UI reassembles.
const MAX_SRC_BYTES: usize = 1 << 20;
const MAX_TOTAL_SRC_BYTES: usize = 16 << 20;
const MAX_CHUNK_BYTES: usize = 192 * 1024;

// One function's disassembly, ready to serialize. `json` is the already-built
// `[{a,b,t,l}, …]` array (see perf_symbolize); the sidecar only chunks + frames
// it. Produced by the B2 disassembly pass; B1 passes an empty slice.
pub const AsmRecord = struct {
    func: []const u8,
    module: []const u8,
    build_id_hex: []const u8,
    json: []const u8,
};

/// Append the source/disasm sidecar to an existing trace file. Reads each path
/// in `src_paths` from local disk (best-effort, bounded) and emits a `sismo_src`
/// record per file, plus a `sismo_asm` record per `AsmRecord`. No-op when there
/// is nothing to emit.
pub fn appendSidecar(
    gpa: std.mem.Allocator,
    io: std.Io,
    output_path: []const u8,
    src_paths: []const []const u8,
    asm_records: []const AsmRecord,
) !void {
    if (src_paths.len == 0 and asm_records.len == 0) return;

    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    const timestamp_ns: u64 =
        @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));

    var out = ProtoWriter.init(gpa);
    defer out.deinit();

    try writeTrackDescriptor(gpa, &out, timestamp_ns);

    var total_src: usize = 0;
    for (src_paths) |path| {
        if (total_src >= MAX_TOTAL_SRC_BYTES) break;
        const text = readWholeFile(gpa, io, path, MAX_SRC_BYTES) orelse continue;
        defer gpa.free(text);
        total_src += text.len;
        try writeChunked(gpa, &out, timestamp_ns, SRC_EVENT_NAME, "path", path, text);
    }

    for (asm_records) |rec| {
        try writeChunked(
            gpa,
            &out,
            timestamp_ns,
            ASM_EVENT_NAME,
            "func",
            rec.func,
            rec.json,
        );
    }

    if (out.bytes().len == 0) return;
    var file = try std.Io.Dir.cwd().openFile(io, output_path, .{ .mode = .read_write });
    defer file.close(io);
    const end = try file.length(io);
    try file.writePositionalAll(io, out.bytes(), end);
}

fn writeTrackDescriptor(
    gpa: std.mem.Allocator,
    out: *ProtoWriter,
    timestamp_ns: u64,
) !void {
    var td = ProtoWriter.init(gpa);
    defer td.deinit();
    try td.writeUint64(TD_FIELD_UUID, TRACK_UUID);
    try td.writeString(TD_FIELD_NAME, TRACK_NAME);

    var tp = ProtoWriter.init(gpa);
    defer tp.deinit();
    try tp.writeUint64(TP_FIELD_TIMESTAMP, timestamp_ns);
    try tp.writeUint32(TP_FIELD_TIMESTAMP_CLOCK_ID, BUILTIN_CLOCK_BOOTTIME);
    try tp.writeUint32(TP_FIELD_TRUSTED_PACKET_SEQUENCE_ID, SEQUENCE_ID);
    try tp.writeMessage(TP_FIELD_TRACK_DESCRIPTOR, td.bytes());
    try out.writeMessage(TP_FIELD_TRACE_PACKET, tp.bytes());
}

// Emit one record as one (small payload) or several (chunked) TYPE_INSTANT
// TrackEvents. `key_name`/`key_val` is the join key (debug.path / debug.func);
// `payload` lands in debug.text. Chunked records carry debug.chunk + nchunks.
fn writeChunked(
    gpa: std.mem.Allocator,
    out: *ProtoWriter,
    timestamp_ns: u64,
    event_name: []const u8,
    key_name: []const u8,
    key_val: []const u8,
    payload: []const u8,
) !void {
    if (payload.len <= MAX_CHUNK_BYTES) {
        try writeEvent(gpa, out, timestamp_ns, event_name, key_name, key_val, payload, null, 0);
        return;
    }
    const nchunks: u32 = @intCast((payload.len + MAX_CHUNK_BYTES - 1) / MAX_CHUNK_BYTES);
    var i: u32 = 0;
    var off: usize = 0;
    while (off < payload.len) : (i += 1) {
        const end = @min(off + MAX_CHUNK_BYTES, payload.len);
        try writeEvent(
            gpa,
            out,
            timestamp_ns,
            event_name,
            key_name,
            key_val,
            payload[off..end],
            i,
            nchunks,
        );
        off = end;
    }
}

fn writeEvent(
    gpa: std.mem.Allocator,
    out: *ProtoWriter,
    timestamp_ns: u64,
    event_name: []const u8,
    key_name: []const u8,
    key_val: []const u8,
    text: []const u8,
    chunk: ?u32,
    nchunks: u32,
) !void {
    var te = ProtoWriter.init(gpa);
    defer te.deinit();
    try te.writeUint32(TE_FIELD_TYPE, TE_TYPE_INSTANT);
    try te.writeUint64(TE_FIELD_TRACK_UUID, TRACK_UUID);
    try te.writeString(TE_FIELD_NAME, event_name);
    try writeStringAnnotation(gpa, &te, key_name, key_val);
    try writeStringAnnotation(gpa, &te, "text", text);
    if (chunk) |c| {
        try writeIntAnnotation(gpa, &te, "chunk", c);
        try writeIntAnnotation(gpa, &te, "nchunks", nchunks);
    }

    var tp = ProtoWriter.init(gpa);
    defer tp.deinit();
    try tp.writeUint64(TP_FIELD_TIMESTAMP, timestamp_ns);
    try tp.writeUint32(TP_FIELD_TIMESTAMP_CLOCK_ID, BUILTIN_CLOCK_BOOTTIME);
    try tp.writeUint32(TP_FIELD_TRUSTED_PACKET_SEQUENCE_ID, SEQUENCE_ID);
    try tp.writeMessage(TP_FIELD_TRACK_EVENT, te.bytes());
    try out.writeMessage(TP_FIELD_TRACE_PACKET, tp.bytes());
}

fn writeStringAnnotation(
    gpa: std.mem.Allocator,
    te: *ProtoWriter,
    name: []const u8,
    value: []const u8,
) !void {
    var ann = ProtoWriter.init(gpa);
    defer ann.deinit();
    try ann.writeString(DA_FIELD_NAME, name);
    try ann.writeString(DA_FIELD_STRING_VALUE, value);
    try te.writeMessage(TE_FIELD_DEBUG_ANNOTATIONS, ann.bytes());
}

fn writeIntAnnotation(
    gpa: std.mem.Allocator,
    te: *ProtoWriter,
    name: []const u8,
    value: u32,
) !void {
    var ann = ProtoWriter.init(gpa);
    defer ann.deinit();
    try ann.writeString(DA_FIELD_NAME, name);
    try ann.writeUint64(DA_FIELD_INT_VALUE, value);
    try te.writeMessage(TE_FIELD_DEBUG_ANNOTATIONS, ann.bytes());
}

// Read an absolute path into a freshly-allocated buffer, up to `max` bytes.
// Returns null on any open/read failure (deleted/relative/remote path) or when
// the file is larger than `max` — the UI degrades to "source unavailable".
fn readWholeFile(
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    max: usize,
) ?[]u8 {
    // openFileAbsolute asserts the path is absolute (a precondition, not an
    // error), so a relative DWARF source path would panic rather than fall
    // through to the null path this function promises. Skip non-absolute paths.
    if (!std.fs.path.isAbsolute(path)) return null;
    var file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch return null;
    defer file.close(io);
    const size_u64 = file.length(io) catch return null;
    if (size_u64 == 0 or size_u64 > max) return null;
    const size: usize = @intCast(size_u64);
    const buf = gpa.alloc(u8, size) catch return null;
    var total: usize = 0;
    while (total < size) {
        const n = file.readPositional(io, &.{buf[total..]}, total) catch {
            gpa.free(buf);
            return null;
        };
        if (n == 0) break;
        total += n;
    }
    if (total != size) {
        gpa.free(buf);
        return null;
    }
    return buf;
}

comptime {
    if (@import("builtin").os.tag == .windows) {
        @compileError("source_asm_sidecar is POSIX-only (uses std.Io.Dir file append)");
    }
}

test "writeChunked single record carries key and text" {
    const gpa = std.testing.allocator;
    var out = ProtoWriter.init(gpa);
    defer out.deinit();
    try writeChunked(gpa, &out, 0, SRC_EVENT_NAME, "path", "/a/b.c", "hello world");
    try std.testing.expect(std.mem.indexOf(u8, out.bytes(), SRC_EVENT_NAME) != null);
    try std.testing.expect(std.mem.indexOf(u8, out.bytes(), "/a/b.c") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.bytes(), "hello world") != null);
}

test "writeChunked splits oversized payloads" {
    const gpa = std.testing.allocator;
    var out = ProtoWriter.init(gpa);
    defer out.deinit();
    const big = try gpa.alloc(u8, MAX_CHUNK_BYTES * 2 + 10);
    defer gpa.free(big);
    @memset(big, 'x');
    try writeChunked(gpa, &out, 0, ASM_EVENT_NAME, "func", "f", big);
    // Three chunks → the "nchunks" annotation name appears (once per chunk).
    var count: usize = 0;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, out.bytes(), i, "nchunks")) |p| : (i = p + 1) count += 1;
    try std.testing.expectEqual(@as(usize, 3), count);
}
