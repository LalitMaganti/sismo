// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Temporary privileged-pid marker for `sismo record`.
//!
//! THIS IS A HACK. It exists only to bridge the gap until sismo grows a
//! proper "JSON-in-zip sidecar" mechanism for per-recording metadata. When
//! that lands, this whole file and its caller in cmd_record.zig should be
//! deleted in one go.
//!
//! Do not extend this file. Do not move it to perfetto_proto.zig. Do not
//! grow a "metadata namespace" around it. The Sismo UI matches on the
//! deliberately-ugly event name `sismo_temporary_privileged_pid_marker` —
//! see third_party/overlays/perfetto/ui/src/plugins/dev.perfetto.Sismo/
//! privileged_set.ts.

const std = @import("std");
const ProtoWriter = @import("proto_writer.zig").ProtoWriter;

// Field tags from protos/perfetto/trace/{trace_packet,track_event}.proto,
// inlined to keep this hack-file's surface narrow.
const TP_FIELD_TRACE_PACKET: u32 = 1;
const TP_FIELD_TIMESTAMP: u32 = 8;
const TP_FIELD_TRUSTED_PACKET_SEQUENCE_ID: u32 = 10;
const TP_FIELD_TRACK_EVENT: u32 = 11;
const TP_FIELD_TIMESTAMP_CLOCK_ID: u32 = 58;
const TP_FIELD_TRACK_DESCRIPTOR: u32 = 60;

// Without a real ts here, the marker defaults to 0 and pulls the trace's
// apparent time range back to boot.
const BUILTIN_CLOCK_BOOTTIME: u32 = 6;

const TE_FIELD_TYPE: u32 = 9;
const TE_FIELD_TRACK_UUID: u32 = 11;
const TE_FIELD_NAME: u32 = 23;
const TE_FIELD_DEBUG_ANNOTATIONS: u32 = 4;
const TE_TYPE_INSTANT: u32 = 3;

const TD_FIELD_UUID: u32 = 1;
const TD_FIELD_NAME: u32 = 2;

const DA_FIELD_INT_VALUE: u32 = 4;
const DA_FIELD_NAME: u32 = 10;

const MARKER_NAME: []const u8 = "sismo_temporary_privileged_pid_marker";
const MARKER_TRACK_UUID: u64 = 0xC0DECAFE_5151_1010;
const MARKER_SEQUENCE_ID: u32 = 0xC0DECAFE;

/// Append the privileged-pid marker (TrackDescriptor + TYPE_INSTANT TrackEvent)
/// to an existing trace file. Caller passes the pids that `sismo record`
/// targeted at record time. No-op if `pids` is empty.
pub fn appendPrivilegedMarker(
    gpa: std.mem.Allocator,
    io: std.Io,
    output_path: []const u8,
    pids: []const i32,
) !void {
    if (pids.len == 0) return;

    // sismo's other emitters use CLOCK_MONOTONIC and the heap path registers
    // a 1:1 MONOTONIC ↔ BOOTTIME snapshot, so a MONOTONIC value labeled as
    // BOOTTIME lines up with the rest of the trace.
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    const timestamp_ns: u64 =
        @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));

    const desc_bytes = try buildTrackDescriptorPacket(gpa, timestamp_ns);
    defer gpa.free(desc_bytes);
    const event_bytes = try buildTrackEventPacket(gpa, pids, timestamp_ns);
    defer gpa.free(event_bytes);

    var out = ProtoWriter.init(gpa);
    defer out.deinit();
    try out.writeMessage(TP_FIELD_TRACE_PACKET, desc_bytes);
    try out.writeMessage(TP_FIELD_TRACE_PACKET, event_bytes);

    var file = try std.Io.Dir.cwd().openFile(io, output_path, .{
        .mode = .read_write,
    });
    defer file.close(io);
    const end = try file.length(io);
    try file.writePositionalAll(io, out.bytes(), end);
}

fn buildTrackDescriptorPacket(gpa: std.mem.Allocator, timestamp_ns: u64) ![]u8 {
    var td = ProtoWriter.init(gpa);
    defer td.deinit();
    try td.writeUint64(TD_FIELD_UUID, MARKER_TRACK_UUID);
    try td.writeString(TD_FIELD_NAME, MARKER_NAME);

    var tp = ProtoWriter.init(gpa);
    errdefer tp.deinit();
    try tp.writeUint64(TP_FIELD_TIMESTAMP, timestamp_ns);
    try tp.writeUint32(TP_FIELD_TIMESTAMP_CLOCK_ID, BUILTIN_CLOCK_BOOTTIME);
    try tp.writeUint32(TP_FIELD_TRUSTED_PACKET_SEQUENCE_ID, MARKER_SEQUENCE_ID);
    try tp.writeMessage(TP_FIELD_TRACK_DESCRIPTOR, td.bytes());
    return tp.buf.toOwnedSlice(gpa);
}

fn buildTrackEventPacket(
    gpa: std.mem.Allocator,
    pids: []const i32,
    timestamp_ns: u64,
) ![]u8 {
    var te = ProtoWriter.init(gpa);
    defer te.deinit();
    try te.writeUint32(TE_FIELD_TYPE, TE_TYPE_INSTANT);
    try te.writeUint64(TE_FIELD_TRACK_UUID, MARKER_TRACK_UUID);
    try te.writeString(TE_FIELD_NAME, MARKER_NAME);
    for (pids) |pid| {
        var ann = ProtoWriter.init(gpa);
        defer ann.deinit();
        try ann.writeString(DA_FIELD_NAME, "pid");
        try ann.writeUint64(DA_FIELD_INT_VALUE, @intCast(pid));
        try te.writeMessage(TE_FIELD_DEBUG_ANNOTATIONS, ann.bytes());
    }

    var tp = ProtoWriter.init(gpa);
    errdefer tp.deinit();
    try tp.writeUint64(TP_FIELD_TIMESTAMP, timestamp_ns);
    try tp.writeUint32(TP_FIELD_TIMESTAMP_CLOCK_ID, BUILTIN_CLOCK_BOOTTIME);
    try tp.writeUint32(TP_FIELD_TRUSTED_PACKET_SEQUENCE_ID, MARKER_SEQUENCE_ID);
    try tp.writeMessage(TP_FIELD_TRACK_EVENT, te.bytes());
    return tp.buf.toOwnedSlice(gpa);
}

test "buildTrackEventPacket carries the marker name and pid varints" {
    const gpa = std.testing.allocator;
    const event_bytes = try buildTrackEventPacket(gpa, &.{ 1234, 5678 }, 0);
    defer gpa.free(event_bytes);

    var occurrences: usize = 0;
    var i: usize = 0;
    while (i + MARKER_NAME.len <= event_bytes.len) : (i += 1) {
        if (std.mem.eql(u8, event_bytes[i .. i + MARKER_NAME.len], MARKER_NAME)) {
            occurrences += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), occurrences);

    // Two pid varints (1234 = 0xd2 0x09, 5678 = 0xae 0x2c) should be present.
    var has_1234 = false;
    var has_5678 = false;
    i = 0;
    while (i + 1 < event_bytes.len) : (i += 1) {
        if (event_bytes[i] == 0xd2 and event_bytes[i + 1] == 0x09) has_1234 = true;
        if (event_bytes[i] == 0xae and event_bytes[i + 1] == 0x2c) has_5678 = true;
    }
    try std.testing.expect(has_1234);
    try std.testing.expect(has_5678);
}
