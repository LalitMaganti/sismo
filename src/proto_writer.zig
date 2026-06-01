// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Minimal protobuf wire-format encoder. Used by heap_emit.zig to
//! emit ProfilePacket / InternedData / Mapping / Frame / Callstack
//! messages directly into a .pftrace file.
//!
//! Wire format reference:
//!   https://protobuf.dev/programming-guides/encoding/
//!
//!   tag = (field_number << 3) | wire_type
//!     wire 0 = VARINT  (uint*, int*, bool, enum)
//!     wire 1 = I64     (8-byte fixed)
//!     wire 2 = LEN     (length-delimited: string, bytes, sub-message)
//!     wire 5 = I32     (4-byte fixed)
//!
//! Nested messages: encode the sub-message into a separate ProtoWriter,
//! then pass its bytes to `writeMessage` on the parent, which prepends
//! the length prefix.

const std = @import("std");

pub const ProtoWriter = struct {
    buf: std.ArrayList(u8),
    gpa: std.mem.Allocator,

    pub fn init(gpa: std.mem.Allocator) ProtoWriter {
        return .{ .buf = .empty, .gpa = gpa };
    }

    pub fn deinit(self: *ProtoWriter) void {
        self.buf.deinit(self.gpa);
    }

    /// Reset for reuse, retaining capacity — a caller that clears between
    /// iterations stops reallocating once the buffer hits peak message size.
    pub fn clear(self: *ProtoWriter) void {
        self.buf.clearRetainingCapacity();
    }

    pub fn bytes(self: *const ProtoWriter) []const u8 {
        return self.buf.items;
    }

    fn writeVarint(self: *ProtoWriter, v: u64) !void {
        var x = v;
        while (x >= 0x80) {
            try self.buf.append(self.gpa, @intCast((x & 0x7f) | 0x80));
            x >>= 7;
        }
        try self.buf.append(self.gpa, @intCast(x & 0x7f));
    }

    fn writeTag(self: *ProtoWriter, field: u32, wire: u3) !void {
        try self.writeVarint((@as(u64, field) << 3) | wire);
    }

    pub fn writeUint64(self: *ProtoWriter, field: u32, value: u64) !void {
        try self.writeTag(field, 0);
        try self.writeVarint(value);
    }

    pub fn writeUint32(self: *ProtoWriter, field: u32, value: u32) !void {
        try self.writeTag(field, 0);
        try self.writeVarint(value);
    }

    pub fn writeBool(self: *ProtoWriter, field: u32, value: bool) !void {
        try self.writeTag(field, 0);
        try self.writeVarint(if (value) 1 else 0);
    }

    /// proto int32/int64: two's-complement varint (NOT zigzag). Negatives
    /// keep the bit pattern of their width — i32 → 5-byte varint, i64 →
    /// 10-byte. Width is load-bearing, so the two are kept distinct.
    pub fn writeInt32(self: *ProtoWriter, field: u32, value: i32) !void {
        try self.writeUint32(field, @bitCast(value));
    }

    pub fn writeInt64(self: *ProtoWriter, field: u32, value: i64) !void {
        try self.writeUint64(field, @bitCast(value));
    }

    pub fn writeEnum(self: *ProtoWriter, field: u32, value: anytype) !void {
        try self.writeUint32(field, @intFromEnum(value));
    }

    pub fn writeString(self: *ProtoWriter, field: u32, str: []const u8) !void {
        try self.writeTag(field, 2);
        try self.writeVarint(str.len);
        try self.buf.appendSlice(self.gpa, str);
    }

    /// Emit a sub-message as a length-delimited field. `msg` is the
    /// already-encoded bytes (typically from another ProtoWriter).
    pub fn writeMessage(self: *ProtoWriter, field: u32, msg: []const u8) !void {
        try self.writeTag(field, 2);
        try self.writeVarint(msg.len);
        try self.buf.appendSlice(self.gpa, msg);
    }
};

test "varint roundtrip" {
    var w: ProtoWriter = .init(std.testing.allocator);
    defer w.deinit();
    try w.writeUint64(1, 150);
    // tag = 1<<3|0 = 0x08; varint(150) = 0x96 0x01
    try std.testing.expectEqualSlices(u8, &.{ 0x08, 0x96, 0x01 }, w.bytes());
}
