// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Hand-written encoders + decoders for sismo data source configs.
//! See `protos/sismo_config.proto` for the schema.
//!
//! One sub-namespace per producer (`macos_cpu_samples`, `heap`,
//! `macos_sched`) — each with its own `Config` struct, `encode`,
//! and `decode`. The producer chooses which to use based on its data
//! source name.
//!
//! All configs ride at vendor-extension field 2000 of Perfetto's
//! `DataSourceConfig`; use `extractFromDataSourceConfig` to pull the
//! bytes out of the serialized DSC the SDK hands to `on_setup`.

const std = @import("std");

// Field on Perfetto's `DataSourceConfig` carrying sismo's config bytes.
pub const DSC_SISMO_CONFIG_FIELD_NUM: u64 = 2000;

const WIRE_VARINT: u64 = 0;
const WIRE_LEN: u64 = 2;

pub const Error = error{MalformedConfig};

// -----------------------------------------------------------------------
// Wire-format primitives (shared)
// -----------------------------------------------------------------------

fn writeVarint(out: *std.ArrayList(u8), gpa: std.mem.Allocator, value: u64) !void {
    var v = value;
    while (v >= 0x80) {
        try out.append(gpa, @intCast((v & 0x7f) | 0x80));
        v >>= 7;
    }
    try out.append(gpa, @intCast(v));
}

fn writeTag(out: *std.ArrayList(u8), gpa: std.mem.Allocator, field_num: u64, wire_type: u64) !void {
    try writeVarint(out, gpa, (field_num << 3) | wire_type);
}

fn writeVarintField(out: *std.ArrayList(u8), gpa: std.mem.Allocator, field_num: u64, value: u64) !void {
    try writeTag(out, gpa, field_num, WIRE_VARINT);
    try writeVarint(out, gpa, value);
}

const VarintRead = struct { value: u64, consumed: usize };

fn readVarint(bytes: []const u8) ?VarintRead {
    var value: u64 = 0;
    var shift: u6 = 0;
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        const b = bytes[i];
        value |= @as(u64, b & 0x7f) << shift;
        if (b & 0x80 == 0) return .{ .value = value, .consumed = i + 1 };
        shift +%= 7;
        if (shift >= 64) return null; // overflow
    }
    return null; // truncated
}

fn skipField(wire_type: u64, bytes: []const u8) ?usize {
    return switch (wire_type) {
        0 => if (readVarint(bytes)) |r| r.consumed else null,
        1 => if (bytes.len >= 8) 8 else null,
        2 => blk: {
            const len_r = readVarint(bytes) orelse break :blk null;
            const total = len_r.consumed +| @as(usize, @intCast(len_r.value));
            if (total > bytes.len) break :blk null;
            break :blk total;
        },
        5 => if (bytes.len >= 4) 4 else null,
        else => null,
    };
}

/// Find Perfetto's `DataSourceConfig.sismo_config` (field 2000,
/// length-delimited bytes) inside a serialized `DataSourceConfig`.
/// Returns a sub-slice of `bytes` (no allocation), or null if
/// absent / malformed.
pub fn extractFromDataSourceConfig(bytes: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < bytes.len) {
        const tag_r = readVarint(bytes[i..]) orelse return null;
        i += tag_r.consumed;
        const field_num = tag_r.value >> 3;
        const wire_type = tag_r.value & 0x07;

        if (field_num == DSC_SISMO_CONFIG_FIELD_NUM and wire_type == WIRE_LEN) {
            const len_r = readVarint(bytes[i..]) orelse return null;
            i += len_r.consumed;
            const end = i + @as(usize, @intCast(len_r.value));
            if (end > bytes.len) return null;
            return bytes[i..end];
        }
        const skip = skipField(wire_type, bytes[i..]) orelse return null;
        i += skip;
    }
    return null;
}

// -----------------------------------------------------------------------
// sismo.macos_cpu_samples
// -----------------------------------------------------------------------

pub const macos_cpu_samples = struct {
    pub const Config = struct {
        target_pid: u32 = 0,
        interval_us: u32 = 0,
    };

    const F_TARGET_PID: u64 = 1;
    const F_INTERVAL_US: u64 = 2;

    pub fn encode(gpa: std.mem.Allocator, cfg: Config) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);
        if (cfg.target_pid != 0) try writeVarintField(&out, gpa, F_TARGET_PID, cfg.target_pid);
        if (cfg.interval_us != 0) try writeVarintField(&out, gpa, F_INTERVAL_US, cfg.interval_us);
        return out.toOwnedSlice(gpa);
    }

    pub fn decode(bytes: []const u8) Error!Config {
        var cfg: Config = .{};
        var i: usize = 0;
        while (i < bytes.len) {
            const tag_r = readVarint(bytes[i..]) orelse return error.MalformedConfig;
            i += tag_r.consumed;
            const field_num = tag_r.value >> 3;
            const wire_type = tag_r.value & 0x07;
            if (wire_type == WIRE_VARINT) {
                const val_r = readVarint(bytes[i..]) orelse return error.MalformedConfig;
                i += val_r.consumed;
                switch (field_num) {
                    F_TARGET_PID => cfg.target_pid = @truncate(val_r.value),
                    F_INTERVAL_US => cfg.interval_us = @truncate(val_r.value),
                    else => {},
                }
            } else {
                const skip = skipField(wire_type, bytes[i..]) orelse return error.MalformedConfig;
                i += skip;
            }
        }
        return cfg;
    }
};

// -----------------------------------------------------------------------
// sismo.heap
// -----------------------------------------------------------------------

pub const heap = struct {
    pub const Config = struct {
        target_pid: u32 = 0,
        ring_size_bytes: u64 = 0,
        sample_interval_bytes: u64 = 0,
    };

    const F_TARGET_PID: u64 = 1;
    const F_RING_SIZE: u64 = 2;
    const F_SAMPLE_INTERVAL: u64 = 3;

    pub fn encode(gpa: std.mem.Allocator, cfg: Config) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);
        if (cfg.target_pid != 0) try writeVarintField(&out, gpa, F_TARGET_PID, cfg.target_pid);
        if (cfg.ring_size_bytes != 0) try writeVarintField(&out, gpa, F_RING_SIZE, cfg.ring_size_bytes);
        if (cfg.sample_interval_bytes != 0) try writeVarintField(&out, gpa, F_SAMPLE_INTERVAL, cfg.sample_interval_bytes);
        return out.toOwnedSlice(gpa);
    }

    pub fn decode(bytes: []const u8) Error!Config {
        var cfg: Config = .{};
        var i: usize = 0;
        while (i < bytes.len) {
            const tag_r = readVarint(bytes[i..]) orelse return error.MalformedConfig;
            i += tag_r.consumed;
            const field_num = tag_r.value >> 3;
            const wire_type = tag_r.value & 0x07;
            if (wire_type == WIRE_VARINT) {
                const val_r = readVarint(bytes[i..]) orelse return error.MalformedConfig;
                i += val_r.consumed;
                switch (field_num) {
                    F_TARGET_PID => cfg.target_pid = @truncate(val_r.value),
                    F_RING_SIZE => cfg.ring_size_bytes = val_r.value,
                    F_SAMPLE_INTERVAL => cfg.sample_interval_bytes = val_r.value,
                    else => {},
                }
            } else {
                const skip = skipField(wire_type, bytes[i..]) orelse return error.MalformedConfig;
                i += skip;
            }
        }
        return cfg;
    }
};

// -----------------------------------------------------------------------
// sismo.macos_sched
// -----------------------------------------------------------------------

pub const macos_sched = struct {
    pub const Config = struct {
        kernel_buffer_events: i32 = 0,
    };

    const F_KERNEL_BUFFER_EVENTS: u64 = 1;

    pub fn encode(gpa: std.mem.Allocator, cfg: Config) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);
        if (cfg.kernel_buffer_events != 0) {
            try writeVarintField(&out, gpa, F_KERNEL_BUFFER_EVENTS, @bitCast(@as(i64, cfg.kernel_buffer_events)));
        }
        return out.toOwnedSlice(gpa);
    }

    pub fn decode(bytes: []const u8) Error!Config {
        var cfg: Config = .{};
        var i: usize = 0;
        while (i < bytes.len) {
            const tag_r = readVarint(bytes[i..]) orelse return error.MalformedConfig;
            i += tag_r.consumed;
            const field_num = tag_r.value >> 3;
            const wire_type = tag_r.value & 0x07;
            if (wire_type == WIRE_VARINT) {
                const val_r = readVarint(bytes[i..]) orelse return error.MalformedConfig;
                i += val_r.consumed;
                switch (field_num) {
                    F_KERNEL_BUFFER_EVENTS => cfg.kernel_buffer_events = @truncate(@as(i64, @bitCast(val_r.value))),
                    else => {},
                }
            } else {
                const skip = skipField(wire_type, bytes[i..]) orelse return error.MalformedConfig;
                i += skip;
            }
        }
        return cfg;
    }
};

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

test "macos_cpu_samples roundtrip" {
    const gpa = std.testing.allocator;
    const orig: macos_cpu_samples.Config = .{ .target_pid = 12345, .interval_us = 1000 };
    const bytes = try macos_cpu_samples.encode(gpa, orig);
    defer gpa.free(bytes);
    const decoded = try macos_cpu_samples.decode(bytes);
    try std.testing.expectEqual(orig, decoded);
}

test "heap roundtrip" {
    const gpa = std.testing.allocator;
    const orig: heap.Config = .{
        .target_pid = 777,
        .ring_size_bytes = 16 * 1024 * 1024,
        .sample_interval_bytes = 4096,
    };
    const bytes = try heap.encode(gpa, orig);
    defer gpa.free(bytes);
    const decoded = try heap.decode(bytes);
    try std.testing.expectEqual(orig, decoded);
}

test "macos_sched roundtrip" {
    const gpa = std.testing.allocator;
    const orig: macos_sched.Config = .{ .kernel_buffer_events = 256 * 1024 };
    const bytes = try macos_sched.encode(gpa, orig);
    defer gpa.free(bytes);
    const decoded = try macos_sched.decode(bytes);
    try std.testing.expectEqual(orig, decoded);
}

test "encode omits zero fields" {
    const gpa = std.testing.allocator;
    const bytes = try macos_cpu_samples.encode(gpa, .{ .target_pid = 42 });
    defer gpa.free(bytes);
    // tag (1<<3|0) = 0x08, varint 42 = 0x2a → 2 bytes.
    try std.testing.expectEqual(@as(usize, 2), bytes.len);
}

test "decode skips unknown fields" {
    // Field 9 (varint 7), then field 1 (target_pid 42). Tag 9<<3|0=72;
    // tag 1<<3|0=8.
    const bytes = [_]u8{ 72, 7, 8, 42 };
    const decoded = try macos_cpu_samples.decode(&bytes);
    try std.testing.expectEqual(@as(u32, 42), decoded.target_pid);
}

test "extractFromDataSourceConfig finds field 2000 amid other DSC fields" {
    const gpa = std.testing.allocator;
    var dsc: std.ArrayList(u8) = .empty;
    defer dsc.deinit(gpa);

    // DataSourceConfig.name = "x" (field 1, length-delimited).
    try writeTag(&dsc, gpa, 1, WIRE_LEN);
    try writeVarint(&dsc, gpa, 1);
    try dsc.append(gpa, 'x');

    // sismo_config (field 2000) carrying a SismoHeapConfig.
    const inner = try heap.encode(gpa, .{ .target_pid = 99 });
    defer gpa.free(inner);
    try writeTag(&dsc, gpa, DSC_SISMO_CONFIG_FIELD_NUM, WIRE_LEN);
    try writeVarint(&dsc, gpa, inner.len);
    try dsc.appendSlice(gpa, inner);

    const extracted = extractFromDataSourceConfig(dsc.items) orelse return error.NotFound;
    const decoded = try heap.decode(extracted);
    try std.testing.expectEqual(@as(u32, 99), decoded.target_pid);
}
