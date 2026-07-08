// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Thin typed facade over the sismo data-source config wire codec, which now
//! lives entirely in Rust (rust-bridge/src/sismo_config.rs). This file keeps
//! the ergonomic `sismo_config.<producer>.{Config,encode,decode}` +
//! `extractFromDataSourceConfig` API the producers use; every byte of wire
//! logic is on the Rust side. See protos/sismo_config.proto for the schema.

const std = @import("std");

pub const Error = error{MalformedConfig};

extern fn sismo_config_extract(
    dsc: [*]const u8,
    dsc_len: usize,
    out_offset: *usize,
    out_len: *usize,
) bool;
extern fn sismo_config_cpu_encode(target_pid: u32, interval_us: u32, out: [*]u8, cap: usize) usize;
extern fn sismo_config_cpu_decode(bytes: [*]const u8, len: usize, out_target_pid: *u32, out_interval_us: *u32) bool;
extern fn sismo_config_heap_encode(
    target_pid: u32,
    ring_size_bytes: u64,
    sample_interval_bytes: u64,
    out: [*]u8,
    cap: usize,
) usize;
extern fn sismo_config_heap_decode(
    bytes: [*]const u8,
    len: usize,
    out_target_pid: *u32,
    out_ring_size_bytes: *u64,
    out_sample_interval_bytes: *u64,
) bool;
extern fn sismo_config_sched_encode(kernel_buffer_events: i32, out: [*]u8, cap: usize) usize;
extern fn sismo_config_sched_decode(bytes: [*]const u8, len: usize, out_kernel_buffer_events: *i32) bool;

/// Return the `DataSourceConfig.sismo_config` sub-slice (vendor field 2000)
/// inside a serialized DataSourceConfig, or null if absent / malformed. The
/// result borrows from `bytes` (no allocation).
pub fn extractFromDataSourceConfig(bytes: []const u8) ?[]const u8 {
    var offset: usize = 0;
    var len: usize = 0;
    if (!sismo_config_extract(bytes.ptr, bytes.len, &offset, &len)) return null;
    return bytes[offset .. offset + len];
}

pub const macos_cpu_samples = struct {
    pub const Config = struct {
        target_pid: u32 = 0,
        interval_us: u32 = 0,
    };

    pub fn encode(gpa: std.mem.Allocator, cfg: Config) ![]u8 {
        var buf: [64]u8 = undefined;
        const n = sismo_config_cpu_encode(cfg.target_pid, cfg.interval_us, &buf, buf.len);
        return gpa.dupe(u8, buf[0..n]);
    }

    pub fn decode(bytes: []const u8) Error!Config {
        var cfg: Config = .{};
        if (!sismo_config_cpu_decode(bytes.ptr, bytes.len, &cfg.target_pid, &cfg.interval_us)) {
            return error.MalformedConfig;
        }
        return cfg;
    }
};

pub const heap = struct {
    pub const Config = struct {
        target_pid: u32 = 0,
        ring_size_bytes: u64 = 0,
        sample_interval_bytes: u64 = 0,
    };

    pub fn encode(gpa: std.mem.Allocator, cfg: Config) ![]u8 {
        var buf: [64]u8 = undefined;
        const n = sismo_config_heap_encode(
            cfg.target_pid,
            cfg.ring_size_bytes,
            cfg.sample_interval_bytes,
            &buf,
            buf.len,
        );
        return gpa.dupe(u8, buf[0..n]);
    }

    pub fn decode(bytes: []const u8) Error!Config {
        var cfg: Config = .{};
        if (!sismo_config_heap_decode(
            bytes.ptr,
            bytes.len,
            &cfg.target_pid,
            &cfg.ring_size_bytes,
            &cfg.sample_interval_bytes,
        )) {
            return error.MalformedConfig;
        }
        return cfg;
    }
};

pub const macos_sched = struct {
    pub const Config = struct {
        kernel_buffer_events: i32 = 0,
    };

    pub fn encode(gpa: std.mem.Allocator, cfg: Config) ![]u8 {
        var buf: [64]u8 = undefined;
        const n = sismo_config_sched_encode(cfg.kernel_buffer_events, &buf, buf.len);
        return gpa.dupe(u8, buf[0..n]);
    }

    pub fn decode(bytes: []const u8) Error!Config {
        var cfg: Config = .{};
        if (!sismo_config_sched_decode(bytes.ptr, bytes.len, &cfg.kernel_buffer_events)) {
            return error.MalformedConfig;
        }
        return cfg;
    }
};
