// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Probe which PMU hardware counters this machine can actually open, so the
//! recorder only asks perfetto for counters that will succeed.
//!
//! Why probe instead of letting perfetto try and fail: perfetto opens the
//! per-sample perf group (timebase leader + counter followers) all-or-nothing
//! — a single unsupported follower discards the whole CPU-sampling data
//! source. Rather than patch perfetto to degrade, we mirror its open here
//! first and drop counters the hardware rejects, keeping CPU sampling intact.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const proto = @import("perfetto_proto.zig");

const PERF_FLAG_FD_CLOEXEC: usize = 1 << 3;
// read_format bit: read the whole group's counts together. Perfetto sets this
// on the timebase leader (event_config.cc), which forces every follower to be
// co-scheduled on the PMU at sample time — so the probe must mirror it to
// predict which followers actually fit.
const PERF_FORMAT_GROUP: u64 = 1 << 3;

/// A candidate counter: the perfetto Counter enum id we emit in the config
/// (proto), the PERF_COUNT_HW_* value we open with to test support, and the
/// display name. Cycles + instructions give IPC; the stall split shows
/// frontend/backend boundedness; cache/branch misses round it out.
const Candidate = struct {
    perfetto_id: u32,
    hw: linux.PERF.COUNT.HW,
    name: []const u8,
};

const CANDIDATES = [_]Candidate{
    .{ .perfetto_id = 10, .hw = .CPU_CYCLES, .name = "cpu-cycles" },
    .{ .perfetto_id = 11, .hw = .INSTRUCTIONS, .name = "instructions" },
    .{ .perfetto_id = 17, .hw = .STALLED_CYCLES_FRONTEND, .name = "stalled-cycles-frontend" },
    .{ .perfetto_id = 18, .hw = .STALLED_CYCLES_BACKEND, .name = "stalled-cycles-backend" },
    .{ .perfetto_id = 13, .hw = .CACHE_MISSES, .name = "cache-misses" },
    .{ .perfetto_id = 15, .hw = .BRANCH_MISSES, .name = "branch-misses" },
};

/// Returns the subset of candidate counters this machine can open as a single
/// co-scheduled sampling group, as perfetto follower specs. Caller owns the
/// returned slice. Emits a one-line summary of what was enabled / skipped. On
/// non-Linux (no perf), returns empty.
pub fn probeSupported(gpa: std.mem.Allocator) ![]proto.PerfCounter {
    if (comptime builtin.os.tag != .linux) return &.{};

    // Leader mirrors perfetto's timebase: a *sampling* software CPU clock with
    // PERF_FORMAT_GROUP, so adding followers exercises the same simultaneous
    // co-scheduling constraint the real recording hits (a non-sampling leader
    // would allow multiplexing and over-report what fits). If even this can't
    // open it's a permissions problem, not missing counters — keep the full
    // set and let the real recording surface the perms error on its own leader.
    const leader_fd = openSamplingLeader();
    if (leader_fd < 0) return dupAll(gpa);
    defer _ = linux.close(leader_fd);

    // Followers that opened stay open while probing the next, so each test is
    // against the cumulative group (the real co-scheduling condition).
    // Candidates are ordered essentials-first (cycles, instructions) so the
    // IPC pair is reserved before optional counters can exhaust the PMU.
    var open_fds: [CANDIDATES.len]i32 = undefined;
    var n_open: usize = 0;
    defer for (open_fds[0..n_open]) |fd| {
        _ = linux.close(fd);
    };

    var supported: std.ArrayList(proto.PerfCounter) = .empty;
    errdefer supported.deinit(gpa);
    var skipped_buf: [CANDIDATES.len][]const u8 = undefined;
    var n_skipped: usize = 0;

    for (CANDIDATES) |c| {
        var attr: linux.perf_event_attr = .{};
        attr.type = .HARDWARE;
        attr.config = @intFromEnum(c.hw);
        attr.flags.disabled = false; // a follower; enabled with the leader
        const rc = linux.perf_event_open(&attr, -1, 0, leader_fd, PERF_FLAG_FD_CLOEXEC);
        if (linux.errno(rc) == .SUCCESS) {
            open_fds[n_open] = @intCast(rc);
            n_open += 1;
            try supported.append(gpa, .{ .id = c.perfetto_id, .name = c.name });
        } else {
            // Either unsupported by the PMU or it would overflow the group's
            // simultaneously-schedulable counters — drop it either way.
            skipped_buf[n_skipped] = c.name;
            n_skipped += 1;
        }
    }

    logSummary(supported.items, skipped_buf[0..n_skipped]);
    return supported.toOwnedSlice(gpa);
}

fn openSamplingLeader() i32 {
    var attr: linux.perf_event_attr = .{};
    attr.type = .SOFTWARE;
    attr.config = @intFromEnum(linux.PERF.COUNT.SW.CPU_CLOCK);
    attr.sample_period_or_freq = 1000;
    attr.sample_type = linux.PERF.SAMPLE.IP;
    attr.read_format = PERF_FORMAT_GROUP;
    attr.flags.freq = true;
    attr.flags.disabled = true;
    const rc = linux.perf_event_open(&attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
    if (linux.errno(rc) != .SUCCESS) return -1;
    return @intCast(rc);
}

fn dupAll(gpa: std.mem.Allocator) ![]proto.PerfCounter {
    const out = try gpa.alloc(proto.PerfCounter, CANDIDATES.len);
    for (CANDIDATES, 0..) |c, i| out[i] = .{ .id = c.perfetto_id, .name = c.name };
    return out;
}

fn logSummary(enabled: []const proto.PerfCounter, skipped: []const []const u8) void {
    if (enabled.len == 0) {
        std.debug.print("sismo record: PMU counters: none available on this hardware\n", .{});
        return;
    }
    std.debug.print("sismo record: PMU counters enabled:", .{});
    for (enabled, 0..) |e, i| {
        std.debug.print("{s} {s}", .{ if (i == 0) "" else ",", e.name });
    }
    if (skipped.len > 0) {
        std.debug.print(" (unsupported, skipped:", .{});
        for (skipped, 0..) |s, i| {
            std.debug.print("{s} {s}", .{ if (i == 0) "" else ",", s });
        }
        std.debug.print(")", .{});
    }
    std.debug.print("\n", .{});
}
