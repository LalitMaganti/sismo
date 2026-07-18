// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.
//
// Zig port of the canonical matrix workload (see workload.c for the shape).

const std = @import("std");

noinline fn sismo_wl_leaf(x0: u64) u64 {
    var x = x0;
    var i: u64 = 0;
    while (i < 4096) : (i += 1) {
        x = x *% 2654435761 +% i;
    }
    return x;
}

noinline fn sismo_wl_mid(x0: u64) u64 {
    var x = x0;
    var i: u64 = 0;
    while (i < 8) : (i += 1) {
        x = sismo_wl_leaf(x ^ i);
    }
    return x;
}

noinline fn sismo_wl_outer(x0: u64) u64 {
    var x = x0;
    var i: u64 = 0;
    while (i < 4) : (i += 1) {
        x = sismo_wl_mid(x +% i);
    }
    return x;
}

// Raw linux syscalls: the 0.16 std.Io time/sleep interface is still
// churning, and this workload is Linux-only anyway.
const linux = std.os.linux;

noinline fn sismo_wl_block() void {
    const req: linux.timespec = .{ .sec = 0, .nsec = 2 * std.time.ns_per_ms };
    _ = linux.nanosleep(&req, null);
}

fn now_ms() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var args = std.process.Args.Iterator.init(init.args);
    _ = args.next();
    const duration_ms: u64 = blk: {
        if (args.next()) |a| {
            break :blk std.fmt.parseInt(u64, a, 10) catch 3000;
        }
        break :blk 3000;
    };

    const end = now_ms() + duration_ms;
    var x: u64 = 1;
    var iters: u64 = 0;
    while (now_ms() < end) {
        x = sismo_wl_outer(x);
        iters += 1;
        if (iters % 32 == 0) {
            sismo_wl_block();
        }
    }
    std.mem.doNotOptimizeAway(x);
    // stderr to sidestep the 0.x stdout API churn; the harness scans both.
    std.debug.print("sismo-workload iters={d}\n", .{iters});
}
