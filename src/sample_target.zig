// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `sample-target` — workload binary `sismo record` spawns and
//! profiles. Three deliberately distinct threads so the trace is
//! easy to read by eye:
//!   - `busyWorker`  — tight arithmetic loop + periodic malloc; near-
//!                     100% CPU.
//!   - `sleepyWorker` — short bursts of work between 2 ms sleeps.
//!   - `sdkWorker`   — emits TrackEvent slices via Perfetto's stock
//!                     SDK so the trace exercises `track_event` too.
//!
//!     zig build sample-target
//!     zig-out/bin/sample-target [duration-ms]
//!
//! Default duration is 5000 ms — long enough for an interesting
//! profile, short enough that a stray invocation exits on its own.

const std = @import("std");

const c = @cImport({
    @cInclude("src/c/sample_target_sdk.h");
});

fn sleepUs(us: u64) void {
    const ts: std.c.timespec = .{
        .sec = @intCast(us / std.time.us_per_s),
        .nsec = @intCast((us % std.time.us_per_s) * std.time.ns_per_us),
    };
    _ = std.c.nanosleep(&ts, null);
}

fn sdkWorker(stop: *std.atomic.Value(bool)) void {
    var iter: u32 = 0;
    while (!stop.load(.monotonic)) {
        iter +%= 1;
        c.sismo_target_slice_begin("frame");
        c.sismo_target_slice_begin("update");
        sleepUs(500);
        c.sismo_target_slice_end();
        c.sismo_target_slice_begin("draw");
        sleepUs(800);
        c.sismo_target_slice_end();
        c.sismo_target_slice_end();
        if (iter % 100 == 0) c.sismo_target_instant("milestone");
        sleepUs(1000);
    }
}

fn busyWorker(stop: *std.atomic.Value(bool)) void {
    var x: u64 = 0;
    var iter: u32 = 0;
    while (!stop.load(.monotonic)) {
        var i: u32 = 0;
        while (i < 1024) : (i += 1) x = x *% 2654435761 +% i;
        std.mem.doNotOptimizeAway(&x);
        // Periodic libc malloc so a heap orchestrator that attaches
        // *after* the startup allocation phase has steady-state
        // captures to consume. Cycle through several sizes so the
        // Poisson sampler captures both small (high-rate) and large
        // (always-sampled) allocations.
        iter +%= 1;
        if (iter % 4 == 0) {
            const sz: usize = switch (iter % 16) {
                0 => 64,
                4 => 256,
                8 => 1024,
                else => 8192, // > sampling interval, always recorded
            };
            const p = std.c.malloc(sz);
            if (p) |ptr| std.c.free(ptr);
        }
    }
}

fn sleepyWorker(stop: *std.atomic.Value(bool)) void {
    var x: u64 = 0;
    while (!stop.load(.monotonic)) {
        sleepUs(2000);
        var i: u32 = 0;
        while (i < 64) : (i += 1) x = x *% 2654435761 +% i;
        std.mem.doNotOptimizeAway(&x);
    }
}

pub fn main(init: std.process.Init.Minimal) !void {
    var iter = init.args.iterate();
    _ = iter.next(); // program name

    var duration_ms: u32 = 5000;
    if (iter.next()) |s| {
        duration_ms = std.fmt.parseInt(u32, s, 10) catch duration_ms;
    }

    const pid = std.c.getpid();
    std.debug.print("sample-target pid={d} duration_ms={d}\n", .{ pid, duration_ms });

    // Connect to the orchestrator's hosted producer socket. SYSTEM
    // backend; `sismo record` owns the session.
    c.sismo_target_te_init();

    // Deterministic allocation phase — gives Q2-macOS a known-shape
    // count to compare against. 1000 explicit libc mallocs from a
    // recognizable site. The sleep-based workers below also do a few
    // thread-spawn allocations but those are noise; this loop is the
    // signal.
    {
        var i: usize = 0;
        while (i < 1000) : (i += 1) {
            const p = std.c.malloc(4096) orelse continue;
            std.c.free(p);
        }
        std.debug.print("sample-target: allocation phase done (1000 explicit libc mallocs)\n", .{});
    }

    var stop = std.atomic.Value(bool).init(false);
    const t_busy = try std.Thread.spawn(.{}, busyWorker, .{&stop});
    const t_sleepy = try std.Thread.spawn(.{}, sleepyWorker, .{&stop});
    const t_sdk = try std.Thread.spawn(.{}, sdkWorker, .{&stop});

    sleepUs(@as(u64, duration_ms) * 1000);

    stop.store(true, .monotonic);
    t_busy.join();
    t_sleepy.join();
    t_sdk.join();
}
