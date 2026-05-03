// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `sismo snapshot` — flight-recorder snapshot client.
//!
//! Doesn't talk to the recorder process. Connects independently to
//! the in-process tracing service the recorder hosts (via its
//! ServiceIPCHost in `sismo_traced.cc`) as a fresh consumer, calls
//! TracingSession::CloneTrace + ReadTrace (Perfetto C++ SDK), and
//! streams the trace bytes back to this Zig code via a chunk
//! callback. We own the file I/O — open, write each chunk, close —
//! using std.Io rather than libc externs so the path/error surface
//! lines up with the rest of sismo.
//!
//! The recorder is uninvolved — no SIGUSR1, no IPC, no shared state
//! beyond the named session ("sismo_record"). Multiple snapshots can
//! be taken concurrently; the source session keeps recording.
//!
//! Usage:
//!   sismo snapshot [--output <path>]
//!
//! Default --output: ./sismo-<UTC-ISO8601>.pftrace in the current dir.

const std = @import("std");
const paths = @import("sismo_paths.zig");

const c = @cImport({
    @cInclude("src/c/perfetto_shim.h");
});

// setenv has no idiomatic Zig wrapper — env mutation is intentionally
// gated through libc so it stays in sync with the libc-side environ
// the C++ SDK reads.
extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;

/// Build a UTC timestamp like "20260502-171530" suitable for use in a
/// filename. Buffer must be at least 16 bytes.
fn formatTimestamp(buf: []u8, io: std.Io) ![]u8 {
    // std.time has only constants in 0.16 — no `timestamp()`. Wall
    // clock comes from std.Io.Clock.now(.real, io), in nanoseconds.
    const ts = std.Io.Clock.now(.real, io);
    if (ts.nanoseconds < 0) return error.NegativeTime;
    const now: i64 = @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_s));
    const epoch_secs: std.time.epoch.EpochSeconds = .{ .secs = @as(u64, @intCast(now)) };
    const day = epoch_secs.getEpochDay();
    const yd = day.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = epoch_secs.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}{d:0>2}{d:0>2}-{d:0>2}{d:0>2}{d:0>2}", .{
        yd.year,
        md.month.numeric(),
        md.day_index + 1,
        ds.getHoursIntoDay(),
        ds.getMinutesIntoHour(),
        ds.getSecondsIntoMinute(),
    });
}

/// State the C++ chunk callback writes through. The callback may fire
/// on a Perfetto-internal thread; std.Io's Threaded backend is fine
/// across threads (it's the canonical multi-threaded Io for Zig 0.16).
const SnapshotCtx = struct {
    io: std.Io,
    file: std.Io.File,
    write_failed: bool = false,
    bytes_written: u64 = 0,
};

fn snapshotChunkCb(
    data: ?*const anyopaque,
    size: usize,
    has_more: bool,
    user_arg: ?*anyopaque,
) callconv(.c) void {
    _ = has_more;
    if (size == 0 or user_arg == null or data == null) return;
    const ctx: *SnapshotCtx = @ptrCast(@alignCast(user_arg.?));
    if (ctx.write_failed) return;
    const slice: []const u8 = @as([*]const u8, @ptrCast(data.?))[0..size];
    ctx.file.writeStreamingAll(ctx.io, slice) catch {
        ctx.write_failed = true;
        return;
    };
    ctx.bytes_written += size;
}

pub fn runSnapshot(init: std.process.Init) !void {
    const io = init.io;

    var iter = init.minimal.args.iterate();
    _ = iter.next(); // exe path
    _ = iter.next(); // "snapshot" subcommand token

    var output_arg: ?[]const u8 = null;
    while (iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--output")) {
            output_arg = iter.next() orelse {
                std.debug.print("sismo snapshot: --output needs a value\n", .{});
                return;
            };
        } else if (std.mem.eql(u8, arg, "--help")) {
            std.debug.print(
                "usage: sismo snapshot [--output <path>]\n" ++
                "\n" ++
                "  Capture a snapshot of the currently-running flight-recorder\n" ++
                "  session. Default output: ./sismo-<UTC>.pftrace.\n",
                .{},
            );
            return;
        } else {
            std.debug.print("sismo snapshot: unknown arg '{s}'\n", .{arg});
            return;
        }
    }

    var ts_buf: [16]u8 = undefined;
    const ts = formatTimestamp(&ts_buf, io) catch return;
    var default_buf: [128]u8 = undefined;
    const default_path = std.fmt.bufPrint(&default_buf, "./sismo-{s}.pftrace", .{ts}) catch return;
    const output_path = output_arg orelse default_path;

    // Point the C++ SDK at the well-known sockets sismo-record hosts.
    // Without these, NewTrace(kSystemBackend) defaults to Perfetto's
    // built-in path which won't reach our in-process service.
    _ = setenv("PERFETTO_PRODUCER_SOCK_NAME", paths.producer_sock.ptr, 1);
    _ = setenv("PERFETTO_CONSUMER_SOCK_NAME", paths.consumer_sock.ptr, 1);

    // Open the destination via std.Io.Dir; chunks land here from the
    // C++ side via snapshotChunkCb.
    var file = std.Io.Dir.cwd().createFile(io, output_path, .{}) catch |err| {
        std.debug.print(
            "sismo snapshot: failed to create {s}: {s}\n",
            .{ output_path, @errorName(err) },
        );
        return;
    };
    defer file.close(io);

    var ctx: SnapshotCtx = .{ .io = io, .file = file };
    const rc = c.sismo_consumer_clone_and_stream("sismo_record", &snapshotChunkCb, &ctx);
    if (rc != 0) {
        std.debug.print(
            "sismo snapshot: clone failed (rc={d}). Is `sismo record --flight-recorder` running?\n",
            .{rc},
        );
        return;
    }
    if (ctx.write_failed) {
        std.debug.print("sismo snapshot: write to {s} failed mid-stream\n", .{output_path});
        return;
    }

    std.debug.print(
        "sismo snapshot: wrote {s} ({d} bytes)\n",
        .{ output_path, ctx.bytes_written },
    );
}
