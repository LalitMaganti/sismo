// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `sismo prepare` — launch a workload with the sismo dormant heap
//! client (and the well-known producer socket env) wired in, then
//! `execvp` into the user's command. The workload runs as a normal
//! process from then on; you record from it later via:
//!
//!     sismo prepare ./myapp arg1 arg2 &      # dormant client loaded
//!     sismo record --pid $(pgrep myapp)      # attach + record
//!
//! Why a separate subcommand instead of `sismo record <cmd>` doing
//! the prepare itself: `sismo record` already does it (spawn mode), but
//! that ties recording to launch time. Many real workflows are "this
//! daemon's been running, I want to record it now" — for those the
//! user pre-launches via `prepare`, then attaches whenever something
//! interesting happens.
//!
//! DYLD_INSERT_LIBRARIES points dyld at libsismo_heap.dylib so the
//! workload loads the dormant client (its constructor binds
//! /tmp/sismo-heap-{pid}.sock and waits for sismo to attach).
//! PERFETTO_PRODUCER_SOCK_NAME points any Perfetto-SDK-linked workload at
//! the well-known producer socket — redundant once the sismo SDK bakes
//! the path in, but harmless to keep setting. Then execvp inherits the
//! env into the user's command.
//!
//! Hardened-runtime caveat: macOS strips DYLD_INSERT_LIBRARIES from the
//! env on exec for hardened-runtime / library-validation / restricted-
//! segment binaries. Unsigned dev binaries (the audience here) are fine;
//! for signed third-party apps heap injection silently fails. sismo does
//! not detect this at prepare time — the user notices when sismo record
//! reports the heap socket missing.

const std = @import("std");
const paths = @import("sismo_paths.zig");

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn execvp(file: [*:0]const u8, argv: [*:null]const ?[*:0]const u8) c_int;

pub fn runPrepare(init: std.process.Init) !void {
    const gpa = init.gpa;

    var iter = init.minimal.args.iterate();
    _ = iter.next(); // exe path
    _ = iter.next(); // "prepare" subcommand token

    // First positional is the workload's argv[0]; the rest are its
    // argv[1..]. --help is the only flag prepare understands.
    var workload_argv: std.ArrayList([]const u8) = .empty;
    defer workload_argv.deinit(gpa);

    while (iter.next()) |arg| {
        if (workload_argv.items.len == 0 and std.mem.eql(u8, arg, "--help")) {
            std.debug.print(
                "usage: sismo prepare <command> [args...]\n" ++
                    "\n" ++
                    "  Launch <command> with sismo's heap-profiler dormant client\n" ++
                    "  preloaded. The launched process can later be recorded via\n" ++
                    "  `sismo record --pid <pid>`.\n",
                .{},
            );
            return;
        }
        try workload_argv.append(gpa, arg);
    }

    if (workload_argv.items.len == 0) {
        std.debug.print(
            "sismo prepare: no command specified\n" ++
                "usage: sismo prepare <command> [args...]\n",
            .{},
        );
        return;
    }

    const heap_dylib = paths.heapDylibPath(init.io, gpa) catch |err| {
        std.debug.print("sismo prepare: failed to resolve heap dylib path: {s}\n", .{@errorName(err)});
        return;
    };
    defer gpa.free(heap_dylib);

    _ = setenv("DYLD_INSERT_LIBRARIES", heap_dylib.ptr, 1);
    _ = setenv("PERFETTO_PRODUCER_SOCK_NAME", paths.producer_sock.ptr, 1);

    // Build NUL-terminated argv for execvp (the [*:null] type requires
    // the trailing null sentinel).
    const cmd = workload_argv.items[0];
    var argv_z = try gpa.alloc(?[*:0]const u8, workload_argv.items.len + 1);
    defer gpa.free(argv_z);

    var arg_dups = try gpa.alloc([:0]u8, workload_argv.items.len);
    defer {
        for (arg_dups) |s| gpa.free(s);
        gpa.free(arg_dups);
    }
    for (workload_argv.items, 0..) |a, i| {
        arg_dups[i] = try gpa.dupeZ(u8, a);
        argv_z[i] = arg_dups[i].ptr;
    }
    argv_z[workload_argv.items.len] = null;

    // execvp replaces this process; only returns on failure.
    const rc = execvp(arg_dups[0].ptr, @ptrCast(argv_z.ptr));
    std.debug.print("sismo prepare: execvp({s}) failed rc={d}\n", .{ cmd, rc });
}
