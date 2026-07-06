// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! C-ABI entry for the host-flipped build, where cargo produces the `sismo`
//! binary and a Rust `main` calls in here. A Zig staticlib has no runtime
//! start code, so this reconstructs the `std.process.Init` that std/start.zig's
//! `callMain` would normally build (io.Threaded backend, arena, gpa, env,
//! preopens), then runs the real dispatcher `sismo.main`.
//!
//! The Rust caller passes the process's raw argc/argv/envp (see
//! rust-bridge/src/main.rs), exactly as the C runtime would hand them to a
//! C `main`.

const std = @import("std");
const sismo = @import("sismo.zig");

export fn zig_sismo_main(
    argc: c_int,
    argv: [*][*:0]u8,
    envp: [*:null]?[*:0]u8,
) c_int {
    var env_count: usize = 0;
    while (envp[env_count] != null) : (env_count += 1) {}
    const env_block: std.process.Environ.Block = .{ .slice = envp[0..env_count :null] };
    const args_vec: std.process.Args.Vector = argv[0..@intCast(argc)];

    // libc is linked (the C runtime owns the process), so c_allocator is the
    // gpa std/start.zig would pick; the arena backs long-lived process state.
    const gpa = std.heap.c_allocator;

    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();

    var threaded: std.Io.Threaded = .init(gpa, .{
        .argv0 = .init(.{ .vector = args_vec }),
        .environ = .{ .block = env_block },
    });
    defer threaded.deinit();

    var environ_map = std.process.Environ.createMap(.{ .block = env_block }, gpa) catch return 1;
    defer environ_map.deinit();

    const preopens = std.process.Preopens.init(arena_allocator.allocator()) catch return 1;

    const init: std.process.Init = .{
        .minimal = .{
            .args = .{ .vector = args_vec },
            .environ = .{ .block = env_block },
        },
        .arena = &arena_allocator,
        .gpa = gpa,
        .io = threaded.io(),
        .environ_map = &environ_map,
        .preopens = preopens,
    };

    sismo.main(init) catch |err| {
        std.log.err("{t}", .{err});
        return 1;
    };
    return 0;
}
