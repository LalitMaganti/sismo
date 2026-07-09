// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! The single Zig entry point. cargo produces the `sismo` binary and a Rust
//! `main` (rust-host/src/main.rs) calls `zig_sismo_main` with the process's
//! raw argc/argv/envp. A Zig staticlib has no runtime start code, so this
//! reconstructs the `std.process.Init` that std/start.zig's `callMain` would
//! build (io.Threaded backend, arena, gpa, env, preopens), then dispatches to
//! the subcommand.
//!
//! Subcommands:
//!   record       Run the unified recorder (orchestrator + in-process
//!                producers), writing a single Perfetto trace.
//!   prepare      Launch a workload with the sismo dormant heap client
//!                preloaded, to attach to later via `sismo record --pid`.
//!   datasource   Run a single producer in daemonized mode.
//!
//! The routing decision — help text, unknown-subcommand error, and which
//! subcommand to run — lives in rust-bridge (src/cli.rs). Each subcommand
//! parses its own args from `init.minimal.args`.

const std = @import("std");
const record = @import("cmd_record.zig");

// snapshot, prepare, and datasource now live in Rust (rust-bridge/src/cmd_*.rs);
// each owns its arg parsing + exit code, so dispatch calls them directly with
// argv. record is the last Zig subcommand.
extern fn sismo_cmd_snapshot(argc: usize, argv: [*]const [*:0]const u8) c_int;
extern fn sismo_cmd_prepare(argc: usize, argv: [*]const [*:0]const u8) c_int;
extern fn sismo_cmd_datasource(argc: usize, argv: [*]const [*:0]const u8) c_int;

// rust-bridge/src/cli.rs — see rust-bridge/include/bridge.h for the contract.
const cli_handled: i32 = 0;
const cli_record: i32 = 1;
const cli_prepare: i32 = 2;
const cli_snapshot: i32 = 3;
const cli_datasource: i32 = 4;

extern fn sismo_cli_dispatch(cmd_utf8: ?[*]const u8, cmd_len: usize, exit_code: *i32) i32;

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

    return dispatch(init);
}

fn dispatch(init: std.process.Init) c_int {
    var iter = init.minimal.args.iterate();
    _ = iter.next(); // exe path
    const cmd = iter.next(); // subcommand token, or null

    var exit_code: i32 = 0;
    const decision = sismo_cli_dispatch(
        if (cmd) |c| c.ptr else null,
        if (cmd) |c| c.len else 0,
        &exit_code,
    );

    // snapshot + prepare + datasource are fully in Rust — hand them the raw
    // argv and return their exit code directly.
    const v = init.minimal.args.vector;
    if (decision == cli_snapshot) return sismo_cmd_snapshot(v.len, @ptrCast(v.ptr));
    if (decision == cli_prepare) return sismo_cmd_prepare(v.len, @ptrCast(v.ptr));
    if (decision == cli_datasource) return sismo_cmd_datasource(v.len, @ptrCast(v.ptr));

    const result = switch (decision) {
        // Bridge already printed help or the unknown-subcommand error; exit
        // with the code it chose (0 for help, 2 for unknown).
        cli_handled => return exit_code,
        cli_record => record.runRecord(init),
        else => unreachable,
    };
    result catch |err| {
        std.log.err("{t}", .{err});
        return 1;
    };
    return 0;
}
