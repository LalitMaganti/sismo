// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `sismo` — top-level CLI dispatcher.
//!
//! Subcommands:
//!   record           Run the unified recorder (orchestrator + in-process
//!                    producers). Either spawns the workload (--pid absent)
//!                    or attaches to a running one (--pid <pid>). Drives
//!                    kdebug + CPU + heap, writes a single Perfetto trace.
//!   prepare          Launch a workload with the sismo dormant heap client
//!                    (DYLD_INSERT_LIBRARIES) and the well-known producer
//!                    socket env wired in, then exec into the command.
//!                    Pair with `sismo record --pid` to attach later.
//!   datasource       Run a single producer in daemonized mode. Connects
//!                    to PERFETTO_PRODUCER_SOCK_NAME (set by whoever is
//!                    hosting traced — typically `sismo record` in
//!                    distributed mode), registers exactly one data
//!                    source, lives until killed.
//!
//! The routing decision — help text, unknown-subcommand error, and which
//! subcommand to run — lives in rust-bridge (src/cli.rs). This file extracts
//! the subcommand token and hands off; the chosen subcommand still parses its
//! own args from `init.minimal.args` (skipping exe path + subcommand token).

const std = @import("std");
const record = @import("cmd_record.zig");
const prepare = @import("cmd_prepare.zig");
const snapshot = @import("cmd_snapshot.zig");
const datasource = @import("cmd_datasource.zig");

// rust-bridge/src/cli.rs — see rust-bridge/include/bridge.h for the contract.
const cli_handled: i32 = 0;
const cli_record: i32 = 1;
const cli_prepare: i32 = 2;
const cli_snapshot: i32 = 3;
const cli_datasource: i32 = 4;

extern fn sismo_cli_dispatch(cmd_utf8: ?[*]const u8, cmd_len: usize, exit_code: *i32) i32;

pub fn main(init: std.process.Init) !void {
    var iter = init.minimal.args.iterate();
    _ = iter.next(); // exe path
    const cmd = iter.next(); // subcommand token, or null

    var exit_code: i32 = 0;
    const decision = sismo_cli_dispatch(
        if (cmd) |c| c.ptr else null,
        if (cmd) |c| c.len else 0,
        &exit_code,
    );

    switch (decision) {
        cli_handled => {
            // Bridge already printed help or the unknown-subcommand error.
            if (exit_code != 0) std.process.exit(@intCast(exit_code));
        },
        cli_record => return record.runRecord(init),
        cli_prepare => return prepare.runPrepare(init),
        cli_snapshot => return snapshot.runSnapshot(init),
        cli_datasource => return datasource.runDatasource(init),
        else => unreachable,
    }
}
