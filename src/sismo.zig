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
//! Subcommand args are parsed by each subcommand handler — they
//! re-iterate `init.minimal.args` and skip the first two slots
//! (exe path + subcommand token) themselves.

const std = @import("std");
const record = @import("cmd_record.zig");
const prepare = @import("cmd_prepare.zig");
const snapshot = @import("cmd_snapshot.zig");
const datasource = @import("cmd_datasource.zig");

const help_text =
    \\sismo - cross-platform desktop tracing/profiling tool
    \\
    \\Usage:
    \\  sismo record [--output <path>] [--duration <dur>] <command> [args...]
    \\  sismo record [--output <path>] [--duration <dur>] --pid <pid>
    \\      Spawn <command> (or attach to --pid) and record sched +
    \\      CPU samples + heap into a single Perfetto trace. Stops on
    \\      SIGINT, target exit, or --duration. Default --output:
    \\      ./sismo.pftrace. Requires sudo on macOS for kdebug +
    \\      task_for_pid.
    \\
    \\  sismo prepare <command> [args...]
    \\      Launch <command> with sismo's dormant heap client preloaded
    \\      and PERFETTO_PRODUCER_SOCK_NAME set to the well-known path.
    \\      The launched process can be attached to later via
    \\      `sismo record --pid <pid>`.
    \\
    \\  sismo snapshot [--output <path>]
    \\      Capture a snapshot of a running flight-recorder session
    \\      (`sismo record --flight-recorder`). Connects to the in-
    \\      process service as a fresh consumer, clones the session,
    \\      writes the trace, exits — the recorder is uninvolved.
    \\
    \\  sismo datasource <name>
    \\      Daemonized producer. <name> in {macos_sched, macos_cpu_samples,
    \\      heap}. Connects to PERFETTO_PRODUCER_SOCK_NAME, registers
    \\      sismo.<name>, blocks until killed.
    \\
    \\  sismo --help
    \\      Show this help.
    \\
;

pub fn main(init: std.process.Init) !void {
    var iter = init.minimal.args.iterate();
    _ = iter.next(); // exe path

    const cmd = iter.next() orelse {
        std.debug.print("{s}", .{help_text});
        return;
    };

    if (std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h") or std.mem.eql(u8, cmd, "help")) {
        std.debug.print("{s}", .{help_text});
        return;
    }

    if (std.mem.eql(u8, cmd, "record")) {
        return record.runRecord(init);
    }

    if (std.mem.eql(u8, cmd, "prepare")) {
        return prepare.runPrepare(init);
    }

    if (std.mem.eql(u8, cmd, "snapshot")) {
        return snapshot.runSnapshot(init);
    }

    if (std.mem.eql(u8, cmd, "datasource")) {
        return datasource.runDatasource(init);
    }

    std.debug.print("sismo: unknown subcommand '{s}'\n\n{s}", .{ cmd, help_text });
}
