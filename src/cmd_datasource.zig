//! `sismo datasource <name>` — daemonized producer.
//!
//! Connects to PERFETTO_PRODUCER_SOCK_NAME (set by whoever's hosting
//! traced — typically `sismo record` in a future distributed mode,
//! or a stock `traced` binary), registers exactly one of the
//! `sismo.*` data sources, and blocks until killed (SIGINT /
//! SIGTERM).
//!
//! Config (target_pid for macos_cpu_samples/heap, sizing knobs for macos_sched)
//! arrives via the on_setup callback when a session enables our DS,
//! decoded from `DataSourceConfig.sismo_config` (field 2000) — see
//! `src/sismo_config.zig`. The producer's CLI doesn't take any
//! tracing-config flags; a session is what configures the producer.

const std = @import("std");
const builtin = @import("builtin");
const c = @cImport({
    @cInclude("perfetto_shim.h");
});

// macOS-only data sources: perf_event-based Linux equivalents (and ETW
// on Windows) live in sibling modules once they're implemented. The
// `else => struct {}` arm keeps the file compileable everywhere; the
// runtime body below short-circuits with a clear error on non-macOS.
const macos_sched_capture = switch (builtin.os.tag) {
    .macos => @import("macos_sched_capture.zig"),
    else => struct {},
};
const macos_cpu_samples_capture = switch (builtin.os.tag) {
    .macos => @import("macos_cpu_samples_capture.zig"),
    else => struct {},
};
const heap_capture = switch (builtin.os.tag) {
    .macos => @import("heap_capture.zig"),
    else => struct {},
};

// Set by SIGINT/SIGTERM handlers to break the run loop. Async-signal-
// safe (atomic store), so we don't touch any locks in the handler.
var g_should_stop = std.atomic.Value(bool).init(false);

fn handleStopSignal(sig: std.c.SIG) callconv(.c) void {
    _ = sig;
    g_should_stop.store(true, .release);
}

fn installStopHandlers() void {
    const act: std.c.Sigaction = .{
        .handler = .{ .handler = handleStopSignal },
        .mask = std.mem.zeroes(std.c.sigset_t),
        .flags = 0,
    };
    std.posix.sigaction(.INT, &act, null);
    std.posix.sigaction(.TERM, &act, null);
}

const usage =
    \\usage: sismo datasource <name>
    \\
    \\  <name>: macos_sched | macos_cpu_samples | heap
    \\          ("sismo." prefix accepted for symmetry with the
    \\          DataSourceConfig.name on the wire.)
    \\
    \\  Connects to PERFETTO_PRODUCER_SOCK_NAME, registers exactly
    \\  one data source, blocks until SIGINT/SIGTERM. Config arrives
    \\  via on_setup from the consumer's TraceConfig.
    \\
;

const Kind = enum { macos_sched, macos_cpu_samples, heap };

fn parseKind(name: []const u8) ?Kind {
    const stripped = if (std.mem.startsWith(u8, name, "sismo.")) name[6..] else name;
    if (std.mem.eql(u8, stripped, "macos_sched")) return .macos_sched;
    if (std.mem.eql(u8, stripped, "macos_cpu_samples")) return .macos_cpu_samples;
    if (std.mem.eql(u8, stripped, "heap")) return .heap;
    return null;
}

pub fn runDatasource(init: std.process.Init) !void {
    var iter = init.minimal.args.iterate();
    _ = iter.next(); // exe path
    _ = iter.next(); // "datasource" subcommand token
    const name = iter.next() orelse {
        std.debug.print("{s}", .{usage});
        return;
    };
    const kind = parseKind(name) orelse {
        std.debug.print("sismo datasource: unknown data source '{s}'\n\n{s}", .{ name, usage });
        return;
    };

    if (comptime builtin.os.tag == .macos) {
        return runDatasourceMacos(init, kind);
    }
    std.debug.print(
        "sismo datasource: '{s}' is not yet implemented on {s}\n",
        .{ name, @tagName(builtin.os.tag) },
    );
}

fn runDatasourceMacos(init: std.process.Init, kind: Kind) !void {
    c.sismo_perfetto_init();

    const ds = c.sismo_perfetto_ds_alloc() orelse return error.PerfettoDsAllocFailed;
    defer c.sismo_perfetto_ds_free(ds);

    installStopHandlers();

    switch (kind) {
        .macos_sched => {
            const cap = try macos_sched_capture.Capture.init(init.gpa, init.io, ds, .{});
            if (!c.sismo_perfetto_ds_register_with_callbacks(
                ds,
                "sismo.macos_sched",
                macos_sched_capture.Capture.onSetupTrampoline,
                macos_sched_capture.Capture.onStartTrampoline,
                macos_sched_capture.Capture.onStopTrampoline,
                macos_sched_capture.Capture.onFlushTrampoline,
                cap,
            )) return error.PerfettoDsRegisterFailed;
            std.debug.print("sismo datasource: sismo.macos_sched registered; blocking until SIGINT/SIGTERM\n", .{});
            blockUntilStopped();
            const stats = cap.shutdown();
            std.debug.print(
                "sismo datasource: sismo.macos_sched stopped — {d} events / {d} drains\n",
                .{ stats.events_emitted, stats.drain_calls },
            );
        },
        .macos_cpu_samples => {
            const cap = try macos_cpu_samples_capture.Capture.init(init.gpa, init.io, ds, .{});
            if (!c.sismo_perfetto_ds_register_with_callbacks(
                ds,
                "sismo.macos_cpu_samples",
                macos_cpu_samples_capture.Capture.onSetupTrampoline,
                macos_cpu_samples_capture.Capture.onStartTrampoline,
                macos_cpu_samples_capture.Capture.onStopTrampoline,
                macos_cpu_samples_capture.Capture.onFlushTrampoline,
                cap,
            )) return error.PerfettoDsRegisterFailed;
            std.debug.print("sismo datasource: sismo.macos_cpu_samples registered; blocking until SIGINT/SIGTERM\n", .{});
            blockUntilStopped();
            const stats = cap.shutdown();
            std.debug.print(
                "sismo datasource: sismo.macos_cpu_samples stopped — {d} samples ({d} active)\n",
                .{ stats.samples, stats.active_samples },
            );
        },
        .heap => {
            const cap = try heap_capture.Capture.init(init.gpa, init.io, ds, .{});
            if (!c.sismo_perfetto_ds_register_with_callbacks(
                ds,
                "sismo.heap",
                heap_capture.Capture.onSetupTrampoline,
                heap_capture.Capture.onStartTrampoline,
                heap_capture.Capture.onStopTrampoline,
                heap_capture.Capture.onFlushTrampoline,
                cap,
            )) return error.PerfettoDsRegisterFailed;
            std.debug.print("sismo datasource: sismo.heap registered; blocking until SIGINT/SIGTERM\n", .{});
            blockUntilStopped();
            const stats = cap.shutdown();
            std.debug.print(
                "sismo datasource: sismo.heap stopped — {d} records / ~{d} bytes / {d} sites\n",
                .{ stats.records, stats.bytes_alloc_estimated, stats.sites },
            );
        },
    }
}

fn blockUntilStopped() void {
    // Coarse poll. The signal handler can't safely touch a condvar /
    // event (no async-signal-safety guarantee), so we just check the
    // atomic on a short interval — wakeup latency = 100 ms, which is
    // fine for an SIGTERM.
    const ts: std.c.timespec = .{ .sec = 0, .nsec = 100 * std.time.ns_per_ms };
    while (!g_should_stop.load(.acquire)) {
        _ = std.c.nanosleep(&ts, null);
    }
}
