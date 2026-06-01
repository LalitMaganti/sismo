// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `sismo datasource <id> [<id>...]` — daemonized producer hosting one
//! or more sismo data sources in this single process.
//!
//! Connects to PERFETTO_PRODUCER_SOCK_NAME (set by whoever's hosting
//! traced — typically `sismo record` in privsep mode), registers each
//! requested data source, and blocks until killed (SIGINT / SIGTERM).
//!
//! Identifiers are **platform-independent** — sismo maps them to the
//! actual `sismo.*` data source name for the running OS:
//!
//!   sched         macOS → sismo.macos_sched   Linux → (TBD)
//!   cpu           macOS → sismo.macos_cpu_samples   Linux → (TBD)
//!   heap          macOS → sismo.heap          Linux → sismo.heap
//!   all-privileged
//!                 expands per-platform to the full set of data sources
//!                 that need elevation on this OS. On macOS:
//!                 sched + cpu + heap.
//!
//! Bundling many data sources in one invocation matters because each
//! one needs a sudo prompt; one process = one prompt. The companion
//! flag set on `sismo record` is `--external-{sched,cpu,heap}` (or
//! `--all-external` for the common case).
//!
//! Config (target_pid for cpu/heap, sizing knobs for sched) arrives via
//! the on_setup callback when a session enables a DS, decoded from
//! `DataSourceConfig.sismo_config` (field 2000) — see
//! `src/sismo_config.zig`. The producer's CLI doesn't take any
//! tracing-config flags; a session is what configures the producer.

const std = @import("std");
const builtin = @import("builtin");
const c = @cImport({
    @cInclude("src/c/perfetto_shim.h");
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

// Set by SIGINT/SIGTERM handlers to break the run loop. Async-signal-safe
// (atomic store), so the handler touches no locks.
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
    \\usage: sismo datasource <id> [<id>...]
    \\
    \\  <id>: sched | cpu | heap | all-privileged
    \\
    \\  Connects to PERFETTO_PRODUCER_SOCK_NAME, registers the requested
    \\  data source(s) in this single process, blocks until SIGINT/SIGTERM.
    \\  Multiple ids in one invocation share the sudo prompt.
    \\
    \\  Identifiers are platform-independent — sismo picks the right
    \\  `sismo.*` data source name for the running OS internally.
    \\
;

const Kind = enum { sched, cpu, heap };

/// Platform-independent identifier → Kind. Returns null on unknown.
/// "all-privileged" is handled separately (it expands to N kinds, not 1).
fn parseKind(name: []const u8) ?Kind {
    if (std.mem.eql(u8, name, "sched")) return .sched;
    if (std.mem.eql(u8, name, "cpu")) return .cpu;
    if (std.mem.eql(u8, name, "heap")) return .heap;
    return null;
}

/// Per-platform expansion of `all-privileged`. macOS: all three need
/// elevation (kdebug for sched, task_for_pid for cpu + heap).
fn allPrivileged() []const Kind {
    return switch (builtin.os.tag) {
        .macos => &.{ .sched, .cpu, .heap },
        else => &.{}, // No Linux/Windows producers wired in this binary yet.
    };
}

pub fn runDatasource(init: std.process.Init) !void {
    var iter = init.minimal.args.iterate();
    _ = iter.next(); // exe path
    _ = iter.next(); // "datasource" subcommand token

    // Collect requested kinds, deduplicating. Eight slots is well above
    // any plausible request count (only three kinds exist today).
    var kinds_buf: [8]Kind = undefined;
    var n_kinds: usize = 0;

    const addKind = struct {
        fn f(buf: *[8]Kind, n: *usize, k: Kind) void {
            for (buf[0..n.*]) |existing| {
                if (existing == k) return; // already added
            }
            if (n.* >= buf.len) return;
            buf[n.*] = k;
            n.* += 1;
        }
    }.f;

    while (iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "all-privileged")) {
            for (allPrivileged()) |k| addKind(&kinds_buf, &n_kinds, k);
            continue;
        }
        const kind = parseKind(arg) orelse {
            std.debug.print("sismo datasource: unknown identifier '{s}'\n\n{s}", .{ arg, usage });
            return;
        };
        addKind(&kinds_buf, &n_kinds, kind);
    }

    if (n_kinds == 0) {
        std.debug.print("{s}", .{usage});
        return;
    }

    if (comptime builtin.os.tag == .macos) {
        return runDatasourceMacos(init, kinds_buf[0..n_kinds]);
    }
    std.debug.print(
        "sismo datasource: not yet implemented on {s}\n",
        .{@tagName(builtin.os.tag)},
    );
}

/// One slot per registered data source. Holds whichever Capture pointer
/// applies, freed at shutdown.
const Slot = struct {
    kind: Kind,
    sched: ?*macos_sched_capture.Capture = null,
    cpu: ?*macos_cpu_samples_capture.Capture = null,
    heap: ?*heap_capture.Capture = null,
};

fn runDatasourceMacos(init: std.process.Init, kinds: []const Kind) !void {
    // Connect to the producer socket via the public C++ SDK; each
    // Capture.init builds + registers its own DataSourceDescriptor.
    const paths = @import("sismo_paths.zig");
    c.sismo_init(paths.producer_sock.ptr);

    var slots_buf: [8]Slot = undefined;
    var n_slots: usize = 0;

    installStopHandlers();

    // Register each requested kind. A single registration failure bails
    // out and frees what's already set up — partial state is useless when
    // the user expected the full set.
    errdefer {
        var i: usize = n_slots;
        while (i > 0) {
            i -= 1;
            shutdownSlot(slots_buf[i]);
        }
    }

    for (kinds) |kind| {
        var slot: Slot = .{ .kind = kind };
        switch (kind) {
            .sched => {
                slot.sched = try macos_sched_capture.Capture.init(init.gpa, init.io, .{});
                std.debug.print("sismo datasource: sismo.macos_sched registered\n", .{});
            },
            .cpu => {
                slot.cpu = try macos_cpu_samples_capture.Capture.init(init.gpa, init.io, .{});
                std.debug.print("sismo datasource: sismo.macos_cpu_samples registered\n", .{});
            },
            .heap => {
                slot.heap = try heap_capture.Capture.init(init.gpa, init.io, .{});
                std.debug.print("sismo datasource: sismo.heap registered\n", .{});
            },
        }
        slots_buf[n_slots] = slot;
        n_slots += 1;
    }

    std.debug.print(
        "sismo datasource: {d} data source(s) registered; blocking until SIGINT/SIGTERM\n",
        .{n_slots},
    );
    blockUntilStopped();

    // Shutdown reverses registration order so each Capture sees its
    // workers torn down before its DS handle is freed.
    var i: usize = n_slots;
    while (i > 0) {
        i -= 1;
        shutdownSlot(slots_buf[i]);
    }
}

fn shutdownSlot(slot: Slot) void {
    switch (slot.kind) {
        .sched => if (slot.sched) |s| {
            const stats = s.shutdown();
            std.debug.print(
                "sismo datasource: sismo.macos_sched stopped — {d} events / {d} drains\n",
                .{ stats.events_emitted, stats.drain_calls },
            );
        },
        .cpu => if (slot.cpu) |s| {
            const stats = s.shutdown();
            std.debug.print(
                "sismo datasource: sismo.macos_cpu_samples stopped — {d} samples ({d} active)\n",
                .{ stats.samples, stats.active_samples },
            );
        },
        .heap => if (slot.heap) |s| {
            const stats = s.shutdown();
            std.debug.print(
                "sismo datasource: sismo.heap stopped — {d} records / ~{d} bytes / {d} sites\n",
                .{ stats.records, stats.bytes_alloc_estimated, stats.sites },
            );
        },
    }
}

fn blockUntilStopped() void {
    // Coarse poll. The signal handler can't safely touch a condvar / event
    // (no async-signal-safety guarantee), so the atomic is checked on a
    // short interval — 100 ms wakeup latency, fine for SIGTERM.
    const ts: std.c.timespec = .{ .sec = 0, .nsec = 100 * std.time.ns_per_ms };
    while (!g_should_stop.load(.acquire)) {
        _ = std.c.nanosleep(&ts, null);
    }
}
