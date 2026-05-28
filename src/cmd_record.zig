// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `sismo record` — the unified recorder subcommand.
//!
//! Hosts an in-process Perfetto tracing service (`ServiceIPCHost`) so
//! the workload (and any external SDK clients) can connect via
//! PERFETTO_PRODUCER_SOCK_NAME, then runs the three sismo producers —
//! macOS sched (kdebug), macOS CPU samples (Mach), heap consumer — as
//! muxer worker threads inside this same process.
//!
//! Muxer pattern (see e.g. `src/macos_sched_capture.zig` for the
//! per-DS state machine):
//!   1. We register each `sismo.*` data source with on_setup /
//!      on_start / on_stop / on_flush callbacks bound to a `*Capture`
//!      state owned by this process.
//!   2. We spawn each capture's worker thread BEFORE starting the
//!      session; the worker waits for `on_setup`, then does its own
//!      heavy setup (`task_for_pid`, image enumeration, framehop
//!      registration, heap attach) on its own thread.
//!   3. When the session starts, traced fires `on_start` on its IO
//!      thread → the trampoline flips the worker into RUNNING via a
//!      `std.Io.Event`. The IO thread returns immediately.
//!   4. On flush (heap snapshot) and on_stop (async stopper handle),
//!      the same pattern applies — trampoline updates an atomic +
//!      sets the wakeup event; worker drains/emits/acks.
//!   5. At process exit we signal EXIT and join.
//!
//! Output: a single Perfetto trace file with all four data sources
//! merged on one timeline (sample-target's `track_event` +
//! `sismo.macos_sched` + `sismo.macos_cpu_samples` + `sismo.heap`).
//!
//! Usage:
//!   sismo record [--output <path>] <command> [args...]
//!
//! Defaults: --output ./sismo.pftrace (in the current directory).
//! `<command>` is the workload binary to spawn + profile; everything
//! after it is passed to the workload as its argv. Recording runs
//! for as long as the workload runs — sismo waits for the spawned
//! process to exit, then stops the session. SIGINT (ctrl-C) cuts
//! the recording short and signals the workload to terminate.
//!
//! Requires sudo: macOS CPU samples + heap need `task_for_pid` (root
//! or `com.apple.security.cs.debugger`); macOS sched needs root for
//! `KERN_KDEBUG`.

const std = @import("std");
const builtin = @import("builtin");
const traced = @import("sismo_traced.zig");
const heap_protocol = @import("heap_protocol.zig");
const sismo_config = @import("sismo_config.zig");
const paths = @import("sismo_paths.zig");
const privileged_marker = @import("sismo_privileged_marker.zig");
const perf_counter_probe = @import("perf_counter_probe.zig");
const c = @cImport({
    @cInclude("src/c/perfetto_shim.h");
});

// macOS-only data sources. Linux needs perf_event-based equivalents,
// Windows needs ETW; both live in sibling modules once they're written.
// On non-macOS builds these resolve to `struct {}` and runRecord
// short-circuits before any reference to the missing types.
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

// Linux uses upstream Perfetto producers (traced_probes + traced_perf)
// embedded as in-process worker threads — same pattern as
// `sismo_traced` for the service. No Zig-side capture wrappers needed;
// the producers self-register their data sources when the consumer's
// TraceConfig requests them.
const linux_traced_probes = switch (builtin.os.tag) {
    .linux => @import("sismo_traced_probes.zig"),
    else => struct {},
};
const linux_traced_perf = switch (builtin.os.tag) {
    .linux => @import("sismo_traced_perf.zig"),
    else => struct {},
};

// `setenv` has no idiomatic Zig wrapper — env mutation goes through libc
// so it stays in sync with the libc-side environ that posix_spawnp
// inherits.
extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;

// `std.c.posix_spawnp` only exposes the Darwin variant in zig 0.16; on
// Linux it's a libc symbol not surfaced through std.c. Declare locally
// with `?*const anyopaque` for the file_actions / attrp pointers since
// we only ever pass null for both — the actual struct types differ
// per-OS but never get instantiated here.
extern "c" fn posix_spawnp(
    pid: *c_int,
    path: [*:0]const u8,
    file_actions: ?*const anyopaque,
    attrp: ?*const anyopaque,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
) c_int;

// `std.c.environ` exists on every libc target but is declared in
// std.c's per-OS section; redeclare locally so the access is uniform.
extern "c" var environ: [*:null]const ?[*:0]const u8;

const EVFILT_PROC: i16 = -5;
const EV_ADD: u16 = 0x0001;
const EV_ONESHOT: u16 = 0x0010;
const NOTE_EXIT: u32 = 0x80000000;

// Self-pipe for the "something happened, look up what" notification.
// All event sources (SIGINT handler, workload exit watcher, optional
// --duration timer) write a single byte; the main thread does ONE
// blocking `read` to find out what next. The byte payload
// distinguishes events:
//   'I' — SIGINT (user wants to stop)
//   'X' — workload exited
//   'T' — --duration deadline reached
// `write()` is async-signal-safe per POSIX; single-byte writes are
// atomic on a pipe (they're well under PIPE_BUF). Cross-platform
// (POSIX) — no kqueue / pidfd / signalfd needed.
//
// Mid-recording snapshots from `sismo snapshot` do NOT flow through
// here — that subcommand is its own consumer that connects directly
// to the in-process service, calls CloneTrace, and writes a file. The
// recorder is uninvolved.
var g_pipe_write_fd: c_int = -1;

fn handleSigint(sig: std.c.SIG) callconv(.c) void {
    _ = sig;
    if (g_pipe_write_fd >= 0) {
        const buf = [_]u8{'I'};
        _ = std.c.write(g_pipe_write_fd, &buf, 1);
    }
}

const ExitMode = enum { spawn, attach };

/// Per-data-source mode. Default is `in_process` (this binary hosts
/// the producer; needs sudo for kdebug / task_for_pid). `external`
/// means a sidecar `sudo sismo datasource <name>` is expected to
/// provide it. `off` skips the data source entirely.
pub const SourceMode = enum { in_process, external, off };

extern "c" fn geteuid() c_uint;

/// Walk a serialized `TracingServiceState` proto looking for
/// data_sources[*].ds_descriptor.name. Calls `cb` once per name found.
/// Returns true on clean parse, false on truncated/malformed input.
///
/// Schema (`protos/perfetto/common/tracing_service_state.proto`):
///   TracingServiceState.data_sources = field 2, repeated DataSource
///   DataSource.ds_descriptor         = field 1, DataSourceDescriptor
///   DataSourceDescriptor.name        = field 1, string
///
/// Inline parser instead of pulling in sismo_config.zig's primitives —
/// keeps this self-contained and the parser's tiny.
fn forEachRegisteredDataSource(
    bytes: []const u8,
    user: anytype,
    cb: *const fn (@TypeOf(user), name: []const u8) void,
) bool {
    var i: usize = 0;
    while (i < bytes.len) {
        const tag = readVarintAt(bytes, &i) orelse return false;
        const fnum = tag >> 3;
        const wt = tag & 0x07;
        if (fnum == 2 and wt == 2) {
            // DataSource sub-message.
            const len = readVarintAt(bytes, &i) orelse return false;
            const end = i + @as(usize, @intCast(len));
            if (end > bytes.len) return false;
            // Within DataSource, find ds_descriptor (field 1).
            var j = i;
            while (j < end) {
                const t2 = readVarintAt(bytes, &j) orelse return false;
                const fnum2 = t2 >> 3;
                const wt2 = t2 & 0x07;
                if (fnum2 == 1 and wt2 == 2) {
                    const len2 = readVarintAt(bytes, &j) orelse return false;
                    const desc_end = j + @as(usize, @intCast(len2));
                    if (desc_end > end) return false;
                    // Within DataSourceDescriptor, find name (field 1).
                    var k = j;
                    while (k < desc_end) {
                        const t3 = readVarintAt(bytes, &k) orelse return false;
                        const fnum3 = t3 >> 3;
                        const wt3 = t3 & 0x07;
                        if (fnum3 == 1 and wt3 == 2) {
                            const len3 = readVarintAt(bytes, &k) orelse return false;
                            const name_end = k + @as(usize, @intCast(len3));
                            if (name_end > desc_end) return false;
                            cb(user, bytes[k..name_end]);
                            k = name_end;
                        } else if (!skipFieldAt(bytes, &k, wt3, desc_end)) {
                            return false;
                        }
                    }
                    j = desc_end;
                } else if (!skipFieldAt(bytes, &j, wt2, end)) {
                    return false;
                }
            }
            i = end;
        } else if (!skipFieldAt(bytes, &i, wt, bytes.len)) {
            return false;
        }
    }
    return true;
}

fn readVarintAt(bytes: []const u8, i: *usize) ?u64 {
    var value: u64 = 0;
    var shift: u6 = 0;
    while (i.* < bytes.len) {
        const b = bytes[i.*];
        i.* += 1;
        value |= @as(u64, b & 0x7f) << shift;
        if (b & 0x80 == 0) return value;
        shift +%= 7;
        if (shift >= 64) return null;
    }
    return null;
}

fn skipFieldAt(bytes: []const u8, i: *usize, wire_type: u64, hard_end: usize) bool {
    switch (wire_type) {
        0 => _ = readVarintAt(bytes, i) orelse return false,
        1 => {
            if (i.* + 8 > hard_end) return false;
            i.* += 8;
        },
        2 => {
            const len = readVarintAt(bytes, i) orelse return false;
            const end = i.* + @as(usize, @intCast(len));
            if (end > hard_end) return false;
            i.* = end;
        },
        5 => {
            if (i.* + 4 > hard_end) return false;
            i.* += 4;
        },
        else => return false,
    }
    return true;
}

/// Poll QueryServiceState until every name in `expected` is registered,
/// or `timeout_ms` elapses. Returns true if all appeared, false on
/// timeout. Polls every 100 ms — the registration round-trip is
/// dominated by IPC latency, sub-100ms typically.
fn waitForExternalDataSources(
    session: *c.struct_SismoConsumerSession,
    expected: []const []const u8,
    timeout_ms: u64,
) bool {
    if (expected.len == 0) return true;

    var buf: [16 * 1024]u8 = undefined;
    var elapsed_ms: u64 = 0;
    const poll_ms: u64 = 100;

    while (true) {
        var written: usize = 0;
        const rc = c.sismo_consumer_query_service_state(session, &buf, buf.len, &written);
        if (rc == 0) {
            const Ctx = struct {
                expected: []const []const u8,
                seen: []bool,
            };
            var seen_buf: [8]bool = .{false} ** 8;
            const seen = seen_buf[0..expected.len];
            var ctx: Ctx = .{ .expected = expected, .seen = seen };
            _ = forEachRegisteredDataSource(buf[0..written], &ctx, struct {
                fn cb(c_ctx: *Ctx, name: []const u8) void {
                    for (c_ctx.expected, 0..) |want, idx| {
                        if (std.mem.eql(u8, want, name)) c_ctx.seen[idx] = true;
                    }
                }
            }.cb);

            var all = true;
            for (seen) |s| if (!s) { all = false; break; };
            if (all) return true;
        }
        // rc != 0 (RPC fail / buffer too small) → just retry; transient
        // errors during connect are normal at startup.

        if (elapsed_ms >= timeout_ms) return false;
        const ts: std.c.timespec = .{
            .sec = 0,
            .nsec = @intCast(poll_ms * std.time.ns_per_ms),
        };
        _ = std.c.nanosleep(&ts, null);
        elapsed_ms += poll_ms;
    }
}

const WaitCtx = struct {
    pid: c_int,
    write_fd: c_int,
    mode: ExitMode,
};

fn exitWatchThread(ctx: *const WaitCtx) void {
    switch (ctx.mode) {
        .spawn => waitpidExitWatch(ctx),
        .attach => attach_watcher.watch(ctx),
    }
}

// macOS uses kqueue NOTE_EXIT to watch a non-child pid for exit.
// Linux would need pidfd_open + poll (or a busy-poll on /proc/<pid>);
// not wired today because runRecordLinux rejects --pid before reaching
// here. Comptime-selected so kqueue references never reach the
// semantic analyzer on Linux.
const attach_watcher = if (builtin.os.tag == .macos) struct {
    pub const watch = kqueueExitWatch;
} else struct {
    pub fn watch(_: *const WaitCtx) void {
        @panic("attach mode not supported on this platform");
    }
};

// Spawn-mode exit watcher: blocks on waitpid for the child we own.
fn waitpidExitWatch(ctx: *const WaitCtx) void {
    _ = std.c.waitpid(ctx.pid, null, 0);
    const buf = [_]u8{'X'};
    _ = std.c.write(ctx.write_fd, &buf, 1);
}

const DurationCtx = struct {
    seconds: c_uint,
    write_fd: c_int,
};

// Sleeps for `seconds` then fires 'T' on the self-pipe. nanosleep
// returns -1 + EINTR on signal delivery (with rmtp filled in to the
// remainder); loop until the full duration has elapsed so a stray
// signal doesn't end recording early.
fn durationTimerThread(ctx: *const DurationCtx) void {
    var remaining: std.c.timespec = .{ .sec = @intCast(ctx.seconds), .nsec = 0 };
    while (remaining.sec > 0 or remaining.nsec > 0) {
        var rem: std.c.timespec = undefined;
        if (std.c.nanosleep(&remaining, &rem) == 0) break;
        remaining = rem;
    }
    const buf = [_]u8{'T'};
    _ = std.c.write(ctx.write_fd, &buf, 1);
}

// Attach-mode exit watcher: register a kqueue NOTE_EXIT filter on the
// pid (which is not our child, so waitpid would EINTR or return ECHILD).
// EVFILT_PROC + NOTE_EXIT works for any pid we have permission to see.
// On macOS this is the canonical way to watch a non-child for exit.
fn kqueueExitWatch(ctx: *const WaitCtx) void {
    const kq = std.c.kqueue();
    if (kq < 0) {
        // Without a kqueue we can't watch — main loop will only stop on
        // SIGINT or --duration. Silent return; SIGINT still works.
        return;
    }
    defer _ = std.c.close(kq);

    var changes = [_]std.c.Kevent{.{
        .ident = @intCast(ctx.pid),
        .filter = EVFILT_PROC,
        .flags = EV_ADD | EV_ONESHOT,
        .fflags = NOTE_EXIT,
        .data = 0,
        .udata = 0,
    }};
    var events: [1]std.c.Kevent = undefined;

    // Register the filter. If the pid is already gone, kevent returns
    // -1 with ESRCH; treat that as "already exited" and fire 'X'.
    // std.c.kevent's changelist/eventlist params are non-null many-item
    // pointers — pass `&events` for the unused slot since nchanges/
    // nevents=0 means the kernel won't read from it.
    if (std.c.kevent(kq, &changes, 1, &events, 0, null) < 0) {
        const buf = [_]u8{'X'};
        _ = std.c.write(ctx.write_fd, &buf, 1);
        return;
    }

    // Block until NOTE_EXIT fires.
    _ = std.c.kevent(kq, &changes, 0, &events, 1, null);
    const buf = [_]u8{'X'};
    _ = std.c.write(ctx.write_fd, &buf, 1);
}

const SpawnedChild = struct {
    name: []const u8,
    pid: c_int,
};

/// Parse a buffer-size argument like "256MB" / "1GB" / "512KB" into KB
/// (build_config takes uint32_t buffer_size_kb). Suffix is required —
/// bare integers are rejected to avoid ambiguity (bytes vs. KB?).
fn parseBufferKb(s: []const u8) ?u32 {
    if (s.len < 3) return null;
    const last2 = s[s.len - 2 ..];
    var num_part: []const u8 = undefined;
    var multiplier_kb: u64 = 0;
    if (std.ascii.eqlIgnoreCase(last2, "kb")) {
        num_part = s[0 .. s.len - 2];
        multiplier_kb = 1;
    } else if (std.ascii.eqlIgnoreCase(last2, "mb")) {
        num_part = s[0 .. s.len - 2];
        multiplier_kb = 1024;
    } else if (std.ascii.eqlIgnoreCase(last2, "gb")) {
        num_part = s[0 .. s.len - 2];
        multiplier_kb = 1024 * 1024;
    } else {
        return null;
    }
    const n = std.fmt.parseInt(u64, num_part, 10) catch return null;
    const total = n * multiplier_kb;
    if (total == 0 or total > std.math.maxInt(u32)) return null;
    return @intCast(total);
}

/// Parse a duration argument. Accepts a bare integer (interpreted as
/// seconds) or an integer with a single-letter suffix: 's', 'm', 'h'.
/// Returns total seconds clamped to u32 (libc `sleep` takes c_uint).
fn parseDurationSeconds(s: []const u8) ?c_uint {
    if (s.len == 0) return null;
    var num_part = s;
    var multiplier: u64 = 1;
    const last = s[s.len - 1];
    switch (last) {
        's' => {
            num_part = s[0 .. s.len - 1];
            multiplier = 1;
        },
        'm' => {
            num_part = s[0 .. s.len - 1];
            multiplier = 60;
        },
        'h' => {
            num_part = s[0 .. s.len - 1];
            multiplier = 3600;
        },
        '0'...'9' => {},
        else => return null,
    }
    const n = std.fmt.parseInt(u64, num_part, 10) catch return null;
    const total = n * multiplier;
    if (total == 0 or total > std.math.maxInt(c_uint)) return null;
    return @intCast(total);
}

fn maybeSpawn(
    gpa: std.mem.Allocator,
    path: []const u8,
    args: []const []const u8,
    env_kv: []const []const u8,
) ?SpawnedChild {
    return maybeSpawnInner(gpa, path, args, env_kv) catch |err| {
        std.debug.print("sismo record: spawn({s}) failed: {s}\n", .{ path, @errorName(err) });
        return null;
    };
}

fn maybeSpawnInner(
    gpa: std.mem.Allocator,
    path: []const u8,
    args: []const []const u8,
    env_kv: []const []const u8,
) !?SpawnedChild {
    var argv = try gpa.alloc(?[*:0]const u8, args.len + 2);
    defer gpa.free(argv);
    const path_z = try gpa.dupeZ(u8, path);
    defer gpa.free(path_z);
    argv[0] = path_z.ptr;

    var arg_dups = try gpa.alloc([:0]u8, args.len);
    defer {
        for (arg_dups) |s| gpa.free(s);
        gpa.free(arg_dups);
    }
    for (args, 0..) |a, i| {
        arg_dups[i] = try gpa.dupeZ(u8, a);
        argv[i + 1] = arg_dups[i].ptr;
    }
    argv[args.len + 1] = null;

    var i: usize = 0;
    while (i + 1 < env_kv.len) : (i += 2) {
        const k_z = try gpa.dupeZ(u8, env_kv[i]);
        defer gpa.free(k_z);
        const v_z = try gpa.dupeZ(u8, env_kv[i + 1]);
        defer gpa.free(v_z);
        _ = setenv(k_z.ptr, v_z.ptr, 1);
    }

    var pid: c_int = 0;
    const rc = posix_spawnp(
        &pid,
        path_z.ptr,
        null,
        null,
        @ptrCast(argv.ptr),
        environ,
    );
    if (rc != 0) {
        std.debug.print("sismo record: posix_spawnp({s}) rc={d}\n", .{ path, rc });
        return null;
    }
    return .{ .name = path, .pid = pid };
}

/// Per-platform capability table. Keep this small — flags should map
/// to a single capability bit. The parser uses these as comptime gates;
/// flags that don't make sense on the current OS are rejected at parse
/// time with a clear message.
///
/// Heap on Linux: not yet wired (master plan §heap). Sched/cpu on
/// Linux ride upstream traced_probes / traced_perf in-process.
/// `--pid` attach: macOS-only today (Linux would need pidfd-based exit
/// watching, not yet implemented).
const PlatformCaps = struct {
    const supports_pid_attach = builtin.os.tag == .macos;
    const supports_sched = builtin.os.tag == .macos or builtin.os.tag == .linux;
    const supports_cpu = builtin.os.tag == .macos or builtin.os.tag == .linux;
    const supports_heap = builtin.os.tag == .macos;
};

/// Fully-parsed command-line arguments for `sismo record`. Platform-
/// independent shape — fields a given OS doesn't honor stay at their
/// default (e.g. `attach_pid` is always null on Linux because the
/// parser rejects `--pid` there).
pub const RecordArgs = struct {
    output_path: []const u8 = "./sismo.pftrace",
    attach_pid: ?c_int = null,
    duration_secs: ?c_uint = null,
    flight_recorder: bool = false,
    buffer_kb: u32 = 128 * 1024,
    buffer_set: bool = false,
    sched_mode: SourceMode = .in_process,
    cpu_mode: SourceMode = .in_process,
    heap_mode: SourceMode = .in_process,
    no_instrumentation: bool = false,
    // PMU hardware counters (IPC + stall breakdown) on the perf sampler.
    // On by default like the other sources; --no-counters opts out. Recording
    // degrades to timebase-only sampling when the hardware lacks the counters.
    counters: bool = true,
    workload_argv: std.ArrayList([]const u8) = .empty,

    pub fn deinit(self: *RecordArgs, gpa: std.mem.Allocator) void {
        self.workload_argv.deinit(gpa);
    }
};

/// Print the platform-appropriate help text. Only flags valid on this
/// OS appear, and the synopsis line reflects which positional forms
/// are accepted (e.g. `--pid` only listed on macOS).
fn printRecordHelp() void {
    const pid_synopsis = if (comptime PlatformCaps.supports_pid_attach)
        "(--pid <pid> | <command> [args...])"
    else
        "<command> [args...]";

    var buf: [2048]u8 = undefined;
    var w: usize = 0;
    const writeStr = struct {
        fn f(b: []u8, idx: *usize, s: []const u8) void {
            const n = @min(s.len, b.len - idx.*);
            @memcpy(b[idx.* .. idx.* + n], s[0..n]);
            idx.* += n;
        }
    }.f;

    writeStr(&buf, &w,
        "usage: sismo record [--output <path>] [--duration <dur>]\n" ++
        "                    [--flight-recorder [--buffer <size>]]\n" ++
        "                    [--no-instrumentation]\n",
    );
    if (comptime PlatformCaps.supports_sched) {
        writeStr(&buf, &w, "                    [--no-sched | --external-sched]\n");
    }
    if (comptime PlatformCaps.supports_cpu) {
        writeStr(&buf, &w, "                    [--no-cpu | --external-cpu]\n");
        writeStr(&buf, &w, "                    [--no-counters]\n");
    }
    if (comptime PlatformCaps.supports_heap) {
        writeStr(&buf, &w, "                    [--no-heap | --external-heap]\n");
    }
    if (comptime PlatformCaps.supports_sched or PlatformCaps.supports_cpu or PlatformCaps.supports_heap) {
        writeStr(&buf, &w, "                    [--all-external]\n");
    }
    writeStr(&buf, &w, "                    ");
    writeStr(&buf, &w, pid_synopsis);
    writeStr(&buf, &w,
        "\n\n" ++
        "  --no-X         disable data source X entirely.\n" ++
        "  --external-X   data source X comes from a sidecar\n" ++
        "                 `sudo sismo datasource X` (no sudo on this process).\n" ++
        "  --all-external shorthand for --external for every privileged source.\n" ++
        "  --no-counters  don't attach PMU hardware counters (IPC, frontend/\n" ++
        "                 backend stalls, cache/branch misses) to CPU samples.\n" ++
        "                 Counters are on by default and degrade to plain\n" ++
        "                 sampling when the hardware can't provide them.\n",
    );
    if (comptime builtin.os.tag == .linux) {
        writeStr(&buf, &w,
            "\nLinux requires CAP_PERFMON for perf_event_open and read access\n" ++
            "to /sys/kernel/tracing for ftrace; running with sudo is the\n" ++
            "easiest path.\n",
        );
    }
    std.debug.print("{s}", .{buf[0..w]});
}

/// Parse `sismo record`'s arguments into a platform-independent
/// RecordArgs struct. Rejects flags whose underlying capability isn't
/// available on the running OS (per `PlatformCaps`). Returns null on
/// any user-visible error (already printed to stderr) or on `--help`;
/// caller treats null as "stop, don't run". On success the caller
/// owns the workload_argv and must call `args.deinit(gpa)`.
fn parseRecordArgs(
    gpa: std.mem.Allocator,
    iter: *std.process.Args.Iterator,
) ?RecordArgs {
    var args: RecordArgs = .{};
    // Cleanup-on-failure: errdefer doesn't fire for `?T` returning
    // null, only for `!T` errors. We have many `return null` paths
    // (each user-input error), so a flag-flipped defer is the
    // cleanest way to free workload_argv if any of them takes us out.
    var ok = false;
    defer if (!ok) args.deinit(gpa);

    const setSourceMode = struct {
        fn f(slot: *SourceMode, slot_name: []const u8, flag_name: []const u8, want: SourceMode) bool {
            if (slot.* != .in_process and slot.* != want) {
                std.debug.print(
                    "sismo record: conflicting flags for '{s}' ({s} vs already-set {s})\n",
                    .{ slot_name, flag_name, @tagName(slot.*) },
                );
                return false;
            }
            slot.* = want;
            return true;
        }
    }.f;

    while (iter.next()) |arg| {
        // Once we see the first positional, every subsequent token is
        // workload argv (so a workload can have its own --flags).
        if (args.workload_argv.items.len > 0 or !std.mem.startsWith(u8, arg, "--")) {
            args.workload_argv.append(gpa, arg) catch return null;
            continue;
        }

        if (std.mem.eql(u8, arg, "--output")) {
            args.output_path = iter.next() orelse {
                std.debug.print("sismo record: --output needs a value\n", .{});
                return null;
            };
        } else if (std.mem.eql(u8, arg, "--flight-recorder")) {
            args.flight_recorder = true;
        } else if (std.mem.eql(u8, arg, "--buffer")) {
            const v = iter.next() orelse {
                std.debug.print("sismo record: --buffer needs a value (e.g. 256MB)\n", .{});
                return null;
            };
            args.buffer_kb = parseBufferKb(v) orelse {
                std.debug.print(
                    "sismo record: invalid --buffer '{s}' (use 256MB / 1GB / 512KB)\n",
                    .{v},
                );
                return null;
            };
            args.buffer_set = true;
        } else if (std.mem.eql(u8, arg, "--pid")) {
            if (comptime !PlatformCaps.supports_pid_attach) {
                std.debug.print(
                    "sismo record: --pid attach is not supported on {s}\n",
                    .{@tagName(builtin.os.tag)},
                );
                return null;
            }
            const v = iter.next() orelse {
                std.debug.print("sismo record: --pid needs a value\n", .{});
                return null;
            };
            args.attach_pid = std.fmt.parseInt(c_int, v, 10) catch {
                std.debug.print("sismo record: --pid '{s}' is not a number\n", .{v});
                return null;
            };
        } else if (std.mem.eql(u8, arg, "--duration")) {
            const v = iter.next() orelse {
                std.debug.print("sismo record: --duration needs a value (e.g. 30s, 5m, 1h)\n", .{});
                return null;
            };
            args.duration_secs = parseDurationSeconds(v) orelse {
                std.debug.print(
                    "sismo record: invalid --duration '{s}' (use 30s, 5m, 1h or a positive integer of seconds)\n",
                    .{v},
                );
                return null;
            };
        } else if (std.mem.eql(u8, arg, "--no-sched")) {
            if (comptime !PlatformCaps.supports_sched) return rejectUnsupported("--no-sched", "sched");
            if (!setSourceMode(&args.sched_mode, "sched", "--no-sched", .off)) return null;
        } else if (std.mem.eql(u8, arg, "--no-cpu")) {
            if (comptime !PlatformCaps.supports_cpu) return rejectUnsupported("--no-cpu", "cpu");
            if (!setSourceMode(&args.cpu_mode, "cpu", "--no-cpu", .off)) return null;
        } else if (std.mem.eql(u8, arg, "--no-heap")) {
            if (comptime !PlatformCaps.supports_heap) return rejectUnsupported("--no-heap", "heap");
            if (!setSourceMode(&args.heap_mode, "heap", "--no-heap", .off)) return null;
        } else if (std.mem.eql(u8, arg, "--external-sched")) {
            if (comptime !PlatformCaps.supports_sched) return rejectUnsupported("--external-sched", "sched");
            if (!setSourceMode(&args.sched_mode, "sched", "--external-sched", .external)) return null;
        } else if (std.mem.eql(u8, arg, "--external-cpu")) {
            if (comptime !PlatformCaps.supports_cpu) return rejectUnsupported("--external-cpu", "cpu");
            if (!setSourceMode(&args.cpu_mode, "cpu", "--external-cpu", .external)) return null;
        } else if (std.mem.eql(u8, arg, "--external-heap")) {
            if (comptime !PlatformCaps.supports_heap) return rejectUnsupported("--external-heap", "heap");
            if (!setSourceMode(&args.heap_mode, "heap", "--external-heap", .external)) return null;
        } else if (std.mem.eql(u8, arg, "--all-external")) {
            // Only flips sources whose capability is supported AND
            // which are still in the default in_process state.
            if (comptime PlatformCaps.supports_sched) {
                if (args.sched_mode == .in_process) args.sched_mode = .external;
            }
            if (comptime PlatformCaps.supports_cpu) {
                if (args.cpu_mode == .in_process) args.cpu_mode = .external;
            }
            if (comptime PlatformCaps.supports_heap) {
                if (args.heap_mode == .in_process) args.heap_mode = .external;
            }
        } else if (std.mem.eql(u8, arg, "--no-instrumentation")) {
            args.no_instrumentation = true;
        } else if (std.mem.eql(u8, arg, "--no-counters")) {
            if (comptime !PlatformCaps.supports_cpu) return rejectUnsupported("--no-counters", "cpu");
            args.counters = false;
        } else if (std.mem.eql(u8, arg, "--help")) {
            printRecordHelp();
            return null; // defer handles cleanup
        } else {
            std.debug.print("sismo record: unknown flag '{s}'\n", .{arg});
            return null;
        }
    }

    // Cross-cutting validation: exactly one workload-acquisition mode.
    const have_pid = args.attach_pid != null;
    const have_cmd = args.workload_argv.items.len > 0;
    if (have_pid and have_cmd) {
        std.debug.print("sismo record: --pid and <command> are mutually exclusive\n", .{});
        return null;
    }
    if (!have_pid and !have_cmd) {
        std.debug.print(
            "sismo record: need {s}\n",
            .{if (comptime PlatformCaps.supports_pid_attach) "either --pid <pid> or a workload <command>" else "a workload <command>"},
        );
        return null;
    }

    // FILE mode default buffer (128 MB) was already on the struct.
    // Flight-recorder bumps to 256 MB unless the user set --buffer
    // explicitly. Apply here so platform runners don't repeat the rule.
    if (args.flight_recorder and !args.buffer_set) args.buffer_kb = 256 * 1024;

    ok = true;
    return args;
}

/// Helper for the parser's "this flag refers to a data source not
/// wired on this platform" error path. Returning null bubbles up from
/// the parser correctly.
fn rejectUnsupported(flag_name: []const u8, ds_name: []const u8) ?RecordArgs {
    std.debug.print(
        "sismo record: {s} is not supported on {s} (data source '{s}' is not wired on this platform yet)\n",
        .{ flag_name, @tagName(builtin.os.tag), ds_name },
    );
    return null;
}

/// Entry point for the `record` subcommand. Dispatched from `sismo.zig`.
/// Parses arguments once into a platform-independent RecordArgs and
/// hands them to the per-platform runner.
pub fn runRecord(init: std.process.Init) !void {
    var iter = init.minimal.args.iterate();
    _ = iter.next(); // exe path
    _ = iter.next(); // "record" subcommand token

    var args = parseRecordArgs(init.gpa, &iter) orelse return;
    defer args.deinit(init.gpa);

    if (comptime builtin.os.tag == .macos) return runRecordMacos(init, &args);
    if (comptime builtin.os.tag == .linux) return runRecordLinux(init, &args);

    std.debug.print(
        "sismo record: not yet implemented on {s}\n",
        .{@tagName(builtin.os.tag)},
    );
}

fn runRecordMacos(init: std.process.Init, args: *RecordArgs) !void {
    const gpa = init.gpa;
    const io = init.io;

    // Read fields off `args` into shorter local names; the per-platform
    // path uses these heavily and keeping the prefix everywhere is noisy.
    const output_path = args.output_path;
    const attach_pid = args.attach_pid;
    const duration_secs = args.duration_secs;
    const flight_recorder = args.flight_recorder;
    const buffer_kb = args.buffer_kb;
    const sched_mode = args.sched_mode;
    const cpu_mode = args.cpu_mode;
    const heap_mode = args.heap_mode;
    const no_instrumentation = args.no_instrumentation;
    const workload_argv = &args.workload_argv;

    if (attach_pid) |pid| {
        // Quick sanity check before tearing into setup. kill(pid, 0)
        // returns 0 if we have permission to signal pid (i.e. it
        // exists), -1 + ESRCH/EPERM otherwise. We don't distinguish —
        // either way the user gave us a pid we can't use.
        if (std.c.kill(pid, @enumFromInt(0)) != 0) {
            std.debug.print("sismo record: pid {d} not found (or not signalable)\n", .{pid});
            return;
        }
    }

    // Privilege check: every privileged data source still in the
    // in_process state needs root. Warn early so the user can ctrl-C
    // and re-launch with sudo (or pass --external-X / --no-X) before
    // we tear into spawning workloads, sockets, etc.
    if (geteuid() != 0) {
        var unmet_buf: [3][]const u8 = undefined;
        var n_unmet: usize = 0;
        if (sched_mode == .in_process) { unmet_buf[n_unmet] = "sched"; n_unmet += 1; }
        if (cpu_mode == .in_process)   { unmet_buf[n_unmet] = "cpu";   n_unmet += 1; }
        if (heap_mode == .in_process)  { unmet_buf[n_unmet] = "heap";  n_unmet += 1; }
        if (n_unmet > 0) {
            std.debug.print(
                "sismo record: WARNING — running unprivileged. The following data\n" ++
                "  sources need root and will fail to capture:\n",
                .{},
            );
            for (unmet_buf[0..n_unmet]) |name| {
                std.debug.print("    {s}\n", .{name});
            }
            std.debug.print(
                "  options:\n" ++
                "    1. re-run with `sudo`     (simple — everything in one process as root)\n" ++
                "    2. pass --external-{{X}}    + run `sudo sismo datasource X` in another\n" ++
                "                                  shell (or --all-external + `sudo sismo\n" ++
                "                                  datasource all-privileged`)\n" ++
                "    3. pass --no-{{X}}          to skip the data source silently\n",
                .{},
            );
        }
    }

    // Single-session lock. Two `sismo record` invocations would race on
    // unlink+bind of the well-known socket and corrupt each other's
    // sessions; flock detects that cleanly. The fd stays open for the
    // lifetime of the recording — the OS releases the lock at exit.
    // The lock file's contents are our pid as ASCII, so `sismo
    // snapshot` can find us.
    const lock_fd = paths.acquireSessionLock(std.c.getpid()) catch |err| switch (err) {
        error.AlreadyHeld => {
            std.debug.print(
                "sismo record: another sismo session is already running (lock held on {s})\n",
                .{paths.session_lock_path},
            );
            return;
        },
        error.OpenFailed => {
            std.debug.print(
                "sismo record: failed to open session lock at {s}\n",
                .{paths.session_lock_path},
            );
            return;
        },
    };
    defer paths.releaseSessionLock(lock_fd);

    const my_pid = std.c.getpid();
    const prod_sock = paths.producer_sock;
    const cons_sock = paths.consumer_sock;

    std.debug.print(
        "sismo record: pid={d} output={s}\n  producer sock: {s}\n  consumer sock: {s}\n",
        .{ my_pid, output_path, prod_sock, cons_sock },
    );

    _ = setenv("PERFETTO_PRODUCER_SOCK_NAME", prod_sock.ptr, 1);
    _ = setenv("PERFETTO_CONSUMER_SOCK_NAME", cons_sock.ptr, 1);

    // 1. Embed traced (the IPC service host) on a worker thread.
    const svc = try traced.create(prod_sock, cons_sock);
    defer traced.destroy(svc);

    // 2. Init our own producer connection. New shim path: connects to
    //    the in-process traced via PERFETTO_PRODUCER_SOCK_NAME, which
    //    we set above to `prod_sock`.
    c.sismo_init(prod_sock.ptr);

    // 3. All three captures (sched, cpu, heap) self-register via the
    //    new shim inside their Capture.init — no separate ds_alloc.

    // 4. Acquire the workload — either spawn it (carrying
    //    DYLD_INSERT_LIBRARIES so the target loads the heap preload's
    //    dormant client) or attach to an already-running pid the user
    //    presumably launched with `sismo prepare`.
    const target: SpawnedChild = blk: {
        if (attach_pid) |pid| {
            std.debug.print("sismo record: attaching to pid={d}\n", .{pid});
            break :blk .{ .name = "(attached)", .pid = pid };
        }

        const heap_dylib = paths.heapDylibPath(io, gpa) catch |err| {
            std.debug.print("sismo record: failed to resolve heap dylib path: {s}\n", .{@errorName(err)});
            return;
        };
        defer gpa.free(heap_dylib);
        const workload_cmd = workload_argv.items[0];
        const workload_args = workload_argv.items[1..];

        const t = maybeSpawn(gpa, workload_cmd, workload_args, &.{
            "PERFETTO_PRODUCER_SOCK_NAME", prod_sock,
            "DYLD_INSERT_LIBRARIES",       heap_dylib,
        }) orelse {
            std.debug.print("sismo record: failed to spawn '{s}' — exiting\n", .{workload_cmd});
            return;
        };
        std.debug.print("sismo record: spawned '{s}' pid={d}\n", .{ workload_cmd, t.pid });
        // Give the target a beat to come up + create its heap socket
        // before any worker tries to attach.
        const settle_ts: std.c.timespec = .{ .sec = 0, .nsec = 200 * std.time.ns_per_ms };
        _ = std.c.nanosleep(&settle_ts, null);
        break :blk t;
    };

    // 5. Spawn capture workers. Each spins up its worker thread, which
    //    *waits for on_setup* before doing any heavy work (task_for_pid,
    //    image enumeration, framehop, heap attach). on_setup arrives
    //    when the consumer session starts up — that's where target_pid
    //    flows in, via SismoXxxConfig embedded at field 2000 of each
    //    DataSourceConfig.
    const sched = blk: {
        if (sched_mode != .in_process) break :blk null;
        break :blk macos_sched_capture.Capture.init(gpa, io, .{}) catch |err| {
            std.debug.print("sismo record: macos_sched_capture.init failed: {s}\n", .{@errorName(err)});
            break :blk null;
        };
    };
    const cpu = blk: {
        if (cpu_mode != .in_process) break :blk null;
        break :blk macos_cpu_samples_capture.Capture.init(gpa, io, .{}) catch |err| {
            std.debug.print("sismo record: macos_cpu_samples_capture.init failed: {s}\n", .{@errorName(err)});
            break :blk null;
        };
    };
    const heap = blk: {
        if (heap_mode != .in_process) break :blk null;
        // In attach mode, heap requires the target was launched via
        // `sismo prepare` (DYLD_INSERT_LIBRARIES'd the dormant client,
        // which binds /tmp/sismo-heap-{pid}.sock from its listener
        // thread). If the per-pid socket is missing, skip heap with a
        // clear log line — the user gets sched + cpu_samples, just no
        // heap.
        if (attach_pid) |pid| {
            var sock_buf: [128]u8 = undefined;
            const sock_path = heap_protocol.socketPath(@intCast(pid), &sock_buf) catch unreachable;
            if (std.c.access(sock_path.ptr, std.c.F_OK) != 0) {
                std.debug.print(
                    "sismo record: target pid={d} not prepared (no heap socket at {s}); heap disabled — relaunch via `sismo prepare` to enable heap\n",
                    .{ pid, sock_path },
                );
                break :blk null;
            }
        }
        break :blk heap_capture.Capture.init(gpa, io, .{}) catch |err| {
            std.debug.print("sismo record: heap_capture.init failed: {s}\n", .{@errorName(err)});
            break :blk null;
        };
    };

    // 6. All captures (sched + cpu + heap) registered themselves via
    //    the new shim path inside their Capture.init.

    // 7. Build the per-DS sismo configs (field 2000 of each
    //    DataSourceConfig), then build the TraceConfig + create + start
    //    the consumer session.
    const cpu_cfg = try sismo_config.macos_cpu_samples.encode(gpa, .{
        .target_pid = @intCast(target.pid),
    });
    defer gpa.free(cpu_cfg);
    const heap_cfg = try sismo_config.heap.encode(gpa, .{
        .target_pid = @intCast(target.pid),
    });
    defer gpa.free(heap_cfg);
    const sched_cfg = try sismo_config.macos_sched.encode(gpa, .{});
    defer gpa.free(sched_cfg);

    // Build the entries array dynamically from the per-source modes.
    // `track_event` (the user's instrumentation surface) is gated by
    // --no-instrumentation. Each privileged data source enters the
    // TraceConfig if its mode is != .off — both in_process and external
    // modes need the name registered in the consumer's config; only
    // in_process gates the local Capture init above.
    //
    // For external entries we also collect the on-the-wire data source
    // names so we can poll for their producer registration before
    // calling StartBlocking (otherwise the session would start without
    // the external producer ever connecting).
    const perfetto_proto = @import("perfetto_proto.zig");
    var entries_buf: [4]perfetto_proto.DataSourceEntry = undefined;
    var n_entries: usize = 0;
    var external_names_buf: [3][]const u8 = undefined;
    var n_external: usize = 0;
    if (!no_instrumentation) {
        entries_buf[n_entries] = .{ .track_event = .{ .enabled_categories = &.{"*"} } };
        n_entries += 1;
    }
    // Heap: in-process when `heap` capture exists; external when caller
    // asked for it AND heap_mode says external (the in-process branch
    // may have failed on attach-without-prepare, in which case the
    // capture is null but mode is still in_process — don't promote
    // those to external silently).
    if (heap != null or heap_mode == .external) {
        entries_buf[n_entries] = .{ .sismo_vendor = .{ .name = "sismo.heap", .sismo_config = heap_cfg } };
        n_entries += 1;
        if (heap_mode == .external) {
            external_names_buf[n_external] = "sismo.heap";
            n_external += 1;
        }
    }
    if (cpu != null or cpu_mode == .external) {
        entries_buf[n_entries] = .{ .sismo_vendor = .{ .name = "sismo.macos_cpu_samples", .sismo_config = cpu_cfg } };
        n_entries += 1;
        if (cpu_mode == .external) {
            external_names_buf[n_external] = "sismo.macos_cpu_samples";
            n_external += 1;
        }
    }
    if (sched != null or sched_mode == .external) {
        // ProtoVM is enabled for sched so that `GenericKernelProcessTree`
        // packets evicted from the ring in flight-recorder mode get
        // mirrored into a maintained DST and surfaced at trace-read
        // time. The DST consumes ~450 B per Process or Thread node
        // (allocator bookkeeping + per-field sub-nodes + cmdline
        // bytes — measured against the C++ Vm with synthetic
        // patches): ~5000 entries fit in 4 MB, comfortably above what
        // a busy macOS system surfaces (~200 procs × ~5 threads/proc).
        // Below ~512 KB, ApplyPatch starts aborting with allocator
        // exhaustion mid-merge.
        entries_buf[n_entries] = .{ .sismo_vendor = .{
            .name = "sismo.macos_sched",
            .sismo_config = sched_cfg,
            .protovm_memory_limit_kb = 4 * 1024,
        } };
        n_entries += 1;
        if (sched_mode == .external) {
            external_names_buf[n_external] = "sismo.macos_sched";
            n_external += 1;
        }
    }
    if (n_entries == 0) {
        std.debug.print(
            "sismo record: no data sources enabled — recording would be empty. Drop one of the --no-* flags.\n",
            .{},
        );
        return;
    }
    const entries = entries_buf[0..n_entries];
    const external_names = external_names_buf[0..n_external];

    // FILE mode auto-writes — pre-clear the output. Flight mode
    // writes nothing automatically; --output is meaningless there
    // (snapshots use `sismo snapshot --output ...`), so don't touch
    // any file the user named.
    if (!flight_recorder) _ = std.c.unlink(@ptrCast(output_path.ptr));
    const trace_cfg: perfetto_proto.TraceConfig = .{
        .mode = if (flight_recorder) .ring else .file,
        .buffer_size_kb = buffer_kb,
        .output_path = if (flight_recorder) "" else output_path,
        .max_file_size_bytes = 1024 * 1024 * 1024,
        .data_sources = entries,
    };
    const cfg_bytes = perfetto_proto.encodeTraceConfig(gpa, trace_cfg) catch |err| {
        std.debug.print("sismo record: encodeTraceConfig failed: {s}\n", .{@errorName(err)});
        return;
    };
    defer gpa.free(cfg_bytes);

    const session = c.sismo_consumer_session_create() orelse {
        std.debug.print("sismo record: session_create failed\n", .{});
        return;
    };
    defer c.sismo_consumer_session_destroy(session);
    const setup_rc = c.sismo_consumer_session_setup(session, cfg_bytes.ptr, cfg_bytes.len);
    if (setup_rc != 0) {
        std.debug.print("sismo record: session_setup rc={d} (TraceConfig failed to parse)\n", .{setup_rc});
        return;
    }

    // Wait for sidecar `sismo datasource` producers to register before
    // starting the session. Without this, StartBlocking proceeds
    // immediately and traced records nothing for any data source whose
    // producer hasn't connected yet — silently producing an incomplete
    // trace.
    if (external_names.len > 0) {
        std.debug.print(
            "sismo record: waiting up to 5s for external producers ({d}) — start them with `sudo sismo datasource ...`\n",
            .{external_names.len},
        );
        if (!waitForExternalDataSources(session, external_names, 5_000)) {
            std.debug.print(
                "sismo record: timed out waiting for external producer(s):\n",
                .{},
            );
            for (external_names) |n| std.debug.print("    {s}\n", .{n});
            std.debug.print(
                "  start a sidecar with `sudo sismo datasource <name>` (or `all-privileged`) and re-run.\n",
                .{},
            );
            return;
        }
    }

    c.sismo_consumer_session_start_blocking(session);
    if (flight_recorder) {
        std.debug.print(
            "sismo record: flight-recorder started ({d} KB buffer); take snapshots via `sismo snapshot` while running\n",
            .{buffer_kb},
        );
    } else {
        std.debug.print("sismo record: session started, recording until workload exits (or SIGINT)\n", .{});
    }

    // 8. Wait for the workload to exit (or for SIGINT). Both events
    //    funnel through a self-pipe: the SIGINT handler writes 'I',
    //    a dedicated thread that blocks on `waitpid` writes 'X'. Main
    //    just reads the pipe — single blocking syscall, no atomics,
    //    no retry loop, no platform-specific event source.
    var pipe_fds: [2]c_int = undefined;
    if (std.c.pipe(&pipe_fds) != 0) {
        std.debug.print("sismo record: pipe() failed\n", .{});
        return;
    }
    defer _ = std.c.close(pipe_fds[0]);
    defer _ = std.c.close(pipe_fds[1]);
    g_pipe_write_fd = pipe_fds[1];
    const sigint_act: std.c.Sigaction = .{
        .handler = .{ .handler = handleSigint },
        .mask = std.mem.zeroes(std.c.sigset_t),
        .flags = 0,
    };
    std.posix.sigaction(.INT, &sigint_act, null);

    const wait_ctx: WaitCtx = .{
        .pid = target.pid,
        .write_fd = pipe_fds[1],
        .mode = if (attach_pid != null) .attach else .spawn,
    };
    const wait_thr = try std.Thread.spawn(.{}, exitWatchThread, .{&wait_ctx});
    defer wait_thr.join();

    // Optional --duration timer. Detached — the thread fires 'T' on the
    // self-pipe and exits; we don't wait for it because if recording
    // ends earlier (SIGINT or target exit), the timer thread can be
    // left to wake up and write to a closed pipe (harmless).
    var duration_ctx: DurationCtx = undefined;
    var duration_thr: ?std.Thread = null;
    if (duration_secs) |secs| {
        duration_ctx = .{ .seconds = secs, .write_fd = pipe_fds[1] };
        duration_thr = try std.Thread.spawn(.{}, durationTimerThread, .{&duration_ctx});
    }
    defer if (duration_thr) |t| t.detach();

    var read_buf: [16]u8 = undefined;
    var workload_done: bool = false;
    while (!workload_done) {
        const n = std.c.read(pipe_fds[0], &read_buf, read_buf.len);
        if (n <= 0) continue;
        for (read_buf[0..@intCast(n)]) |b| switch (b) {
            'I' => {
                if (attach_pid == null) {
                    // Spawn mode: we own the workload, propagate SIGTERM
                    // so it shuts down cleanly. Then break out — the
                    // wait thread will fire 'X' once it actually exits.
                    std.debug.print("sismo record: SIGINT — sending SIGTERM to workload pid={d}\n", .{target.pid});
                    _ = std.c.kill(target.pid, .TERM);
                } else {
                    // Attach mode: it's the user's process, we don't
                    // signal it. Just stop recording.
                    std.debug.print("sismo record: SIGINT — stopping recording (attached pid={d} keeps running)\n", .{target.pid});
                    workload_done = true;
                }
            },
            'T' => {
                if (attach_pid == null) {
                    std.debug.print("sismo record: --duration reached — sending SIGTERM to workload pid={d}\n", .{target.pid});
                    _ = std.c.kill(target.pid, .TERM);
                } else {
                    std.debug.print("sismo record: --duration reached — stopping recording (attached pid={d} keeps running)\n", .{target.pid});
                    workload_done = true;
                }
            },
            'X' => workload_done = true,
            else => {},
        };
    }

    // 9. Stop the session. In FILE mode the data has been streaming
    //    to disk via Perfetto's auto-write; on_stop fires per DS,
    //    workers drain + ack, stop_blocking returns. In flight mode
    //    we don't auto-flush — if the user wanted the buffer's
    //    contents, they took a `sismo snapshot` already; otherwise
    //    the buffer is dropped on stop. Snapshotting is exclusively
    //    a clone operation, never a side-effect of stopping.
    c.sismo_consumer_session_stop_blocking(session);
    if (flight_recorder) {
        std.debug.print("sismo record: flight-recorder stopped (buffer discarded; use `sismo snapshot` before stopping to capture)\n", .{});
    } else {
        std.debug.print("sismo record: trace saved to {s}\n", .{output_path});
        // TODO: replace with JSON-in-zip sidecar. See sismo_privileged_marker.zig.
        privileged_marker.appendPrivilegedMarker(gpa, io, output_path, &.{target.pid}) catch |err| {
            std.debug.print("sismo record: failed to write privileged marker: {s}\n", .{@errorName(err)});
        };
    }

    // 11. Shut down captures (signals EXIT, joins worker, frees state).
    if (heap) |s| {
        const stats = s.shutdown();
        std.debug.print(
            "sismo record: heap — {d} records, ~{d} bytes, {d} sites\n",
            .{ stats.records, stats.bytes_alloc_estimated, stats.sites },
        );
    }
    if (cpu) |s| {
        const stats = s.shutdown();
        std.debug.print(
            "sismo record: cpu — {d} samples ({d} active)\n",
            .{ stats.samples, stats.active_samples },
        );
    }
    if (sched) |s| {
        const stats = s.shutdown();
        std.debug.print(
            "sismo record: sched — {d} events emitted across {d} drains\n",
            .{ stats.events_emitted, stats.drain_calls },
        );
    }

    // 12. Stop the embedded traced thread.
    traced.stop(svc);
}

// -----------------------------------------------------------------------------
// Linux record path
//
// Same self-pipe wait-loop + lock + spawn skeleton as the macOS path,
// but the data sources live inside upstream Perfetto producers we
// embed as in-process threads (`linux_traced_probes` for ftrace +
// procfs, `linux_traced_perf` for perf_event_open CPU sampling) rather
// than bespoke Zig captures. The producers self-register their data
// sources when the consumer's TraceConfig enables `linux.ftrace` /
// `linux.perf`; sismo's only job is to spawn + tear down the threads.
//
// What this branch does NOT do today:
//   - --pid attach: would need a pidfd-based exit watcher (Linux's
//     equivalent of the macOS kqueue path); skipped for v0.
//   - heap profiling: Linux LD_PRELOAD heap interception is its own
//     task (master plan §"Heap (libc malloc)"), not wired here.
// -----------------------------------------------------------------------------
fn runRecordLinux(init: std.process.Init, args: *RecordArgs) !void {
    const gpa = init.gpa;
    const io = init.io;

    // Read fields off `args` into local names. The Linux runner doesn't
    // currently honor sched_mode/cpu_mode/heap_mode beyond the
    // shared-parser semantics (privileged-source toggles for the linux
    // producers + sismo.heap aren't wired through this codepath yet —
    // that's a follow-up to plan 10). What we *do* honor today is
    // --no-sched, --no-cpu, --no-instrumentation and the buffer/output
    // family.
    const output_path = args.output_path;
    const duration_secs = args.duration_secs;
    const flight_recorder = args.flight_recorder;
    const buffer_kb = args.buffer_kb;
    const no_sched = args.sched_mode == .off;
    const no_cpu = args.cpu_mode == .off;
    const no_instrumentation = args.no_instrumentation;
    const workload_argv = &args.workload_argv;

    const lock_fd = paths.acquireSessionLock(std.c.getpid()) catch |err| switch (err) {
        error.AlreadyHeld => {
            std.debug.print(
                "sismo record: another sismo session is already running (lock held on {s})\n",
                .{paths.session_lock_path},
            );
            return;
        },
        error.OpenFailed => {
            std.debug.print(
                "sismo record: failed to open session lock at {s}\n",
                .{paths.session_lock_path},
            );
            return;
        },
    };
    defer paths.releaseSessionLock(lock_fd);

    const my_pid = std.c.getpid();
    const prod_sock = paths.producer_sock;
    const cons_sock = paths.consumer_sock;

    std.debug.print(
        "sismo record: pid={d} output={s}\n  producer sock: {s}\n  consumer sock: {s}\n",
        .{ my_pid, output_path, prod_sock, cons_sock },
    );

    _ = setenv("PERFETTO_PRODUCER_SOCK_NAME", prod_sock.ptr, 1);
    _ = setenv("PERFETTO_CONSUMER_SOCK_NAME", cons_sock.ptr, 1);

    // 1. Embed traced (the IPC service host) on a worker thread.
    const svc = try traced.create(prod_sock, cons_sock);
    defer traced.destroy(svc);

    // 2. Embed traced_probes (ftrace + procfs) and traced_perf
    //    (perf_event_open) as in-process producer threads. They both
    //    connect to the in-process traced over the producer socket the
    //    service just bound. defer LIFO order tears them down before
    //    the service.
    const probes = if (no_sched)
        null
    else linux_traced_probes.create(prod_sock) catch |err| blk: {
        std.debug.print(
            "sismo record: traced_probes attach failed: {s} — sched events disabled\n",
            .{@errorName(err)},
        );
        break :blk null;
    };
    defer if (probes) |p| linux_traced_probes.destroy(p);

    const perf = if (no_cpu)
        null
    else linux_traced_perf.create(prod_sock) catch |err| blk: {
        std.debug.print(
            "sismo record: traced_perf attach failed: {s} — CPU samples disabled\n",
            .{@errorName(err)},
        );
        break :blk null;
    };
    defer if (perf) |p| linux_traced_perf.destroy(p);

    // 3. Spawn the workload. No DYLD_INSERT_LIBRARIES — that's macOS.
    //    The Linux LD_PRELOAD heap interceptor is a separate pillar.
    const workload_cmd = workload_argv.items[0];
    const workload_args = workload_argv.items[1..];
    const target = maybeSpawn(gpa, workload_cmd, workload_args, &.{
        "PERFETTO_PRODUCER_SOCK_NAME", prod_sock,
    }) orelse {
        std.debug.print("sismo record: failed to spawn '{s}' — exiting\n", .{workload_cmd});
        return;
    };
    std.debug.print("sismo record: spawned '{s}' pid={d}\n", .{ workload_cmd, target.pid });

    // 4. Build the TraceConfig in Zig. Linux producers (traced_probes,
    //    traced_perf) get the Perfetto-native FtraceConfig /
    //    PerfEventConfig nested submessages embedded inside the
    //    DataSourceConfig — see perfetto_proto.zig.
    const perfetto_proto = @import("perfetto_proto.zig");
    var entries_buf: [3]perfetto_proto.DataSourceEntry = undefined;
    var n_entries: usize = 0;
    if (!no_instrumentation) {
        entries_buf[n_entries] = .{ .track_event = .{ .enabled_categories = &.{"*"} } };
        n_entries += 1;
    }
    if (probes != null) {
        // ftrace stays system-wide because traced_probes can't filter
        // by pid. trace_processor handles separating the workload's
        // events out post-hoc.
        entries_buf[n_entries] = .{ .linux_ftrace = .{} };
        n_entries += 1;
    }
    // PMU counters are opt-out (--no-counters). Probe which the hardware can
    // actually open so we only ask perfetto for those — it opens the sample
    // group all-or-nothing, so an unsupported follower would sink CPU sampling.
    var perf_counters: []const perfetto_proto.PerfCounter = &.{};
    if (perf != null and args.counters) {
        perf_counters = perf_counter_probe.probeSupported(gpa) catch &.{};
    }
    defer gpa.free(perf_counters);
    if (perf != null) {
        // 2048 pages = 8 MB per CPU. perfetto's 256-page default overflows at
        // 1 kHz sampling with full DWARF stack snapshots; trace stats show
        // hundreds of lost records per CPU under that default. 8 MB is what
        // perfetto's docs recommend for "high frequency / large stacks".
        entries_buf[n_entries] = .{ .linux_perf = .{
            .target_pid = target.pid,
            .ring_buffer_pages = 2048,
            .counters = perf_counters,
        } };
        n_entries += 1;
    }
    if (n_entries == 0) {
        std.debug.print(
            "sismo record: no data sources enabled — recording would be empty. Drop one of the --no-* flags.\n",
            .{},
        );
        return;
    }
    const entries = entries_buf[0..n_entries];

    if (!flight_recorder) _ = std.c.unlink(@ptrCast(output_path.ptr));
    const trace_cfg: perfetto_proto.TraceConfig = .{
        .mode = if (flight_recorder) .ring else .file,
        .buffer_size_kb = buffer_kb,
        .output_path = if (flight_recorder) "" else output_path,
        .max_file_size_bytes = 1024 * 1024 * 1024,
        .data_sources = entries,
    };
    const cfg_bytes = perfetto_proto.encodeTraceConfig(gpa, trace_cfg) catch |err| {
        std.debug.print("sismo record: encodeTraceConfig failed: {s}\n", .{@errorName(err)});
        return;
    };
    defer gpa.free(cfg_bytes);

    const session = c.sismo_consumer_session_create() orelse {
        std.debug.print("sismo record: session_create failed\n", .{});
        return;
    };
    defer c.sismo_consumer_session_destroy(session);
    const setup_rc = c.sismo_consumer_session_setup(session, cfg_bytes.ptr, cfg_bytes.len);
    if (setup_rc != 0) {
        std.debug.print("sismo record: session_setup rc={d} (TraceConfig failed to parse)\n", .{setup_rc});
        return;
    }
    c.sismo_consumer_session_start_blocking(session);
    if (flight_recorder) {
        std.debug.print(
            "sismo record: flight-recorder started ({d} KB buffer); take snapshots via `sismo snapshot` while running\n",
            .{buffer_kb},
        );
    } else {
        std.debug.print("sismo record: session started, recording until workload exits (or SIGINT)\n", .{});
    }

    // 5. Self-pipe wait loop, identical to the macOS path.
    var pipe_fds: [2]c_int = undefined;
    if (std.c.pipe(&pipe_fds) != 0) {
        std.debug.print("sismo record: pipe() failed\n", .{});
        return;
    }
    defer _ = std.c.close(pipe_fds[0]);
    defer _ = std.c.close(pipe_fds[1]);
    g_pipe_write_fd = pipe_fds[1];
    const sigint_act: std.c.Sigaction = .{
        .handler = .{ .handler = handleSigint },
        .mask = std.mem.zeroes(std.c.sigset_t),
        .flags = 0,
    };
    std.posix.sigaction(.INT, &sigint_act, null);

    const wait_ctx: WaitCtx = .{
        .pid = target.pid,
        .write_fd = pipe_fds[1],
        .mode = .spawn,  // attach mode not yet supported on Linux
    };
    const wait_thr = try std.Thread.spawn(.{}, exitWatchThread, .{&wait_ctx});
    defer wait_thr.join();

    var duration_ctx: DurationCtx = undefined;
    var duration_thr: ?std.Thread = null;
    if (duration_secs) |secs| {
        duration_ctx = .{ .seconds = secs, .write_fd = pipe_fds[1] };
        duration_thr = try std.Thread.spawn(.{}, durationTimerThread, .{&duration_ctx});
    }
    defer if (duration_thr) |t| t.detach();

    var read_buf: [16]u8 = undefined;
    var workload_done: bool = false;
    while (!workload_done) {
        const n = std.c.read(pipe_fds[0], &read_buf, read_buf.len);
        if (n <= 0) continue;
        for (read_buf[0..@intCast(n)]) |b| switch (b) {
            'I' => {
                std.debug.print("sismo record: SIGINT — sending SIGTERM to workload pid={d}\n", .{target.pid});
                _ = std.c.kill(target.pid, .TERM);
            },
            'T' => {
                std.debug.print("sismo record: --duration reached — sending SIGTERM to workload pid={d}\n", .{target.pid});
                _ = std.c.kill(target.pid, .TERM);
            },
            'X' => workload_done = true,
            else => {},
        };
    }

    // 6. Stop the session. The producers' on_stop callbacks fire on
    //    their own threads; once stop_blocking returns, the trace is
    //    flushed (FILE mode) or sitting in the ring (flight mode).
    c.sismo_consumer_session_stop_blocking(session);
    if (flight_recorder) {
        std.debug.print("sismo record: flight-recorder stopped (buffer discarded; use `sismo snapshot` before stopping to capture)\n", .{});
    } else {
        std.debug.print("sismo record: trace saved to {s}\n", .{output_path});
        // TODO: replace with JSON-in-zip sidecar. See sismo_privileged_marker.zig.
        privileged_marker.appendPrivilegedMarker(gpa, io, output_path, &.{target.pid}) catch |err| {
            std.debug.print("sismo record: failed to write privileged marker: {s}\n", .{@errorName(err)});
        };
    }

    // 7. Tear-down via Zig defer LIFO:
    //      perf.destroy → probes.destroy → traced.destroy
    //    Each destroy() Quits the producer's TaskRunner and joins the
    //    worker thread, so producers fully detach before the service
    //    tears down.
    traced.stop(svc);
}
