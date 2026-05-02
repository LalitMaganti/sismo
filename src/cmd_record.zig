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
const c = @cImport({
    @cInclude("perfetto_shim.h");
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

/// Entry point for the `record` subcommand. Dispatched from `sismo.zig`.
/// Re-iterates `init.minimal.args` and skips two slots — the exe path
/// and the literal "record" subcommand token — before parsing the
/// record-specific arguments.
pub fn runRecord(init: std.process.Init) !void {
    if (comptime builtin.os.tag == .macos) {
        return runRecordMacos(init);
    }
    if (comptime builtin.os.tag == .linux) {
        return runRecordLinux(init);
    }
    std.debug.print(
        "sismo record: not yet implemented on {s}\n",
        .{@tagName(builtin.os.tag)},
    );
}

fn runRecordMacos(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    // Args: [--output <path>] (--pid <pid> | <command> [args...])
    // Exactly one of --pid (attach to a running process) or <command>
    // (spawn a new one) must be supplied. Everything after the first
    // non-flag positional is the workload's argv when spawning.
    var iter = init.minimal.args.iterate();
    _ = iter.next(); // exe path
    _ = iter.next(); // "record" subcommand token
    var output_path: []const u8 = "./sismo.pftrace";
    var attach_pid: ?c_int = null;
    var duration_secs: ?c_uint = null;
    var flight_recorder = false;
    // 128 MB default for FILE mode (matches the original hardcoded
    // buffer that kdebug needs to avoid SEQ_INCREMENTAL_STATE_CLEARED
    // eviction). 256 MB default for flight-recorder mode (the master
    // plan number — comfortable for typical desktop workloads).
    var buffer_kb: u32 = 128 * 1024;
    var buffer_set = false;
    var no_sched = false;
    var no_cpu = false;
    var no_heap = false;
    var no_instrumentation = false;
    var workload_argv: std.ArrayList([]const u8) = .empty;
    defer workload_argv.deinit(gpa);

    while (iter.next()) |arg| {
        if (workload_argv.items.len == 0 and std.mem.startsWith(u8, arg, "--")) {
            if (std.mem.eql(u8, arg, "--output")) {
                output_path = iter.next() orelse {
                    std.debug.print("sismo record: --output needs a value\n", .{});
                    return;
                };
            } else if (std.mem.eql(u8, arg, "--flight-recorder")) {
                flight_recorder = true;
            } else if (std.mem.eql(u8, arg, "--buffer")) {
                const v = iter.next() orelse {
                    std.debug.print("sismo record: --buffer needs a value (e.g. 256MB)\n", .{});
                    return;
                };
                buffer_kb = parseBufferKb(v) orelse {
                    std.debug.print(
                        "sismo record: invalid --buffer '{s}' (use 256MB / 1GB / 512KB)\n",
                        .{v},
                    );
                    return;
                };
                buffer_set = true;
            } else if (std.mem.eql(u8, arg, "--pid")) {
                const v = iter.next() orelse {
                    std.debug.print("sismo record: --pid needs a value\n", .{});
                    return;
                };
                attach_pid = std.fmt.parseInt(c_int, v, 10) catch {
                    std.debug.print("sismo record: --pid '{s}' is not a number\n", .{v});
                    return;
                };
            } else if (std.mem.eql(u8, arg, "--duration")) {
                const v = iter.next() orelse {
                    std.debug.print("sismo record: --duration needs a value (e.g. 30s, 5m, 1h)\n", .{});
                    return;
                };
                duration_secs = parseDurationSeconds(v) orelse {
                    std.debug.print(
                        "sismo record: invalid --duration '{s}' (use 30s, 5m, 1h or a positive integer of seconds)\n",
                        .{v},
                    );
                    return;
                };
            } else if (std.mem.eql(u8, arg, "--no-sched")) {
                no_sched = true;
            } else if (std.mem.eql(u8, arg, "--no-cpu")) {
                no_cpu = true;
            } else if (std.mem.eql(u8, arg, "--no-heap")) {
                no_heap = true;
            } else if (std.mem.eql(u8, arg, "--no-instrumentation")) {
                no_instrumentation = true;
            } else if (std.mem.eql(u8, arg, "--help")) {
                std.debug.print(
                    "usage: sismo record [--output <path>] [--duration <dur>]\n" ++
                    "                    [--flight-recorder [--buffer <size>]]\n" ++
                    "                    [--no-sched] [--no-cpu] [--no-heap] [--no-instrumentation]\n" ++
                    "                    (--pid <pid> | <command> [args...])\n",
                    .{},
                );
                return;
            } else {
                std.debug.print("sismo record: unknown flag '{s}'\n", .{arg});
                return;
            }
        } else {
            try workload_argv.append(gpa, arg);
        }
    }

    const have_pid = attach_pid != null;
    const have_cmd = workload_argv.items.len > 0;
    if (have_pid and have_cmd) {
        std.debug.print(
            "sismo record: --pid and <command> are mutually exclusive\n",
            .{},
        );
        return;
    }
    if (!have_pid and !have_cmd) {
        std.debug.print(
            "sismo record: need either --pid <pid> or a workload <command>\n" ++
            "usage: sismo record [--output <path>] (--pid <pid> | <command> [args...])\n",
            .{},
        );
        return;
    }
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

    // Default buffer for flight-recorder mode is 256 MB (vs. 128 MB
    // for streaming FILE mode). User --buffer overrides either way.
    if (flight_recorder and !buffer_set) buffer_kb = 256 * 1024;

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

    // 2. Init our own producer connection. Same SYSTEM backend the
    //    workload uses; we connect from inside this process to our own
    //    hosted socket.
    c.sismo_perfetto_init();

    // 3. Allocate DS handles for the three sismo data sources. We don't
    //    register them yet — registration happens after we spawn the
    //    captures (we need the captures' state pointers as the
    //    callbacks' user_arg).
    const ds_sched = c.sismo_perfetto_ds_alloc() orelse return error.PerfettoDsAllocFailed;
    defer c.sismo_perfetto_ds_free(ds_sched);
    const ds_cpu = c.sismo_perfetto_ds_alloc() orelse return error.PerfettoDsAllocFailed;
    defer c.sismo_perfetto_ds_free(ds_cpu);
    const ds_heap = c.sismo_perfetto_ds_alloc() orelse return error.PerfettoDsAllocFailed;
    defer c.sismo_perfetto_ds_free(ds_heap);

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
        if (no_sched) break :blk null;
        break :blk macos_sched_capture.Capture.init(gpa, io, ds_sched, .{}) catch |err| {
            std.debug.print("sismo record: macos_sched_capture.init failed: {s}\n", .{@errorName(err)});
            break :blk null;
        };
    };
    const cpu = blk: {
        if (no_cpu) break :blk null;
        break :blk macos_cpu_samples_capture.Capture.init(gpa, io, ds_cpu, .{}) catch |err| {
            std.debug.print("sismo record: macos_cpu_samples_capture.init failed: {s}\n", .{@errorName(err)});
            break :blk null;
        };
    };
    const heap = blk: {
        if (no_heap) break :blk null;
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
        break :blk heap_capture.Capture.init(gpa, io, ds_heap, .{}) catch |err| {
            std.debug.print("sismo record: heap_capture.init failed: {s}\n", .{@errorName(err)});
            break :blk null;
        };
    };

    // 6. Register each DS with its on_setup / on_start / on_stop /
    //    on_flush callbacks.
    if (sched) |s| {
        if (!c.sismo_perfetto_ds_register_with_callbacks(
            ds_sched,
            "sismo.macos_sched",
            macos_sched_capture.Capture.onSetupTrampoline,
            macos_sched_capture.Capture.onStartTrampoline,
            macos_sched_capture.Capture.onStopTrampoline,
            macos_sched_capture.Capture.onFlushTrampoline,
            s,
        )) std.debug.print("sismo record: register sismo.macos_sched failed\n", .{});
    }
    if (cpu) |s| {
        if (!c.sismo_perfetto_ds_register_with_callbacks(
            ds_cpu,
            "sismo.macos_cpu_samples",
            macos_cpu_samples_capture.Capture.onSetupTrampoline,
            macos_cpu_samples_capture.Capture.onStartTrampoline,
            macos_cpu_samples_capture.Capture.onStopTrampoline,
            macos_cpu_samples_capture.Capture.onFlushTrampoline,
            s,
        )) std.debug.print("sismo record: register sismo.macos_cpu_samples failed\n", .{});
    }
    if (heap) |s| {
        if (!c.sismo_perfetto_ds_register_with_callbacks(
            ds_heap,
            "sismo.heap",
            heap_capture.Capture.onSetupTrampoline,
            heap_capture.Capture.onStartTrampoline,
            heap_capture.Capture.onStopTrampoline,
            heap_capture.Capture.onFlushTrampoline,
            s,
        )) std.debug.print("sismo record: register sismo.heap failed\n", .{});
    }

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

    // Build the entries array dynamically from the source toggles.
    // `track_event` (the user's instrumentation surface) is gated by
    // --no-instrumentation; the three sismo.* entries follow the
    // capture nullability we set above (which already folds in the
    // matching --no-* flag and the heap-not-prepared case).
    var entries_buf: [4]c.SismoDsConfigEntry = undefined;
    var n_entries: usize = 0;
    if (!no_instrumentation) {
        entries_buf[n_entries] = .{ .name = "track_event", .extra_bytes = null, .extra_bytes_size = 0, .target_pid = 0 };
        n_entries += 1;
    }
    if (heap != null) {
        entries_buf[n_entries] = .{ .name = "sismo.heap", .extra_bytes = heap_cfg.ptr, .extra_bytes_size = heap_cfg.len, .target_pid = 0 };
        n_entries += 1;
    }
    if (cpu != null) {
        entries_buf[n_entries] = .{ .name = "sismo.macos_cpu_samples", .extra_bytes = cpu_cfg.ptr, .extra_bytes_size = cpu_cfg.len, .target_pid = 0 };
        n_entries += 1;
    }
    if (sched != null) {
        entries_buf[n_entries] = .{ .name = "sismo.macos_sched", .extra_bytes = if (sched_cfg.len > 0) sched_cfg.ptr else null, .extra_bytes_size = sched_cfg.len, .target_pid = 0 };
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

    // FILE mode auto-writes — pre-clear the output. Flight mode
    // writes nothing automatically; --output is meaningless there
    // (snapshots use `sismo snapshot --output ...`), so don't touch
    // any file the user named.
    if (!flight_recorder) _ = std.c.unlink(@ptrCast(output_path.ptr));
    var cfg: ?*anyopaque = null;
    var cfg_len: usize = 0;
    const path_z = try gpa.dupeZ(u8, output_path);
    defer gpa.free(path_z);
    const mode: c.SismoMode = if (flight_recorder) c.SISMO_MODE_RING else c.SISMO_MODE_FILE;
    // RING mode ignores output_path (no auto-write), but the shim still
    // accepts it; pass null so a future shim assert can catch a misuse.
    const out_for_shim: ?[*:0]const u8 = if (flight_recorder) null else path_z.ptr;
    const cfg_rc = c.sismo_perfetto_build_config(
        mode,
        entries.ptr,
        entries.len,
        buffer_kb,
        0,
        1024 * 1024 * 1024,
        out_for_shim,
        &cfg,
        &cfg_len,
    );
    if (cfg_rc != 0) {
        std.debug.print("sismo record: build_config rc={d}\n", .{cfg_rc});
        return;
    }
    defer c.sismo_perfetto_free_config(cfg);

    const session = c.sismo_consumer_session_create() orelse {
        std.debug.print("sismo record: session_create failed\n", .{});
        return;
    };
    defer c.sismo_consumer_session_destroy(session);
    const setup_rc = c.sismo_consumer_session_setup(session, cfg, cfg_len);
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
fn runRecordLinux(init: std.process.Init) !void {
    const gpa = init.gpa;
    _ = init.io;

    var iter = init.minimal.args.iterate();
    _ = iter.next(); // exe path
    _ = iter.next(); // "record" subcommand token
    var output_path: []const u8 = "./sismo.pftrace";
    var duration_secs: ?c_uint = null;
    var flight_recorder = false;
    var buffer_kb: u32 = 128 * 1024;
    var buffer_set = false;
    var no_sched = false;
    var no_cpu = false;
    var no_instrumentation = false;
    var workload_argv: std.ArrayList([]const u8) = .empty;
    defer workload_argv.deinit(gpa);

    while (iter.next()) |arg| {
        if (workload_argv.items.len == 0 and std.mem.startsWith(u8, arg, "--")) {
            if (std.mem.eql(u8, arg, "--output")) {
                output_path = iter.next() orelse {
                    std.debug.print("sismo record: --output needs a value\n", .{});
                    return;
                };
            } else if (std.mem.eql(u8, arg, "--flight-recorder")) {
                flight_recorder = true;
            } else if (std.mem.eql(u8, arg, "--buffer")) {
                const v = iter.next() orelse {
                    std.debug.print("sismo record: --buffer needs a value (e.g. 256MB)\n", .{});
                    return;
                };
                buffer_kb = parseBufferKb(v) orelse {
                    std.debug.print(
                        "sismo record: invalid --buffer '{s}' (use 256MB / 1GB / 512KB)\n",
                        .{v},
                    );
                    return;
                };
                buffer_set = true;
            } else if (std.mem.eql(u8, arg, "--duration")) {
                const v = iter.next() orelse {
                    std.debug.print("sismo record: --duration needs a value (e.g. 30s, 5m, 1h)\n", .{});
                    return;
                };
                duration_secs = parseDurationSeconds(v) orelse {
                    std.debug.print(
                        "sismo record: invalid --duration '{s}' (use 30s, 5m, 1h or a positive integer of seconds)\n",
                        .{v},
                    );
                    return;
                };
            } else if (std.mem.eql(u8, arg, "--no-sched")) {
                no_sched = true;
            } else if (std.mem.eql(u8, arg, "--no-cpu")) {
                no_cpu = true;
            } else if (std.mem.eql(u8, arg, "--no-instrumentation")) {
                no_instrumentation = true;
            } else if (std.mem.eql(u8, arg, "--no-heap")) {
                // Heap profiling not wired on Linux yet; accept the
                // flag silently so users can share invocations across
                // platforms.
            } else if (std.mem.eql(u8, arg, "--pid")) {
                std.debug.print("sismo record: --pid attach not yet supported on Linux\n", .{});
                return;
            } else if (std.mem.eql(u8, arg, "--help")) {
                std.debug.print(
                    "usage: sismo record [--output <path>] [--duration <dur>]\n" ++
                    "                    [--flight-recorder [--buffer <size>]]\n" ++
                    "                    [--no-sched] [--no-cpu] [--no-instrumentation]\n" ++
                    "                    <command> [args...]\n" ++
                    "\n" ++
                    "Linux requires CAP_PERFMON for perf_event_open and read access\n" ++
                    "to /sys/kernel/tracing for ftrace; running with sudo is the\n" ++
                    "easiest path.\n",
                    .{},
                );
                return;
            } else {
                std.debug.print("sismo record: unknown flag '{s}'\n", .{arg});
                return;
            }
        } else {
            try workload_argv.append(gpa, arg);
        }
    }

    if (workload_argv.items.len == 0) {
        std.debug.print(
            "sismo record: need a workload <command> on Linux (--pid attach not yet supported)\n",
            .{},
        );
        return;
    }

    if (flight_recorder and !buffer_set) buffer_kb = 256 * 1024;

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

    // 4. Build the TraceConfig. Linux producers don't need sismo's
    //    vendor extension at field 2000 — their config lives in the
    //    Perfetto-native FtraceConfig / PerfEventConfig nested
    //    submessages, which sismo_perfetto_build_config hand-rolls
    //    when it sees the entry names "linux.ftrace" / "linux.perf".
    var entries_buf: [3]c.SismoDsConfigEntry = undefined;
    var n_entries: usize = 0;
    if (!no_instrumentation) {
        entries_buf[n_entries] = .{ .name = "track_event", .extra_bytes = null, .extra_bytes_size = 0, .target_pid = 0 };
        n_entries += 1;
    }
    if (probes != null) {
        // ftrace stays system-wide because traced_probes can't filter
        // by pid. trace_processor handles separating the workload's
        // events out post-hoc.
        entries_buf[n_entries] = .{ .name = "linux.ftrace", .extra_bytes = null, .extra_bytes_size = 0, .target_pid = 0 };
        n_entries += 1;
    }
    if (perf != null) {
        entries_buf[n_entries] = .{ .name = "linux.perf", .extra_bytes = null, .extra_bytes_size = 0, .target_pid = target.pid };
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
    var cfg: ?*anyopaque = null;
    var cfg_len: usize = 0;
    const path_z = try gpa.dupeZ(u8, output_path);
    defer gpa.free(path_z);
    const mode: c.SismoMode = if (flight_recorder) c.SISMO_MODE_RING else c.SISMO_MODE_FILE;
    const out_for_shim: ?[*:0]const u8 = if (flight_recorder) null else path_z.ptr;
    const cfg_rc = c.sismo_perfetto_build_config(
        mode,
        entries.ptr,
        entries.len,
        buffer_kb,
        0,
        1024 * 1024 * 1024,
        out_for_shim,
        &cfg,
        &cfg_len,
    );
    if (cfg_rc != 0) {
        std.debug.print("sismo record: build_config rc={d}\n", .{cfg_rc});
        return;
    }
    defer c.sismo_perfetto_free_config(cfg);

    const session = c.sismo_consumer_session_create() orelse {
        std.debug.print("sismo record: session_create failed\n", .{});
        return;
    };
    defer c.sismo_consumer_session_destroy(session);
    const setup_rc = c.sismo_consumer_session_setup(session, cfg, cfg_len);
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
    }

    // 7. Tear-down via Zig defer LIFO:
    //      perf.destroy → probes.destroy → traced.destroy
    //    Each destroy() Quits the producer's TaskRunner and joins the
    //    worker thread, so producers fully detach before the service
    //    tears down.
    traced.stop(svc);
}
