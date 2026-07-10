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
//! per-DS state machine): each `sismo.*` data source registers
//! on_setup / on_start / on_stop / on_flush callbacks bound to a
//! `*Capture` state owned by this process. Each capture's worker
//! thread is spawned BEFORE the session starts; it waits for on_setup,
//! then does its own heavy setup (task_for_pid, image enumeration,
//! framehop registration, heap attach) on its own thread. When the
//! session starts, traced fires on_start on its IO thread and the
//! trampoline flips the worker into RUNNING via a std.Io.Event,
//! returning immediately so the IO thread never blocks. Flush (heap
//! snapshot) and on_stop (async stopper handle) follow the same
//! pattern — the trampoline updates an atomic + sets the wakeup event;
//! the worker drains/emits/acks. At process exit the worker is
//! signalled EXIT and joined.
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
// Privileged-pid marker encoder + file-append now lives in Rust
// (rust-bridge/src/privileged_marker.rs).
extern fn sismo_append_privileged_marker(
    path: [*]const u8,
    path_len: usize,
    pids: [*]const i32,
    n_pids: usize,
    focus_preset: ?[*]const u8,
    focus_preset_len: usize,
    focus_precise: bool,
) bool;
const focus_presets = @import("focus_presets.zig");
// Post-record symbolization now lives in Rust (rust-bridge/src/perf_symbolize.rs).
extern fn sismo_symbolize_trace(trace_path_ptr: [*]const u8, trace_path_len: usize) void;
const c = @cImport({
    @cInclude("src/c/perfetto_shim.h");
});

// macOS-only data sources. Linux needs perf_event-based equivalents,
// Windows needs ETW; both live in sibling modules once they're written.
// On non-macOS builds these resolve to `struct {}` and runRecord
// short-circuits before any reference to the missing types.
// sched (kdebug) capture worker now lives in Rust
// (rust-bridge/src/macos_sched_capture.rs).
const SchedCapture = opaque {};
extern fn sismo_sched_capture_init() ?*SchedCapture;
extern fn sismo_sched_capture_shutdown(cap: *SchedCapture, out_events_emitted: *u64, out_drain_calls: *u64) void;
// CPU-samples capture worker now lives in Rust (rust-bridge/src/
// macos_cpu_capture.rs) — it owns its thread + the C++ SDK data-source
// lifecycle. cmd_record just init/shutdowns it over the C ABI.
const CpuCapture = opaque {};
extern fn sismo_cpu_capture_init(default_interval_ns: u64) ?*CpuCapture;
extern fn sismo_cpu_capture_shutdown(cap: *CpuCapture, out_samples: *u64, out_active_samples: *u64) void;
// Heap capture worker now lives in Rust (rust-bridge/src/macos_heap_capture.rs).
const HeapCapture = opaque {};
extern fn sismo_heap_capture_init() ?*HeapCapture;
extern fn sismo_heap_capture_shutdown(cap: *HeapCapture, out_records: *u64, out_bytes_alloc: *u64, out_sites: *u32) void;

// The whole macOS `sismo record` path lives in Rust
// (rust-bridge/src/cmd_record.rs): parse + spawn/attach + traced + consumer
// session + the self-pipe wait loop. runRecord's macOS branch calls it directly.
extern fn sismo_run_record_macos(argc: usize, argv: [*]const [*:0]const u8) c_int;

// The `sismo record` argument parser is ONE Rust parser (clap) for all
// platforms (rust-bridge/src/record_args.rs). It fills this C-ABI struct; the
// macOS runner reads its own copy internally, the Linux runner (below) reads
// this one. Layout mirrors the Rust `#[repr(C)] RecordArgsC` (size-guarded).
const RecordArgsC = extern struct {
    output_path_ptr: [*]const u8, // NUL-terminated at [output_path_len]
    output_path_len: usize,
    workload_start: usize, // absolute argv index of the workload cmd; == argc if none
    focus_preset_ptr: ?[*]const u8, // preset name (Linux); null if none
    focus_preset_len: usize,
    sample_density: f64,
    attach_pid: i32,
    duration_secs: u32,
    buffer_kb: u32,
    sched_mode: u8, // 0 in_process, 1 external, 2 off
    cpu_mode: u8,
    heap_mode: u8,
    has_attach_pid: bool,
    has_duration: bool,
    flight_recorder: bool,
    buffer_set: bool,
    no_instrumentation: bool,
    has_focus: bool,
    has_sample_density: bool,
};
comptime {
    if (@sizeOf(RecordArgsC) != 72) @compileError("RecordArgsC must match the Rust layout (72 bytes)");
}
extern fn sismo_parse_record_args(argc: usize, argv: [*]const [*:0]const u8, out: *RecordArgsC) bool;

// Linux uses upstream Perfetto's traced_probes (ftrace + procfs) embedded as
// an in-process worker thread — same pattern as `sismo_traced` for the
// service. It self-registers its data source when the consumer's TraceConfig
// requests it.
const linux_traced_probes = switch (builtin.os.tag) {
    .linux => @import("sismo_traced_probes.zig"),
    else => struct {},
};

// In-process BPF CPU collector (per-thread counters + stack sampling) — the
// Linux CPU profiler.
const linux_bpf_capture = switch (builtin.os.tag) {
    .linux => @import("linux_bpf_capture.zig"),
    else => struct {},
};

// `setenv` has no idiomatic Zig wrapper — env mutation goes through libc
// so it stays in sync with the libc-side environ that posix_spawnp
// inherits.
extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;

// rust-bridge/src/session_config.rs — TraceConfig encoder. `data_sources` is a
// flat array of DataSourceEntryC (built via the ds* helpers below).
const DataSourceEntryC = extern struct {
    kind: u32, // 0=track_event, 1=sismo_vendor, 2=linux_ftrace
    name: ?[*]const u8,
    name_len: usize,
    sismo_config: ?[*]const u8,
    sismo_config_len: usize,
    protovm_memory_limit_kb: u32,
};
extern fn sismo_encode_trace_config(
    mode: u32, // 0=ring, 1=capped, 2=file
    buffer_size_kb: u32,
    duration_ms: u32,
    output_path: ?[*]const u8,
    output_path_len: usize,
    max_file_size_bytes: u64,
    session_name: [*]const u8,
    session_name_len: usize,
    entries: [*]const DataSourceEntryC,
    entries_len: usize,
    out: [*]u8,
    cap: usize,
) usize;

fn dsTrackEvent() DataSourceEntryC {
    return .{ .kind = 0, .name = null, .name_len = 0, .sismo_config = null, .sismo_config_len = 0, .protovm_memory_limit_kb = 0 };
}
fn dsLinuxFtrace() DataSourceEntryC {
    return .{ .kind = 2, .name = null, .name_len = 0, .sismo_config = null, .sismo_config_len = 0, .protovm_memory_limit_kb = 0 };
}
fn dsSismoVendor(name: []const u8, cfg: []const u8, protovm_kb: u32) DataSourceEntryC {
    return .{
        .kind = 1,
        .name = name.ptr,
        .name_len = name.len,
        .sismo_config = cfg.ptr,
        .sismo_config_len = cfg.len,
        .protovm_memory_limit_kb = protovm_kb,
    };
}

// `std.c.posix_spawnp` only exposes the Darwin variant in zig 0.16; on
// Linux it's a libc symbol not surfaced through std.c. Declared locally
// with `?*const anyopaque` for the file_actions / attrp pointers, both
// always null here — the actual struct types differ per-OS but are never
// instantiated.
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

// Per-data-source mode wire values (0 in_process, 1 external, 2 off) come from
// RecordArgsC now — the parser (Rust) owns the SourceMode enum.

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
            for (seen) |s| if (!s) {
                all = false;
                break;
            };
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

// Spawn-mode exit watcher: blocks on waitpid for the owned child.
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

// Attach-mode exit watcher: register a kqueue NOTE_EXIT filter on the pid
// (not a child, so waitpid would EINTR or return ECHILD). EVFILT_PROC +
// NOTE_EXIT works for any visible pid — the canonical macOS way to watch a
// non-child for exit.
fn kqueueExitWatch(ctx: *const WaitCtx) void {
    const kq = std.c.kqueue();
    if (kq < 0) {
        // No kqueue — the main loop will only stop on SIGINT or --duration.
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
pub fn runRecord(init: std.process.Init) !void {
    // macOS: the entire record path is in Rust (rust-bridge/src/cmd_record.rs).
    if (comptime builtin.os.tag == .macos) {
        const v = init.minimal.args.vector;
        _ = sismo_run_record_macos(v.len, @ptrCast(v.ptr));
        return;
    }
    // Linux: same unified Rust parser; the runner is still Zig (coupled to
    // linux_bpf / focus_presets; migrates in P5).
    if (comptime builtin.os.tag == .linux) {
        const v = init.minimal.args.vector;
        var rc: RecordArgsC = undefined;
        if (!sismo_parse_record_args(v.len, @ptrCast(v.ptr), &rc)) return; // help/error printed
        return runRecordLinux(init, &rc);
    }
    std.debug.print(
        "sismo record: not yet implemented on {s}\n",
        .{@tagName(builtin.os.tag)},
    );
}

// -----------------------------------------------------------------------------
// Linux record path
//
// Same self-pipe wait-loop + lock + spawn skeleton as the macOS path.
// Sched rides upstream Perfetto's `linux_traced_probes` (ftrace + procfs)
// embedded as an in-process thread, self-registering when the consumer's
// TraceConfig enables `linux.ftrace`. CPU is `linux_bpf_capture`, a
// bespoke in-process BPF collector (per-thread counters + stack samples).
//
// What this branch does NOT do today:
//   - --pid attach: would need a pidfd-based exit watcher (Linux's
//     equivalent of the macOS kqueue path); skipped for v0.
//   - heap profiling: Linux LD_PRELOAD heap interception is its own
//     task (master plan §"Heap (libc malloc)"), not wired here.
// -----------------------------------------------------------------------------
fn runRecordLinux(init: std.process.Init, rc: *const RecordArgsC) !void {
    const gpa = init.gpa;

    // Unpack RecordArgsC (parsed by the unified Rust parser). The Linux runner
    // doesn't yet honor external/heap toggles (follow-up); honored today:
    // --no-sched, --no-cpu, --no-instrumentation, buffer/output, --focus.
    const MODE_OFF: u8 = 2;
    const output_path: []const u8 = rc.output_path_ptr[0..rc.output_path_len];
    const duration_secs: ?c_uint = if (rc.has_duration) @as(c_uint, rc.duration_secs) else null;
    const flight_recorder = rc.flight_recorder;
    const buffer_kb = rc.buffer_kb;
    const no_sched = rc.sched_mode == MODE_OFF;
    const no_cpu = rc.cpu_mode == MODE_OFF;
    const no_instrumentation = rc.no_instrumentation;
    const argv_vec = init.minimal.args.vector;
    const sample_density: ?f64 = if (rc.has_sample_density) rc.sample_density else null;
    // Focus preset arrives as its name; resolve it here (keeps the parser
    // decoupled from focus_presets). Unknown name = a hard error, as before.
    const focus_preset: ?focus_presets.FocusPreset = if (rc.has_focus) blk: {
        const name = rc.focus_preset_ptr.?[0..rc.focus_preset_len];
        break :blk focus_presets.fromName(name) orelse {
            std.debug.print("sismo record: unknown focus preset '{s}' (supported: cache)\n", .{name});
            return;
        };
    } else null;

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

    // Initialize the in-process C++ SDK producer client against the service's
    // producer socket. Needed by `sismo_ds_register` for the BPF CPU collector
    // (the traced_probes producer connects through its own glue).
    c.sismo_init(prod_sock.ptr);

    // Embed traced_probes (ftrace + procfs) as an in-process producer
    // thread, connecting to the in-process traced over the producer socket
    // the service just bound. (defer LIFO tears it down before the service.)
    const probes = if (no_sched)
        null
    else
        linux_traced_probes.create(prod_sock) catch |err| blk: {
            std.debug.print(
                "sismo record: traced_probes attach failed: {s} — sched events disabled\n",
                .{@errorName(err)},
            );
            break :blk null;
        };
    defer if (probes) |p| linux_traced_probes.destroy(p);

    // Spawn the workload. No DYLD_INSERT_LIBRARIES — that's macOS; the
    // Linux LD_PRELOAD heap interceptor is a separate pillar. The workload is
    // the argv tail from workload_start (Linux rejects --pid, so it's present).
    const workload_cmd = std.mem.span(argv_vec[rc.workload_start]);
    const n_wargs = argv_vec.len - rc.workload_start - 1;
    const workload_args = try gpa.alloc([]const u8, n_wargs);
    defer gpa.free(workload_args);
    for (0..n_wargs) |k| workload_args[k] = std.mem.span(argv_vec[rc.workload_start + 1 + k]);
    const target = maybeSpawn(gpa, workload_cmd, workload_args, &.{
        "PERFETTO_PRODUCER_SOCK_NAME", prod_sock,
    }) orelse {
        std.debug.print("sismo record: failed to spawn '{s}' — exiting\n", .{workload_cmd});
        return;
    };
    std.debug.print("sismo record: spawned '{s}' pid={d}\n", .{ workload_cmd, target.pid });

    // BPF CPU collector: per-thread cycle/instruction counters + stack
    // sampling, scoped to the workload — the Linux CPU profiler. Drains on its
    // own worker thread; shut down (and report) on the way out via defer.
    const bpf = if (no_cpu)
        null
    else
        linux_bpf_capture.Capture.init(gpa, @intCast(target.pid), focus_preset, sample_density) catch |err| blk: {
            std.debug.print("sismo record: bpf capture init failed: {s} — CPU samples disabled\n", .{@errorName(err)});
            break :blk null;
        };
    defer if (bpf) |b| {
        const s = b.shutdown();
        std.debug.print(
            "sismo record: bpf — {d} samples across {d} threads (busiest {d} cycles)\n",
            .{ s.samples, s.threads, s.busiest_cycles },
        );
        // Cache focus: how many samples got a resolved data-region leaf frame.
        if (s.data_frames > 0) std.debug.print(
            "sismo record: cache — {d} of {d} samples carry a data-region frame\n",
            .{ s.data_frames, s.samples },
        );
    };

    // Build the TraceConfig in Zig. traced_probes gets the Perfetto-native
    // FtraceConfig nested submessage embedded inside the DataSourceConfig;
    // the BPF collector is a sismo vendor data source — see perfetto_proto.zig.
    var entries_buf: [3]DataSourceEntryC = undefined;
    var n_entries: usize = 0;
    if (!no_instrumentation) {
        entries_buf[n_entries] = dsTrackEvent();
        n_entries += 1;
    }
    if (probes != null) {
        // ftrace stays system-wide because traced_probes can't filter
        // by pid. trace_processor handles separating the workload's
        // events out post-hoc.
        entries_buf[n_entries] = dsLinuxFtrace();
        n_entries += 1;
    }
    // The in-process BPF collector emits thread-scoped PerfSamples via its own
    // producer; traced only activates it if the config names it.
    if (bpf != null) {
        entries_buf[n_entries] = dsSismoVendor(linux_bpf_capture.DS_NAME, "", 0);
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
    const out_path: []const u8 = if (flight_recorder) "" else output_path;
    const session_name = "sismo_record";
    var cfg_buf: [16384]u8 = undefined;
    const cfg_len = sismo_encode_trace_config(
        if (flight_recorder) 0 else 2, // ring : file
        buffer_kb,
        0, // duration_ms (capped mode only)
        out_path.ptr,
        out_path.len,
        1024 * 1024 * 1024,
        session_name.ptr,
        session_name.len,
        entries.ptr,
        entries.len,
        &cfg_buf,
        cfg_buf.len,
    );
    if (cfg_len == 0) {
        std.debug.print("sismo record: encodeTraceConfig failed (config exceeds buffer)\n", .{});
        return;
    }
    const cfg_bytes = cfg_buf[0..cfg_len];

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

    // Self-pipe wait loop, identical to the macOS path.
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
        .mode = .spawn, // attach mode not yet supported on Linux
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

    // Stop the session. The producers' on_stop callbacks fire on their
    // own threads; once stop_blocking returns, the trace is flushed (FILE
    // mode) or sitting in the ring (flight mode).
    c.sismo_consumer_session_stop_blocking(session);
    if (flight_recorder) {
        std.debug.print("sismo record: flight-recorder stopped (buffer discarded; use `sismo snapshot` before stopping to capture)\n", .{});
    } else {
        std.debug.print("sismo record: trace saved to {s}\n", .{output_path});
        // TODO: replace with JSON-in-zip sidecar.
        const focus_name: ?[]const u8 =
            if (focus_preset) |p| focus_presets.presetName(p) else null;
        // Honest precision: only claim PEBS if the sampler actually got it.
        const focus_precise = if (bpf) |b| b.sampler_precise_ip >= 2 else false;
        const pids = [_]i32{@intCast(target.pid)};
        const fp_ptr: ?[*]const u8 = if (focus_name) |f| f.ptr else null;
        const fp_len: usize = if (focus_name) |f| f.len else 0;
        if (!sismo_append_privileged_marker(output_path.ptr, output_path.len, &pids, pids.len, fp_ptr, fp_len, focus_precise)) {
            std.debug.print("sismo record: failed to write privileged marker\n", .{});
        }
        // Resolve perf sample frames to function names. The BPF collector
        // records them unsymbolized; this appends ModuleSymbols for the UI to join.
        if (bpf != null) sismo_symbolize_trace(output_path.ptr, output_path.len);
    }

    // Tear-down runs via defer LIFO (probes.destroy → traced.destroy):
    // each destroy() quits the producer's TaskRunner and joins its worker
    // thread, so producers fully detach before the service tears down.
    traced.stop(svc);
}
