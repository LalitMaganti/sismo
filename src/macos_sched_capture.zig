//! In-process kdebug → `sismo.macos_sched` producer.
//!
//! Lifecycle (the "muxer" pattern shared by all sismo producers):
//!
//!   process startup:
//!     `init()` spawns a single worker thread. The worker does the
//!     heavy setup (allocates buffers, queries mach_timebase, brings
//!     up the kernel kdebug session) on its own stack, then enters
//!     the main loop.
//!
//!   main loop:
//!     The worker is the only consumer of state — there's no
//!     contention between worker and trampolines beyond a few atomic
//!     flag updates, so no mutex is needed. Between drain cycles the
//!     worker calls `wakeup_event.waitTimeout(io, drain_interval)`,
//!     which blocks until either the timeout expires or someone
//!     calls `wakeup_event.set(io)`. That gives us O(drain_interval)
//!     latency on a normal cycle and ~0 latency on a stop / shutdown
//!     signal — no busy polling.
//!
//!   trampolines (called from Perfetto's IO thread):
//!     `onStartTrampoline`  — store running=true, set event.
//!     `onStopTrampoline`   — store stopper handle, set event.
//!     `onFlushTrampoline`  — kdebug emits continuously, no buffered
//!                            state; ack on the IO thread.
//!     `shutdown()` (orchestrator) — store exit=true, set event,
//!                                   join. The worker's next observe
//!                                   sees exit and returns.

const std = @import("std");
const builtin = @import("builtin");
const kdebug = @import("macos/kdebug.zig");
const sismo_config = @import("sismo_config.zig");

const perfetto = @cImport({
    @cInclude("perfetto_shim.h");
});

comptime {
    if (builtin.os.tag != .macos) @compileError("macos_sched_capture is macOS-only");
}

const MachTimebaseInfo = std.c.mach_timebase_info_data;

pub const Config = struct {
    /// kdebug kernel ring sizing, in events. The default 256K events ×
    /// 64 B/event = 16 MB of kernel memory; at the observed busy-system
    /// rate of ~50K events/s that's ~5s of headroom against a drain
    /// stall.
    kernel_buffer_events: c_int = 256 * 1024,

    /// Maximum gap between drains while RUNNING. The worker actually
    /// blocks on `wakeup_event.waitTimeout(io, .{.duration = ...})` so
    /// it wakes earlier on any signal.
    drain_interval_ns: u64 = 100 * std.time.ns_per_ms,

    /// Per-drain user-space staging buffer, in events.
    drain_capacity_events: usize = 16 * 1024,

    /// Capacity for the per-drain thread-map snapshot.
    thread_map_capacity: usize = 16 * 1024,
};

pub const Stats = struct {
    events_emitted: u64,
    drain_calls: u64,
};

pub const Capture = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    ds: *perfetto.struct_PerfettoDs,
    config: Config,

    // Wakeup primitive — the worker waits on it with a timeout
    // matching `drain_interval_ns`; trampolines and shutdown call
    // `set(io)` to wake it early.
    wakeup: std.Io.Event,

    // Single-writer/single-reader atomic signals from the IO thread
    // (or shutdown caller) to the worker. No mutex needed.
    running: std.atomic.Value(bool),
    exit_requested: std.atomic.Value(bool),
    pending_stopper: std.atomic.Value(usize),

    // on_setup populates `setup_config` then sets `setup_received`.
    // Worker reads after `setup_received` is true; the trampoline
    // never re-touches it once published. Single producer/consumer
    // ordering — release on the writer side, acquire on the reader,
    // no lock needed.
    setup_received: std.atomic.Value(bool),
    setup_config: sismo_config.macos_sched.Config,

    thread: ?std.Thread,
    setup_failed: std.atomic.Value(bool),
    torn_down: bool,

    event_buf: []kdebug.KdBuf,
    thread_map_buf: []kdebug.KdThreadMap,
    tb_n: u64,
    tb_d: u64,

    events_emitted: std.atomic.Value(u64),
    drain_calls: std.atomic.Value(u64),

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        ds_opaque: *anyopaque,
        config: Config,
    ) !*Capture {
        const ds: *perfetto.struct_PerfettoDs = @ptrCast(ds_opaque);

        const event_buf = try allocator.alloc(kdebug.KdBuf, config.drain_capacity_events);
        errdefer allocator.free(event_buf);
        const thread_map_buf = try allocator.alloc(kdebug.KdThreadMap, config.thread_map_capacity);
        errdefer allocator.free(thread_map_buf);
        @memset(thread_map_buf, std.mem.zeroes(kdebug.KdThreadMap));

        const self = try allocator.create(Capture);
        self.* = .{
            .allocator = allocator,
            .io = io,
            .ds = ds,
            .config = config,
            .wakeup = .unset,
            .running = std.atomic.Value(bool).init(false),
            .exit_requested = std.atomic.Value(bool).init(false),
            .pending_stopper = std.atomic.Value(usize).init(0),
            .setup_received = std.atomic.Value(bool).init(false),
            .setup_config = .{},
            .thread = null,
            .setup_failed = std.atomic.Value(bool).init(false),
            .torn_down = false,
            .event_buf = event_buf,
            .thread_map_buf = thread_map_buf,
            .tb_n = 1,
            .tb_d = 1,
            .events_emitted = std.atomic.Value(u64).init(0),
            .drain_calls = std.atomic.Value(u64).init(0),
        };
        self.thread = try std.Thread.spawn(.{}, workerEntry, .{self});
        return self;
    }

    /// Invoked from traced's IO thread when our DS is set up for a
    /// session. `dsc_bytes` is the serialized `DataSourceConfig`; we
    /// pull our vendor extension (field 2000) and decode the
    /// macos_sched config inside.
    pub fn onSetupTrampoline(
        user_arg: ?*anyopaque,
        dsc_bytes_ptr: ?*const anyopaque,
        dsc_bytes_size: usize,
    ) callconv(.c) void {
        const self: *Capture = @ptrCast(@alignCast(user_arg.?));
        const ds_bytes: []const u8 = if (dsc_bytes_ptr) |p|
            @as([*]const u8, @ptrCast(p))[0..dsc_bytes_size]
        else
            &[_]u8{};
        if (sismo_config.extractFromDataSourceConfig(ds_bytes)) |inner| {
            if (sismo_config.macos_sched.decode(inner)) |cfg| {
                self.setup_config = cfg;
            } else |_| {}
        }
        self.setup_received.store(true, .release);
        self.wakeup.set(self.io);
    }

    pub fn onStartTrampoline(user_arg: ?*anyopaque) callconv(.c) void {
        const self: *Capture = @ptrCast(@alignCast(user_arg.?));
        self.running.store(true, .release);
        self.wakeup.set(self.io);
    }

    pub fn onStopTrampoline(user_arg: ?*anyopaque, stopper: ?*anyopaque) callconv(.c) void {
        const self: *Capture = @ptrCast(@alignCast(user_arg.?));
        if (stopper) |s| self.pending_stopper.store(@intFromPtr(s), .release);
        self.wakeup.set(self.io);
    }

    /// kdebug emits continuously in the drain loop; nothing buffered to
    /// dump. Ack on the IO thread.
    pub fn onFlushTrampoline(user_arg: ?*anyopaque, flusher: ?*anyopaque) callconv(.c) void {
        _ = user_arg;
        if (flusher) |f| perfetto.sismo_perfetto_flush_done(f);
    }

    pub fn shutdown(self: *Capture) Stats {
        self.exit_requested.store(true, .release);
        self.wakeup.set(self.io);
        if (self.thread) |t| t.join();

        const stats: Stats = .{
            .events_emitted = self.events_emitted.load(.monotonic),
            .drain_calls = self.drain_calls.load(.monotonic),
        };
        if (!self.torn_down) {
            kdebug.Capture.tearDown();
            self.torn_down = true;
        }
        self.allocator.free(self.event_buf);
        self.allocator.free(self.thread_map_buf);
        self.allocator.destroy(self);
        return stats;
    }
};

fn workerEntry(self: *Capture) void {
    // Wait for on_setup (or shutdown). on_setup carries the
    // SismoMacosSchedConfig from the consumer, which may override
    // our producer-side defaults — we don't want to bring up the
    // kernel kdebug session with a stale buffer size.
    while (!self.exit_requested.load(.acquire) and !self.setup_received.load(.acquire)) {
        self.wakeup.reset();
        if (self.exit_requested.load(.acquire) or self.setup_received.load(.acquire)) break;
        self.wakeup.wait(self.io) catch {};
    }
    if (self.exit_requested.load(.acquire)) return;

    // Apply non-zero overrides from on_setup; fall back to producer
    // defaults otherwise.
    const setup = self.setup_config;
    const kernel_buffer_events: c_int = if (setup.kernel_buffer_events != 0)
        setup.kernel_buffer_events
    else
        self.config.kernel_buffer_events;

    // ---- Heavy setup (on the worker thread, not the caller's) ----
    var tb: MachTimebaseInfo = .{ .numer = 1, .denom = 1 };
    _ = std.c.mach_timebase_info(&tb);
    self.tb_n = tb.numer;
    self.tb_d = tb.denom;

    kdebug.Capture.start(kernel_buffer_events) catch |err| {
        std.debug.print("macos_sched_capture: kdebug.start failed: {s}\n", .{@errorName(err)});
        self.setup_failed.store(true, .release);
    };

    while (true) {
        // Reset BEFORE reading flags so any signal from a trampoline
        // (which writes a flag and then calls `wakeup.set`) is either
        // observed by this iteration's reads or wakes the next
        // `waitTimeout`. Not both, but never neither.
        self.wakeup.reset();

        if (self.exit_requested.load(.acquire)) return;

        if (self.running.load(.acquire) and !self.setup_failed.load(.acquire)) {
            drainOnce(self);
        }

        // Stop signal: do a final drain (catches anything between the
        // last periodic drain and the stop), ack the postponed
        // stopper, return to IDLE so a subsequent session can come in.
        const stopper_addr = self.pending_stopper.swap(0, .acq_rel);
        if (stopper_addr != 0) {
            if (!self.setup_failed.load(.acquire)) drainOnce(self);
            perfetto.sismo_perfetto_stop_done(@ptrFromInt(stopper_addr));
            self.running.store(false, .release);
        }

        // Re-check exit in case it was raised during the drain or
        // emit work above.
        if (self.exit_requested.load(.acquire)) return;

        // Sleep with timeout (RUNNING) or unbounded (IDLE). Either
        // wakes immediately on the next `wakeup.set`.
        if (self.running.load(.acquire)) {
            self.wakeup.waitTimeout(self.io, .{ .duration = .{
                .raw = .fromNanoseconds(@intCast(self.config.drain_interval_ns)),
                .clock = .awake,
            } }) catch {};
        } else {
            self.wakeup.wait(self.io) catch {};
        }
    }
}

fn drainOnce(self: *Capture) void {
    const n_evt = kdebug.Capture.drain(self.event_buf) catch 0;
    const n_thr = kdebug.Capture.readThreadMap(self.thread_map_buf) catch 0;
    const emitted = emitBatch(
        self.event_buf[0..n_evt],
        self.thread_map_buf[0..n_thr],
        self.ds,
        self.tb_n,
        self.tb_d,
    );
    _ = self.events_emitted.fetchAdd(emitted, .monotonic);
    _ = self.drain_calls.fetchAdd(1, .monotonic);
}

fn lookupComm(threads: []const kdebug.KdThreadMap, tid: u64) []const u8 {
    // Iterate by pointer — capturing by value would copy the entry onto
    // the local stack, and the returned `sliceTo(&t.command, 0)` would
    // alias that local copy and dangle once we return.
    for (threads) |*t| {
        if (t.thread == tid) return std.mem.sliceTo(&t.command, 0);
    }
    return "?";
}

/// xnu thread-state bits (TH_*) → Perfetto TaskStateEnum, for the OUTGOING
/// thread of a context switch. Incoming is always RUNNING.
///
/// Ignores TH_TERMINATE / TH_TERMINATE2: those mean "marked for future
/// destruction" but the thread still cycles through normal scheduler
/// states during teardown. Mapping them to DEAD poisons
/// trace_processor's per-thread state machine — DEAD is terminal,
/// every later sched event becomes generic_task_state_invalid_order.
/// state_bits == 0 is "preempted, still on the runqueue" → RUNNABLE.
fn outgoingTaskState(state_bits: u32) perfetto.SismoTaskState {
    if (state_bits & 0x02 != 0) return perfetto.SISMO_TASK_STATE_STOPPED;
    if (state_bits & 0x01 != 0) {
        return if (state_bits & 0x08 != 0)
            perfetto.SISMO_TASK_STATE_UNINTERRUPTIBLE_SLEEP
        else
            perfetto.SISMO_TASK_STATE_INTERRUPTIBLE_SLEEP;
    }
    return perfetto.SISMO_TASK_STATE_RUNNABLE;
}

fn emitBatch(
    events: []const kdebug.KdBuf,
    thread_map: []const kdebug.KdThreadMap,
    ds: *perfetto.struct_PerfettoDs,
    tb_n: u64,
    tb_d: u64,
) u64 {
    var emitted: u64 = 0;
    for (events) |*e| {
        // Two event types describe a context switch:
        //   MACH_SCHED          (code 0x0) — preempted / scheduler choice
        //   MACH_STACK_HANDOFF  (code 0x2) — voluntary yield (sync prims,
        //                                    fast IPC). Outgoing state is
        //                                    implicit RUNNABLE.
        const code = kdebug.extractCode(e.debugid);
        if (code != 0 and code != 0x2) continue;
        const args = kdebug.MachSchedArgs.fromBuf(e);
        // Idle-loop self-switch — accounting marker that would
        // otherwise produce two emits at the same ts on the same
        // thread, tripping ThreadStateTracker.
        if (args.outgoing_tid == args.incoming_tid) continue;

        const ts_ns = e.timestamp *% tb_n / tb_d;
        const off_comm = lookupComm(thread_map, args.outgoing_tid);
        const off_state: perfetto.SismoTaskState = if (code == 0x2)
            perfetto.SISMO_TASK_STATE_RUNNABLE
        else
            outgoingTaskState(args.outgoing_state);
        _ = perfetto.sismo_perfetto_ds_emit_kernel_task_state(
            ds,
            ts_ns,
            @intCast(e.cpuid),
            off_comm.ptr,
            off_comm.len,
            @intCast(@as(i64, @intCast(args.outgoing_tid))),
            off_state,
            @intCast(args.outgoing_pri),
        );
        const on_comm = lookupComm(thread_map, args.incoming_tid);
        _ = perfetto.sismo_perfetto_ds_emit_kernel_task_state(
            ds,
            ts_ns,
            @intCast(e.cpuid),
            on_comm.ptr,
            on_comm.len,
            @intCast(@as(i64, @intCast(args.incoming_tid))),
            perfetto.SISMO_TASK_STATE_RUNNING,
            0,
        );
        emitted += 2;
    }
    return emitted;
}
