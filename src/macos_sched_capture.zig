// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! In-process kdebug → `sismo.macos_sched` producer.
//!
//! Muxer pattern (shared by all sismo producers): `init()` spawns one
//! worker thread that owns all state and does the heavy setup (buffers,
//! mach_timebase, kdebug session) on its own stack, then loops. The
//! worker is the sole consumer of state, so no mutex is needed — only a
//! few atomic flags. Between drains it blocks on
//! `wakeup_event.waitTimeout(io, drain_interval)`: O(drain_interval)
//! latency on a normal cycle, ~0 on stop/shutdown, no busy poll.
//!
//! Trampolines (Perfetto IO thread) each set the wakeup event: onStart
//! sets running=true, onStop stores the stopper handle, onFlush acks
//! inline (kdebug has no buffered state), shutdown() sets exit=true.

const std = @import("std");
const builtin = @import("builtin");
const kdebug = @import("macos/kdebug.zig");
const process_tree = @import("macos/process_tree.zig");
const sismo_config = @import("sismo_config.zig");
const perfetto_proto = @import("perfetto_proto.zig");
const ProtoWriter = @import("proto_writer.zig").ProtoWriter;

const perfetto = @cImport({
    @cInclude("src/c/perfetto_shim.h");
});

const DS_NAME = "sismo.macos_sched";

// Per-tid cache entry. `pid` identifies the owning process when the cache
// was populated; a later threadmap snapshot reporting a different pid for
// the same tid invalidates it (pid reuse — mach tids don't reuse, but the
// (tid, pid) pair can if the owner exits, the pid is reassigned, and a new
// thread lands on the same tid value: vanishingly rare, not impossible).
const ThreadEntry = struct {
    pid: i32,
    name_buf: [64]u8,
    name_len: u8,

    fn name(self: *const ThreadEntry) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

// Per-pid cache entry. cmdline_buf holds the proc_pidpath result;
// cmdline_len is its byte length. Empty cmdline = pidpath failed
// (kernel-only or zombie pid) — still cached to avoid retrying.
const ProcessEntry = struct {
    ppid: i32,
    cmdline_buf: [process_tree.MAXPATHLEN]u8,
    cmdline_len: u16,

    fn cmdline(self: *const ProcessEntry) []const u8 {
        return self.cmdline_buf[0..self.cmdline_len];
    }
};

// First-seen cache: a Thread / Process entry is emitted into the
// GenericKernelProcessTree packet only on the drain that first observed
// it; later drains hit the cache and skip the emit. trace_processor's
// process tree is incremental — repeating entries is harmless but wasteful.
const ProcessTreeCache = struct {
    threads: std.AutoHashMapUnmanaged(u64, ThreadEntry),
    processes: std.AutoHashMapUnmanaged(i32, ProcessEntry),

    fn init() ProcessTreeCache {
        return .{ .threads = .empty, .processes = .empty };
    }

    fn deinit(self: *ProcessTreeCache, gpa: std.mem.Allocator) void {
        self.threads.deinit(gpa);
        self.processes.deinit(gpa);
    }
};

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

    /// Per-drain staging buffer, in events. Sized to match
    /// `kernel_buffer_events` so one `KDREADTR` drains everything.
    /// Undersizing leaves a residue that grows when the worker lags;
    /// once it exceeds kernel_buffer_events the kernel overwrites its
    /// oldest queued events mid-cycle, showing as 100s-of-ms timeline gaps.
    drain_capacity_events: usize = 256 * 1024,

    /// Capacity for the per-drain thread-map snapshot.
    thread_map_capacity: usize = 16 * 1024,
};

pub const Stats = struct {
    events_emitted: u64,
    drain_calls: u64,
};

/// xnu emits each context switch as TWO kdebug events on the same CPU:
///   - MACH_SCHED (or MACH_STACK_HANDOFF), in `thread_invoke` BEFORE the
///     register switch: timestamp, both TIDs, both priorities — but NOT
///     the outgoing thread's finalized `thread->state`.
///   - MACH_DISPATCH, in `thread_dispatch` AFTER the switch: the outgoing
///     TID and its finalized state bits (TH_WAIT/TH_SUSP/TH_UNINT/...).
///
/// The MACH_SCHED half is buffered here keyed by `cpuid`; the matching
/// MACH_DISPATCH on the same CPU completes the pair. Per-CPU (not per-TID)
/// because kdebug guarantees per-CPU ordering with at most one switch in
/// flight per CPU. Must persist across drains — a drain can split the pair.
pub const PendingSwitch = struct {
    valid: bool = false,
    timestamp: u64 = 0,
    outgoing_tid: u64 = 0,
    outgoing_pri: u32 = 0,
    incoming_tid: u64 = 0,
    incoming_pri: u32 = 0,
};

/// Cap of distinct cpuids tracked. macOS tops out at ~32 logical CPUs
/// (M2 Ultra) plus a few IOP cpuids, so 256 is comfortably oversized;
/// events on out-of-range cpuids are dropped.
pub const MAX_CPUS: usize = 256;

pub const Capture = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    /// Slot handle returned by `sismo_ds_register`. Used as the first
    /// arg of every `sismo_ds_emit` call in the worker.
    ds_slot: u32,
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

    pending_switches: [MAX_CPUS]PendingSwitch,

    /// Process / thread name cache, populated lazily from
    /// `proc_pidinfo` and emitted as `GenericKernelProcessTree`
    /// deltas. Owned by the worker thread — never accessed from
    /// trampolines or shutdown caller.
    pt_cache: ProcessTreeCache,

    /// Reusable scratch buffers for the per-event encode path. After
    /// warm-up these grow to peak event/packet size and stay there;
    /// each emit is `clear()` + writes-into instead of an
    /// alloc/free pair through the gpa. With 50K+ events/s and
    /// DebugAllocator's stack-trace tracking, the alloc churn alone
    /// was costing 200 µs per event and letting the kernel kdebug
    /// ring overflow.
    event_scratch: ProtoWriter,
    packet_scratch: ProtoWriter,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        config: Config,
    ) !*Capture {
        const event_buf = try allocator.alloc(kdebug.KdBuf, config.drain_capacity_events);
        errdefer allocator.free(event_buf);
        const thread_map_buf = try allocator.alloc(kdebug.KdThreadMap, config.thread_map_capacity);
        errdefer allocator.free(thread_map_buf);
        @memset(thread_map_buf, std.mem.zeroes(kdebug.KdThreadMap));

        const self = try allocator.create(Capture);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .io = io,
            .ds_slot = std.math.maxInt(u32), // set after register
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
            .pending_switches = [_]PendingSwitch{.{}} ** MAX_CPUS,
            .pt_cache = .init(),
            .event_scratch = .init(allocator),
            .packet_scratch = .init(allocator),
        };

        // Register the data source via the new C++-SDK-backed shim.
        // The returned slot index keys every later `sismo_ds_emit` call.
        // The descriptor carries a ProtoVM program that mirrors the
        // GenericKernelProcessTree packets into per-buffer DST state:
        // traced applies it to overwritten packets in ring/flight mode and
        // surfaces the DST at trace-read time. Inert in file mode (no
        // overwrites).
        const protovm_program = try perfetto_proto.macosSchedVmProgram(allocator);
        defer allocator.free(protovm_program);
        const desc_bytes = try perfetto_proto.encodeDataSourceDescriptor(
            allocator,
            .{
                .name = DS_NAME,
                .will_notify_on_stop = true,
                .protovm_program = protovm_program,
            },
        );
        defer allocator.free(desc_bytes);
        const slot = perfetto.sismo_ds_register(
            desc_bytes.ptr,
            desc_bytes.len,
            onSetupTrampoline,
            onStartTrampoline,
            onStopTrampoline,
            onFlushTrampoline,
            self,
        );
        if (slot == std.math.maxInt(u32)) return error.PerfettoDsRegisterFailed;
        self.ds_slot = slot;

        self.thread = try std.Thread.spawn(.{}, workerEntry, .{self});
        return self;
    }

    /// Invoked from traced's IO thread at DS setup. `dsc_bytes` is the
    /// serialized `DataSourceConfig`; the vendor extension (field 2000)
    /// carries the macos_sched config decoded here.
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
        if (flusher) |f| perfetto.sismo_flush_done(f);
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
        self.pt_cache.deinit(self.allocator);
        self.event_scratch.deinit();
        self.packet_scratch.deinit();
        self.allocator.destroy(self);
        return stats;
    }
};

fn workerEntry(self: *Capture) void {
    // Wait for on_setup (or shutdown). on_setup carries the consumer's
    // SismoMacosSchedConfig, which may override producer-side defaults —
    // so the kdebug session isn't brought up with a stale buffer size.
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
            perfetto.sismo_stop_done(@ptrFromInt(stopper_addr));
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
    var t0: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &t0);

    const n_evt = kdebug.Capture.drain(self.event_buf) catch 0;
    var t_drain: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &t_drain);

    const n_thr = kdebug.Capture.readThreadMap(self.thread_map_buf) catch 0;
    const thread_map = self.thread_map_buf[0..n_thr];

    // Refresh process / thread name cache from the threadmap and emit a
    // GenericKernelProcessTree delta for any newly-observed pids/tids.
    // Done before emitBatch so the emitted sched events can use the
    // freshly cached pth_name in their `comm` field.
    refreshAndEmitTree(self, thread_map);
    var t_refresh: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &t_refresh);

    const emitted = emitBatch(
        self.event_buf[0..n_evt],
        thread_map,
        &self.pt_cache,
        self.ds_slot,
        &self.event_scratch,
        &self.packet_scratch,
        self.tb_n,
        self.tb_d,
        &self.pending_switches,
    );
    var t_end: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &t_end);

    _ = self.events_emitted.fetchAdd(emitted, .monotonic);
    const drain_idx = self.drain_calls.fetchAdd(1, .monotonic);

    // Diagnostic logging: first cycle only (cold-cache warm-up), plus any
    // cycle where the kernel ring saturated (`n_evt` near the buffer cap =
    // events overwritten before being read, the cause of multi-hundred-ms
    // timeline gaps). Steady-state cycles are silent.
    const overflow_threshold = @as(usize, @intCast(self.config.kernel_buffer_events)) * 9 / 10;
    if (drain_idx == 0 or n_evt >= overflow_threshold) {
        const drain_ns = nsBetween(t0, t_drain);
        const refresh_ns = nsBetween(t_drain, t_refresh);
        const emit_ns = nsBetween(t_refresh, t_end);
        const tag: []const u8 = if (n_evt >= overflow_threshold) "[ring near-full]" else "";
        std.debug.print(
            "macos_sched: drain[{d}] evt={d} thr={d} emit={d}  drain={d}us refresh={d}us emit={d}us {s}\n",
            .{ drain_idx, n_evt, n_thr, emitted, drain_ns / 1000, refresh_ns / 1000, emit_ns / 1000, tag },
        );
    }
}

fn nsBetween(a: std.c.timespec, b: std.c.timespec) u64 {
    const a_ns: i128 = @as(i128, a.sec) * std.time.ns_per_s + a.nsec;
    const b_ns: i128 = @as(i128, b.sec) * std.time.ns_per_s + b.nsec;
    if (b_ns <= a_ns) return 0;
    return @intCast(b_ns - a_ns);
}

/// Walk the kdebug threadmap, populate the per-tid + per-pid name cache
/// for new entries via `proc_pidinfo`, and emit one
/// `GenericKernelProcessTree` packet listing the deltas.
///
/// Cache key = mach thread id (`KdThreadMap.thread`), which xnu allocates
/// from a 64-bit monotonic counter and never reuses system-wide, so a hit
/// always points at the same thread. Pids DO reuse, but only after the
/// prior owner is reaped — rare within a ~minutes recording, accepted for
/// v0. (A future patch could subscribe to BSD_PROC_EXIT for fast
/// invalidation.)
fn refreshAndEmitTree(self: *Capture, thread_map: []const kdebug.KdThreadMap) void {
    const gpa = self.allocator;

    // Per-emit arena. Each new entry's name/cmdline is dup'd here so the
    // slices in new_threads_buf / new_processes_buf outlive the loop
    // iteration. Without it they alias `entry`/`pe` — locals whose stack
    // slot the compiler reuses each iteration — so by emit time every slice
    // points at the LAST iteration's content (seen in the wild as cross-
    // contaminated cmdlines/comms in traceconv). Freed at function exit.
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    // Stack-bounded staging for new entries this drain. A drain rarely
    // surfaces more than a few new threads, so these caps are generous;
    // overflow is silently truncated and picked up next drain.
    var new_threads_buf: [256]perfetto_proto.ThreadEntry = undefined;
    var n_new_threads: usize = 0;
    var new_processes_buf: [128]perfetto_proto.ProcessEntry = undefined;
    var n_new_processes: usize = 0;

    for (thread_map) |*t| {
        if (t.thread == 0 or t.pid <= 0) continue;
        const tid = t.thread;
        const pid: i32 = @intCast(t.pid);

        const t_gop = self.pt_cache.threads.getOrPut(gpa, tid) catch continue;
        if (t_gop.found_existing and t_gop.value_ptr.pid == pid) continue;

        // New tid (or pid changed — reuse). Re-query proc_pidinfo for the
        // pth_name; fall back to the threadmap comm if it returns nothing.
        var name_buf: [64]u8 = undefined;
        const fetched = process_tree.threadName(pid, tid, &name_buf);
        const name: []const u8 = if (fetched) |n|
            n
        else
            std.mem.sliceTo(&t.command, 0);

        var entry: ThreadEntry = .{
            .pid = pid,
            .name_buf = undefined,
            .name_len = 0,
        };
        const cap_n: u8 = @intCast(@min(name.len, entry.name_buf.len));
        entry.name_len = cap_n;
        @memcpy(entry.name_buf[0..cap_n], name[0..cap_n]);
        t_gop.value_ptr.* = entry;

        if (n_new_threads < new_threads_buf.len) {
            const comm_dup = a.dupe(u8, name[0..cap_n]) catch continue;
            new_threads_buf[n_new_threads] = .{
                .tid = @intCast(tid),
                .pid = pid,
                .comm = comm_dup,
            };
            n_new_threads += 1;
        }

        // New pid? Look up its bsdinfo (ppid) and proc_pidpath (cmdline).
        const p_gop = self.pt_cache.processes.getOrPut(gpa, pid) catch continue;
        if (p_gop.found_existing) continue;

        var pe: ProcessEntry = .{ .ppid = 0, .cmdline_buf = undefined, .cmdline_len = 0 };
        if (process_tree.bsdinfo(pid)) |bi| pe.ppid = @intCast(bi.pbi_ppid);
        if (process_tree.pidPath(pid, &pe.cmdline_buf)) |path| {
            // proc_pidpath's return length includes the NUL
            // terminator; drop it (and any other trailing NULs)
            // before storing so trace_processor renders the cmdline
            // cleanly.
            const trimmed = std.mem.sliceTo(path, 0);
            pe.cmdline_len = @intCast(trimmed.len);
        }
        p_gop.value_ptr.* = pe;

        if (n_new_processes < new_processes_buf.len) {
            const cmdline_dup = a.dupe(u8, pe.cmdline()) catch continue;
            new_processes_buf[n_new_processes] = .{
                .pid = pid,
                .ppid = pe.ppid,
                .cmdline = cmdline_dup,
            };
            n_new_processes += 1;
        }
    }

    if (n_new_threads == 0 and n_new_processes == 0) return;

    const tree_bytes = perfetto_proto.encodeKernelProcessTree(
        gpa,
        new_processes_buf[0..n_new_processes],
        new_threads_buf[0..n_new_threads],
    ) catch return;
    defer gpa.free(tree_bytes);

    const body = perfetto_proto.encodeTracePacketBody(
        gpa,
        0, // no per-packet timestamp; trace_processor reads ProcessTree
        // entries as time-independent metadata.
        0, // sequence_flags
        perfetto_proto.TP_FIELD_GENERIC_KERNEL_PROCESS_TREE,
        tree_bytes,
    ) catch return;
    defer gpa.free(body);
    perfetto.sismo_ds_emit(self.ds_slot, body.ptr, body.len);
}

/// Resolve a tid → comm. Cache hit (populated by `refreshAndEmitTree`)
/// returns the proc_pidinfo `pth_name`, else the kdebug threadmap's
/// 16-char `command`. Cache miss does a linear threadmap scan (slow path,
/// only on the first drain after a mid-recording spawn).
///
/// Uses `getPtr` (not `get`) so the slice aliases the hashmap's stable
/// storage, not a freshly-copied local that would die at return — the
/// source of early corrupt "\000…"/0xAA-padded comms.
fn lookupComm(
    threads: []const kdebug.KdThreadMap,
    cache: *ProcessTreeCache,
    tid: u64,
) []const u8 {
    if (cache.threads.getPtr(tid)) |entry| {
        if (entry.name_len > 0) return entry.name();
    }
    // Cache miss — fall back to the kdebug threadmap. Iterate by pointer:
    // by-value would copy the entry to a local and the returned
    // `sliceTo(&t.command, 0)` would alias it and dangle after return.
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
/// state_bits == 0 (TH_RUN cleared, no other bits) is "preempted, still
/// on the runqueue" → RUNNABLE. TH_RUN alone (0x04) is the same case
/// before `thread_dispatch` clears it for waiters; treat as RUNNABLE.
fn outgoingTaskState(state_bits: u32) perfetto_proto.TaskState {
    if (state_bits & 0x02 != 0) return .stopped;
    if (state_bits & 0x01 != 0) {
        return if (state_bits & 0x08 != 0) .uninterruptible_sleep else .interruptible_sleep;
    }
    return .runnable;
}

/// Build the GenericKernelTaskStateEvent payload + TracePacket wrapper
/// using the caller's persistent scratch writers, then emit via the
/// public C++ SDK shim. Both writers are `clear()`-ed at entry; after
/// warm-up their backing buffers are sized to the peak event/packet
/// size and incur zero allocations per call.
fn emitTaskState(
    slot: u32,
    event_w: *ProtoWriter,
    packet_w: *ProtoWriter,
    timestamp_ns: u64,
    cpu: i32,
    comm: []const u8,
    tid: i64,
    state: perfetto_proto.TaskState,
    prio: i32,
) void {
    event_w.clear();
    perfetto_proto.encodeKernelTaskStateEventInto(event_w, .{
        .cpu = cpu,
        .comm = comm,
        .tid = tid,
        .state = state,
        .prio = prio,
    }) catch return;
    packet_w.clear();
    perfetto_proto.encodeTracePacketBodyInto(
        packet_w,
        timestamp_ns,
        perfetto_proto.TP_FIELD_GENERIC_KERNEL_TASK_STATE,
        event_w.bytes(),
    ) catch return;
    perfetto.sismo_ds_emit(slot, packet_w.bytes().ptr, packet_w.bytes().len);
}

fn emitBatch(
    events: []const kdebug.KdBuf,
    thread_map: []const kdebug.KdThreadMap,
    cache: *ProcessTreeCache,
    ds_slot: u32,
    event_w: *ProtoWriter,
    packet_w: *ProtoWriter,
    tb_n: u64,
    tb_d: u64,
    pending: *[MAX_CPUS]PendingSwitch,
) u64 {
    var emitted: u64 = 0;
    for (events) |*e| {
        // Three DBG_MACH_SCHED codes matter:
        //   MACH_SCHED         (0x00) — preempted / scheduler choice
        //   MACH_STACK_HANDOFF (0x02) — voluntary yield (sync prims, IPC)
        //   MACH_DISPATCH      (0x20) — switch completed; carries the
        //                               OUTGOING thread's finalized state.
        // 0x00/0x02 carry timestamp + both TIDs + priorities, 0x20 the
        // outgoing state. They arrive strictly in that order per cpuid, so
        // the first half is buffered per-CPU and the Perfetto pair emitted
        // when the second arrives.
        const code = kdebug.extractCode(e.debugid);
        if (e.cpuid >= MAX_CPUS) continue;

        switch (code) {
            0x00, 0x02 => {
                const args = kdebug.MachSchedArgs.fromBuf(e);
                // Idle-loop self-switch — accounting marker that would
                // otherwise produce two emits at the same ts on the same
                // thread, tripping ThreadStateTracker.
                if (args.outgoing_tid == args.incoming_tid) continue;
                pending[e.cpuid] = .{
                    .valid = true,
                    .timestamp = e.timestamp,
                    .outgoing_tid = args.outgoing_tid,
                    .outgoing_pri = args.outgoing_pri,
                    .incoming_tid = args.incoming_tid,
                    .incoming_pri = args.incoming_pri,
                };
            },
            0x20 => {
                const args = kdebug.MachDispatchArgs.fromBuf(e);
                const slot = &pending[e.cpuid];
                if (!slot.valid) continue;
                // TID mismatch means the pair on this CPU broke (capture
                // started mid-switch, or a drain dropped events). Discard
                // the stale MACH_SCHED rather than mis-attribute state.
                if (slot.outgoing_tid != args.outgoing_tid) {
                    slot.valid = false;
                    continue;
                }

                const ts_ns = slot.timestamp *% tb_n / tb_d;
                const off_comm = lookupComm(thread_map, cache, slot.outgoing_tid);
                const off_state = outgoingTaskState(args.outgoing_state);
                emitTaskState(
                    ds_slot,
                    event_w,
                    packet_w,
                    ts_ns,
                    @intCast(e.cpuid),
                    off_comm,
                    @intCast(slot.outgoing_tid),
                    off_state,
                    @intCast(slot.outgoing_pri),
                );
                const on_comm = lookupComm(thread_map, cache, slot.incoming_tid);
                emitTaskState(
                    ds_slot,
                    event_w,
                    packet_w,
                    ts_ns,
                    @intCast(e.cpuid),
                    on_comm,
                    @intCast(slot.incoming_tid),
                    .running,
                    @intCast(slot.incoming_pri),
                );
                slot.valid = false;
                emitted += 2;
            },
            else => {},
        }
    }
    return emitted;
}
