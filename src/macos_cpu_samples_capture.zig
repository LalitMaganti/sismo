// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! In-process Mach CPU sampler → `sismo.macos_cpu_samples` producer.
//!
//! Periodic stack sampler driven by the muxer pattern (see
//! `macos_sched_capture.zig` for the full lifecycle doc). Single worker
//! thread does heavy Mach setup (`task_for_pid`, image enumeration,
//! framehop module registration) at process startup, then sleeps on
//! a `std.Io.Event.waitTimeout` between samples — wakes on the
//! sample interval OR on a signal from a trampoline / shutdown.
//!
//! Per-sample: read accumulated CPU time, skip the unwind on idle
//! threads, otherwise suspend → grab registers → walk the FP chain
//! via framehop → resume. Emits `PerfSample` packets continuously
//! (no buffered state), so on_flush is a no-op.

const std = @import("std");
const builtin = @import("builtin");
const sampler = @import("macos/mach_sampler.zig");
const dyld_images = @import("macos/dyld_images.zig");
const unwinder = @import("unwinder.zig");
const sismo_config = @import("sismo_config.zig");
const perfetto_proto = @import("perfetto_proto.zig");

const perfetto = @cImport({
    @cInclude("src/c/perfetto_shim.h");
});

// rust-bridge/src/proto.rs — see rust-bridge/include/bridge.h.
extern fn sismo_encode_perf_sample(
    cpu: u32,
    pid: u32,
    tid: u32,
    callstack_iid: u64,
    timebase_count: u64,
    follower_counts: ?[*]const u64,
    follower_count: usize,
    data_address: u64,
    data_symbol: ?[*]const u8,
    data_symbol_len: usize,
    out: [*]u8,
    cap: usize,
) usize;

const DS_NAME = "sismo.macos_cpu_samples";

comptime {
    if (builtin.os.tag != .macos) @compileError("cpu_sampler is macOS-only");
}

fn nowMonotonicNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

const MAX_FRAMES = 32;

pub const Config = struct {
    /// Producer-side default sampling period. on_setup may override
    /// via SismoMacosCpuSamplesConfig.interval_us. 1 kHz matches samply.
    interval_ns: u64 = std.time.ns_per_ms,
};

pub const Stats = struct {
    samples: u64,
    active_samples: u64,
};

const ThreadState = struct {
    thread: sampler.thread_t,
    tid: u64,
    last_cpu_us: u64,
};

const ReadCtx = struct { task: sampler.task_t };

fn readStackCb(addr: u64, out: *u64, user_data: ?*anyopaque) callconv(.c) c_int {
    const ctx: *const ReadCtx = @ptrCast(@alignCast(user_data.?));
    const got = sampler.vmReadInto(ctx.task, addr, std.mem.asBytes(out)) catch return 1;
    if (got < @sizeOf(u64)) return 1;
    return 0;
}

pub const Capture = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    /// Slot handle returned by `sismo_ds_register`.
    ds_slot: u32,
    config: Config,

    wakeup: std.Io.Event,
    running: std.atomic.Value(bool),
    exit_requested: std.atomic.Value(bool),
    pending_stopper: std.atomic.Value(usize),

    setup_received: std.atomic.Value(bool),
    setup_config: sismo_config.macos_cpu_samples.Config,

    /// Resolved target_pid (from on_setup, after applying defaults).
    /// Read by `sampleOnce` to stamp emitted PerfSamples. Written
    /// once by the worker after on_setup, before the running loop;
    /// the trampolines only ever touch `setup_config`.
    target_pid: c_int,

    thread: ?std.Thread,

    samples: std.atomic.Value(u64),
    active_samples: std.atomic.Value(u64),

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        config: Config,
    ) !*Capture {
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
            .target_pid = 0,
            .thread = null,
            .samples = std.atomic.Value(u64).init(0),
            .active_samples = std.atomic.Value(u64).init(0),
        };

        // Descriptor built in Zig, registered via the C++ SDK; the
        // returned slot keys every `sismo_ds_emit` call.
        const desc_bytes = try perfetto_proto.encodeDataSourceDescriptor(
            allocator,
            .{ .name = DS_NAME, .will_notify_on_stop = true },
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

    /// Decode SismoMacosCpuSamplesConfig from the consumer-supplied
    /// DataSourceConfig and publish to the worker.
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
            if (sismo_config.macos_cpu_samples.decode(inner)) |cfg| {
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

    /// Emits happen synchronously inside the sampling loop; nothing
    /// buffered. Ack on the IO thread.
    pub fn onFlushTrampoline(user_arg: ?*anyopaque, flusher: ?*anyopaque) callconv(.c) void {
        _ = user_arg;
        if (flusher) |f| perfetto.sismo_flush_done(f);
    }

    pub fn shutdown(self: *Capture) Stats {
        self.exit_requested.store(true, .release);
        self.wakeup.set(self.io);
        if (self.thread) |t| t.join();
        const stats: Stats = .{
            .samples = self.samples.load(.monotonic),
            .active_samples = self.active_samples.load(.monotonic),
        };
        self.allocator.destroy(self);
        return stats;
    }
};

fn exitRequestedAbort(ctx: ?*anyopaque) bool {
    const self: *Capture = @ptrCast(@alignCast(ctx.?));
    return self.exit_requested.load(.acquire);
}

fn workerEntry(self: *Capture) void {
    // Wait for on_setup: `task_for_pid` can't run until the consumer's
    // SismoMacosCpuSamplesConfig.target_pid arrives.
    while (!self.exit_requested.load(.acquire) and !self.setup_received.load(.acquire)) {
        self.wakeup.reset();
        if (self.exit_requested.load(.acquire) or self.setup_received.load(.acquire)) break;
        self.wakeup.wait(self.io) catch {};
    }
    if (self.exit_requested.load(.acquire)) return;

    const setup = self.setup_config;
    const target_pid: c_int = @intCast(setup.target_pid);
    const interval_ns: u64 = if (setup.interval_us != 0)
        @as(u64, setup.interval_us) * std.time.ns_per_us
    else
        self.config.interval_ns;

    if (target_pid == 0) {
        std.debug.print("cpu_sampler: SismoMacosCpuSamplesConfig.target_pid not set — bailing\n", .{});
        parkUntilExit(self);
        return;
    }
    self.target_pid = target_pid;

    // ---- Heavy setup phase ---------------------------------------------
    const task = sampler.taskForPid(target_pid) catch |err| {
        std.debug.print(
            "cpu_sampler: task_for_pid({d}) failed: {s} — need sudo or the\n" ++
                "  com.apple.security.cs.debugger entitlement.\n",
            .{ target_pid, @errorName(err) },
        );
        parkUntilExit(self);
        return;
    };

    // Retry on EmptyImageList — the target was just `posix_spawn`'d and
    // its `dyld_all_image_infos` may not be populated for a brief
    // window even though `task_for_pid` already succeeded.
    const target_images = dyld_images.enumerateImagesWaitReady(
        task,
        self.allocator,
        50 * std.time.ns_per_ms,
        5 * std.time.ns_per_s,
        @ptrCast(self),
        exitRequestedAbort,
    ) catch |err| {
        std.debug.print("cpu_sampler: enumerateImagesWaitReady failed: {s}\n", .{@errorName(err)});
        parkUntilExit(self);
        return;
    };
    defer dyld_images.freeImages(self.allocator, target_images);
    std.mem.sort(dyld_images.Image, target_images, {}, struct {
        fn lt(_: void, a: dyld_images.Image, b: dyld_images.Image) bool {
            return a.base_avma < b.base_avma;
        }
    }.lt);

    const u = unwinder.create() catch |err| {
        std.debug.print("cpu_sampler: unwinder.create failed: {s}\n", .{@errorName(err)});
        parkUntilExit(self);
        return;
    };
    defer unwinder.destroy(u);
    for (target_images) |*img| {
        const image = dyld_images.readImageMachO(task, img.base_avma, self.allocator) catch continue;
        defer self.allocator.free(image.bytes);
        unwinder.addModule(u, img.base_avma, image.bytes) catch continue;
    }

    var thread_states = std.AutoHashMap(sampler.thread_t, ThreadState).init(self.allocator);
    defer thread_states.deinit();
    var read_ctx = ReadCtx{ .task = task };
    // De-spam threadList failures — when the target exits the worker
    // keeps trying every interval until on_stop arrives, which is
    // hundreds of failed calls per shutdown. Print only on edge
    // (success → fail), suppress the rest.
    var threadlist_was_ok: bool = true;

    // ---- Main loop -----------------------------------------------------
    while (true) {
        self.wakeup.reset();

        if (self.exit_requested.load(.acquire)) return;

        if (self.running.load(.acquire)) {
            const threads = sampler.threadList(task) catch |err| blk: {
                if (threadlist_was_ok) {
                    std.debug.print("cpu_sampler: threadList failed: {s} (suppressing further occurrences until recovery)\n", .{@errorName(err)});
                    threadlist_was_ok = false;
                }
                break :blk null;
            };
            if (threads) |thr| {
                if (!threadlist_was_ok) {
                    std.debug.print("cpu_sampler: threadList recovered\n", .{});
                    threadlist_was_ok = true;
                }
                for (thr) |t| {
                    const ts = getOrInit(&thread_states, t) catch continue;
                    sampleOnce(self, ts, u, &read_ctx);
                }
                sampler.freeThreadList(task, thr);
            }
        }

        const stopper_addr = self.pending_stopper.swap(0, .acq_rel);
        if (stopper_addr != 0) {
            perfetto.sismo_stop_done(@ptrFromInt(stopper_addr));
            self.running.store(false, .release);
        }

        if (self.exit_requested.load(.acquire)) return;

        if (self.running.load(.acquire)) {
            self.wakeup.waitTimeout(self.io, .{ .duration = .{
                .raw = .fromNanoseconds(@intCast(interval_ns)),
                .clock = .awake,
            } }) catch {};
        } else {
            self.wakeup.wait(self.io) catch {};
        }
    }
}

/// Setup-failure path: park honoring stop and exit so the
/// orchestrator's `shutdown()` still joins cleanly.
fn parkUntilExit(self: *Capture) void {
    while (true) {
        self.wakeup.reset();
        if (self.exit_requested.load(.acquire)) return;
        const stopper_addr = self.pending_stopper.swap(0, .acq_rel);
        if (stopper_addr != 0) {
            perfetto.sismo_stop_done(@ptrFromInt(stopper_addr));
            self.running.store(false, .release);
        }
        if (self.exit_requested.load(.acquire)) return;
        self.wakeup.wait(self.io) catch {};
    }
}

fn getOrInit(
    map: *std.AutoHashMap(sampler.thread_t, ThreadState),
    thread: sampler.thread_t,
) !*ThreadState {
    const gop = try map.getOrPut(thread);
    if (!gop.found_existing) {
        const tid = sampler.threadId(thread) catch 0;
        const cpu = sampler.threadCpuTimeUs(thread) catch 0;
        gop.value_ptr.* = .{
            .thread = thread,
            .tid = tid,
            .last_cpu_us = cpu,
        };
    }
    return gop.value_ptr;
}

fn sampleOnce(self: *Capture, state: *ThreadState, u: *unwinder.Unwinder, ctx: *ReadCtx) void {
    _ = self.samples.fetchAdd(1, .monotonic);

    const cpu_now = sampler.threadCpuTimeUs(state.thread) catch return;
    const delta = cpu_now -% state.last_cpu_us;
    state.last_cpu_us = cpu_now;
    if (delta == 0) return; // idle — no point unwinding the same stack

    _ = self.active_samples.fetchAdd(1, .monotonic);

    sampler.threadSuspend(state.thread) catch return;
    const reg = sampler.threadStateArm64(state.thread) catch {
        sampler.threadResume(state.thread) catch {};
        return;
    };
    var pcs: [MAX_FRAMES]u64 = undefined;
    const n = unwinder.walk(u, .{
        .pc = reg.cleanPC(),
        .fp = reg.cleanFP(),
        .lr = reg.cleanLR(),
        .sp = reg.cleanSP(),
    }, readStackCb, ctx, &pcs);
    sampler.threadResume(state.thread) catch {};
    _ = n; // callstack interning is a follow-up; emit leaf-only sample for now

    // Build PerfSample → wrap in TracePacket body → emit.
    var sample_buf: [4096]u8 = undefined;
    const sample_len = sismo_encode_perf_sample(
        0, // cpu — core not tracked
        @intCast(self.target_pid),
        @intCast(state.tid),
        0, // callstack_iid — interning is a follow-up
        0, // timebase_count
        null,
        0,
        0, // data_address
        null,
        0,
        &sample_buf,
        sample_buf.len,
    );
    if (sample_len == 0) return;
    const body = perfetto_proto.encodeTracePacketBody(
        self.allocator,
        nowMonotonicNs(),
        0,
        perfetto_proto.TP_FIELD_PERF_SAMPLE,
        sample_buf[0..sample_len],
    ) catch return;
    defer self.allocator.free(body);
    perfetto.sismo_ds_emit(self.ds_slot, body.ptr, body.len);
}
