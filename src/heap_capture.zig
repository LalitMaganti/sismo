// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! In-process heap capture → `sismo.heap` producer.
//!
//! Single worker thread driven by the muxer pattern. Worker does
//! the heavy setup (`task_for_pid`, image enumeration, framehop +
//! wholesym, shm ring + heap-protocol attach) at process startup,
//! then sleeps on `std.Io.Event.waitTimeout` between drain cycles —
//! wakes on the drain interval OR on a signal from a trampoline /
//! shutdown. See `macos_sched_capture.zig` for the full lifecycle doc.
//!
//! **Heap emits on FLUSH, not stop.** Perfetto fires `on_flush_cb`
//! periodically AND once before each stop, so emitting the
//! ProfilePacket on flush:
//!   - matches heapprofd's pattern,
//!   - works for ring-mode reads mid-session and ordinary
//!     stop-flush-write lifecycles,
//!   - keeps `on_stop` cheap — we just detach from the target's
//!     preload and ack the postponed stopper.

const std = @import("std");
const builtin = @import("builtin");
const wire = @import("heap_wire.zig");
const ring = @import("heap_ring.zig");
const protocol = @import("heap_protocol.zig");
const sampler = @import("macos/mach_sampler.zig");
const dyld_images = @import("macos/dyld_images.zig");
const unwinder = @import("unwinder.zig");
const symbolizer = @import("symbolizer.zig");
const heap_emit = @import("heap_emit.zig");
const sismo_config = @import("sismo_config.zig");
const perfetto_proto = @import("perfetto_proto.zig");

const perfetto = @cImport({
    @cInclude("src/c/perfetto_shim.h");
});

const DS_NAME = "sismo.heap";

comptime {
    if (builtin.os.tag != .macos) @compileError("heap_capture is macOS-only");
}

fn nowNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

const STACK_SNAPSHOT_BYTES: usize = 8192;
const MAX_FRAMES: usize = 32;

/// Mirror of heap_preload's RegBlockArm64 layout in AllocMetadata.register_data.
const RegBlockArm64 = extern struct {
    pc: u64,
    lr: u64,
    fp: u64,
    _padding: u64 = 0,
};

const AllocStats = struct {
    count: u64 = 0,
    total_size: u64 = 0,
    pcs: [MAX_FRAMES]u64 = undefined,
    pc_count: u8 = 0,
};

pub const Config = struct {
    /// Producer-side defaults. on_setup may override target_pid /
    /// ring_size / sample_interval via SismoHeapConfig; the rest are
    /// always producer-side.
    ring_size_bytes: u64 = 16 * 1024 * 1024,
    sample_interval_bytes: u64 = 4 * 1024,

    /// How often the worker drains the shm ring while RUNNING.
    drain_interval_ns: u64 = std.time.ns_per_ms,

    /// Brief settling pause after detach so the target's heap_preload
    /// observes EOF on its listener fd before we drain leftovers.
    /// 5 ms is plenty for any in-flight malloc to finish writing its
    /// record into shm; longer values just delay `session.stop_blocking`
    /// (which waits for the slowest DS's stop ack).
    detach_settle_ns: u64 = 5 * std.time.ns_per_ms,
};

pub const Stats = struct {
    records: u64,
    bytes_alloc_estimated: u64,
    sites: u32,
};

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
    pending_flusher: std.atomic.Value(usize),

    setup_received: std.atomic.Value(bool),
    setup_config: sismo_config.heap.Config,

    /// Resolved target_pid, set by the worker after on_setup. Stored
    /// on `self` so `emitProfile`/buildTraceData see the right value
    /// without threading it through every call.
    target_pid: c_int,

    thread: ?std.Thread,
    setup_failed: std.atomic.Value(bool),

    records: std.atomic.Value(u64),
    bytes_alloc: std.atomic.Value(u64),
    sites_observed: std.atomic.Value(u32),

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
            .pending_flusher = std.atomic.Value(usize).init(0),
            .setup_received = std.atomic.Value(bool).init(false),
            .setup_config = .{},
            .target_pid = 0,
            .thread = null,
            .setup_failed = std.atomic.Value(bool).init(false),
            .records = std.atomic.Value(u64).init(0),
            .bytes_alloc = std.atomic.Value(u64).init(0),
            .sites_observed = std.atomic.Value(u32).init(0),
        };

        const desc_bytes = try perfetto_proto.encodeDataSourceDescriptor(
            allocator,
            .{ .name = DS_NAME, .will_notify_on_stop = true },
        );
        defer allocator.free(desc_bytes);
        const slot = perfetto.sismo_ds_register(
            desc_bytes.ptr, desc_bytes.len,
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

    /// Decode SismoHeapConfig from the consumer-supplied DataSourceConfig.
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
            if (sismo_config.heap.decode(inner)) |cfg| {
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

    pub fn onFlushTrampoline(user_arg: ?*anyopaque, flusher: ?*anyopaque) callconv(.c) void {
        const self: *Capture = @ptrCast(@alignCast(user_arg.?));
        if (flusher) |f| self.pending_flusher.store(@intFromPtr(f), .release);
        self.wakeup.set(self.io);
    }

    pub fn shutdown(self: *Capture) Stats {
        self.exit_requested.store(true, .release);
        self.wakeup.set(self.io);
        if (self.thread) |t| t.join();
        const stats: Stats = .{
            .records = self.records.load(.monotonic),
            .bytes_alloc_estimated = self.bytes_alloc.load(.monotonic),
            .sites = self.sites_observed.load(.monotonic),
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
    // Wait for on_setup so we know which target to attach to.
    while (!self.exit_requested.load(.acquire) and !self.setup_received.load(.acquire)) {
        self.wakeup.reset();
        if (self.exit_requested.load(.acquire) or self.setup_received.load(.acquire)) break;
        self.wakeup.wait(self.io) catch {};
    }
    if (self.exit_requested.load(.acquire)) return;

    const setup = self.setup_config;
    const target_pid: c_int = @intCast(setup.target_pid);
    const ring_size_bytes: u64 = if (setup.ring_size_bytes != 0) setup.ring_size_bytes else self.config.ring_size_bytes;
    const sample_interval_bytes: u64 = if (setup.sample_interval_bytes != 0) setup.sample_interval_bytes else self.config.sample_interval_bytes;

    if (target_pid == 0) {
        std.debug.print("heap_capture: SismoHeapConfig.target_pid not set — bailing\n", .{});
        self.setup_failed.store(true, .release);
        parkUntilExit(self);
        return;
    }
    self.target_pid = target_pid;

    // ---- Heavy setup phase ---------------------------------------------
    const task = sampler.taskForPid(target_pid) catch |err| {
        std.debug.print(
            "heap_capture: task_for_pid({d}) failed: {s}\n",
            .{ target_pid, @errorName(err) },
        );
        self.setup_failed.store(true, .release);
        parkUntilExit(self);
        return;
    };

    // Retry on EmptyImageList — same race as cpu_sampler.
    const target_images = dyld_images.enumerateImagesWaitReady(
        task,
        self.allocator,
        50 * std.time.ns_per_ms,
        5 * std.time.ns_per_s,
        @ptrCast(self),
        exitRequestedAbort,
    ) catch |err| {
        std.debug.print("heap_capture: enumerateImagesWaitReady failed: {s}\n", .{@errorName(err)});
        self.setup_failed.store(true, .release);
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
        std.debug.print("heap_capture: unwinder.create failed: {s}\n", .{@errorName(err)});
        self.setup_failed.store(true, .release);
        parkUntilExit(self);
        return;
    };
    defer unwinder.destroy(u);
    const sym = symbolizer.create() catch |err| {
        std.debug.print("heap_capture: symbolizer.create failed: {s}\n", .{@errorName(err)});
        self.setup_failed.store(true, .release);
        parkUntilExit(self);
        return;
    };
    defer symbolizer.destroy(sym);

    for (target_images, 0..) |*img, idx| {
        const image = dyld_images.readImageMachO(task, img.base_avma, self.allocator) catch continue;
        defer self.allocator.free(image.bytes);

        const claimed_end = img.base_avma +% image.text_vmsize;
        const next_base = if (idx + 1 < target_images.len)
            target_images[idx + 1].base_avma
        else
            std.math.maxInt(u64);
        const end_avma = @min(claimed_end, next_base);

        const arch = dyld_images.archString(image.cputype, image.cpusubtype);
        symbolizer.addModule(sym, img.base_avma, end_avma, img.path, &image.uuid, arch, null) catch {};
        unwinder.addModule(u, img.base_avma, image.bytes) catch continue;
    }

    var rb = ring.RingBuffer.create(ring_size_bytes) catch |err| {
        std.debug.print("heap_capture: ring.create failed: {s}\n", .{@errorName(err)});
        self.setup_failed.store(true, .release);
        parkUntilExit(self);
        return;
    };
    defer rb.destroy();

    const attach_cfg = protocol.AttachConfig{
        .version = 1,
        .ring_size = @intCast(ring_size_bytes),
        .sample_interval = sample_interval_bytes,
        ._reserved = std.mem.zeroes([16]u8),
    };
    const ctrl_fd = protocol.connectAndAttach(target_pid, rb.fd, attach_cfg) catch |err| {
        std.debug.print(
            "heap_capture: connectAndAttach({d}) failed: {s} — target's heap_preload may not be loaded yet\n",
            .{ target_pid, @errorName(err) },
        );
        self.setup_failed.store(true, .release);
        parkUntilExit(self);
        return;
    };
    var ctrl_fd_open = true;
    defer if (ctrl_fd_open) {
        _ = std.c.close(ctrl_fd);
    };

    var sizes_by_top_pc = std.AutoHashMap(u64, AllocStats).init(self.allocator);
    defer sizes_by_top_pc.deinit();

    // ---- Main loop -----------------------------------------------------
    while (true) {
        self.wakeup.reset();

        if (self.exit_requested.load(.acquire)) return;

        if (self.running.load(.acquire)) {
            drainShmInto(self, &rb, u, &sizes_by_top_pc);
        }

        // Flush: snapshot accumulated state + emit ProfilePacket.
        // Catch up on the ring before stamping so the snapshot
        // includes everything up to "now".
        const flusher_addr = self.pending_flusher.swap(0, .acq_rel);
        if (flusher_addr != 0) {
            drainShmInto(self, &rb, u, &sizes_by_top_pc);
            // Stamp the snapshot's timestamp HERE — at the moment we
            // stop reading the ring — not after symbolicate + encode
            // below. trace_processor reads ProcessHeapSamples.timestamp
            // as the snapshot moment; using post-encode time would
            // misplace every sample in the table by however long the
            // emit took (10s of ms with wholesym in the loop).
            const snapshot_ts = nowNs();
            self.sites_observed.store(@intCast(sizes_by_top_pc.count()), .release);
            emitProfile(self, &sizes_by_top_pc, target_images, sym, snapshot_ts) catch |err| {
                std.debug.print("heap_capture: flush emit failed: {s}\n", .{@errorName(err)});
            };
            perfetto.sismo_flush_done(@ptrFromInt(flusher_addr));
        }

        // Stop: detach from the target so it stops producing, do a
        // final drain to clear the ring (records here are NOT
        // emitted — the preceding flush already covered the visible
        // window; the few records between flush and detach are
        // microseconds of noise). Ack the postponed stopper.
        const stopper_addr = self.pending_stopper.swap(0, .acq_rel);
        if (stopper_addr != 0) {
            if (ctrl_fd_open) {
                _ = std.c.close(ctrl_fd);
                ctrl_fd_open = false;
                self.wakeup.waitTimeout(self.io, .{ .duration = .{
                    .raw = .fromNanoseconds(@intCast(self.config.detach_settle_ns)),
                    .clock = .awake,
                } }) catch {};
            }
            drainShmInto(self, &rb, u, &sizes_by_top_pc);
            perfetto.sismo_stop_done(@ptrFromInt(stopper_addr));
            self.running.store(false, .release);
        }

        if (self.exit_requested.load(.acquire)) return;

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

/// Setup-failure path: park honoring stop, flush, and exit so the
/// orchestrator's `shutdown()` still joins us cleanly.
fn parkUntilExit(self: *Capture) void {
    while (true) {
        self.wakeup.reset();
        if (self.exit_requested.load(.acquire)) return;
        const flusher_addr = self.pending_flusher.swap(0, .acq_rel);
        if (flusher_addr != 0) perfetto.sismo_flush_done(@ptrFromInt(flusher_addr));
        const stopper_addr = self.pending_stopper.swap(0, .acq_rel);
        if (stopper_addr != 0) {
            perfetto.sismo_stop_done(@ptrFromInt(stopper_addr));
            self.running.store(false, .release);
        }
        if (self.exit_requested.load(.acquire)) return;
        self.wakeup.wait(self.io) catch {};
    }
}

fn drainShmInto(
    self: *Capture,
    rb: *ring.RingBuffer,
    u: *unwinder.Unwinder,
    sizes: *std.AutoHashMap(u64, AllocStats),
) void {
    var pcs: [MAX_FRAMES]u64 = undefined;
    var batch: u64 = 0;
    while (rb.beginRead()) |slice| {
        processRecord(self, slice, u, sizes, &pcs);
        rb.endRead(slice);
        batch += 1;
        if (batch > 4096) break;
    }
}

fn processRecord(
    self: *Capture,
    slice: []const u8,
    u: *unwinder.Unwinder,
    sizes: *std.AutoHashMap(u64, AllocStats),
    pcs: *[MAX_FRAMES]u64,
) void {
    if (slice.len < @sizeOf(wire.AllocMetadata) + STACK_SNAPSHOT_BYTES) return;
    const meta: *const wire.AllocMetadata = @ptrCast(@alignCast(slice.ptr));
    const reg_block: *const RegBlockArm64 = @ptrCast(@alignCast(&meta.register_data));
    const stack_bytes: []const u8 = slice[@sizeOf(wire.AllocMetadata)..];
    const sp = meta.stack_pointer;

    const n = unwinder.walkSnapshot(u, .{
        .pc = reg_block.pc,
        .fp = reg_block.fp,
        .lr = reg_block.lr,
        .sp = sp,
    }, stack_bytes, pcs);

    const top_pc = if (n > 0) pcs[0] else meta.alloc_address;
    const gop = sizes.getOrPut(top_pc) catch return;
    if (!gop.found_existing) {
        gop.value_ptr.* = .{};
        const cap = @min(n, MAX_FRAMES);
        @memcpy(gop.value_ptr.pcs[0..cap], pcs[0..cap]);
        gop.value_ptr.pc_count = @intCast(cap);
    }
    gop.value_ptr.count += 1;
    gop.value_ptr.total_size += meta.sample_size;

    _ = self.records.fetchAdd(1, .monotonic);
    _ = self.bytes_alloc.fetchAdd(meta.sample_size, .monotonic);
}

fn emitProfile(
    self: *Capture,
    sizes_map: *const std.AutoHashMap(u64, AllocStats),
    target_images: []const dyld_images.Image,
    sym: *symbolizer.Symbolizer,
    snapshot_ts_ns: u64,
) !void {
    const sample_interval = if (self.setup_config.sample_interval_bytes != 0)
        self.setup_config.sample_interval_bytes
    else
        self.config.sample_interval_bytes;
    var owned = try buildTraceData(
        self.allocator,
        @intCast(self.target_pid),
        sample_interval,
        sizes_map,
        target_images,
        sym,
        snapshot_ts_ns,
    );
    defer owned.deinit(self.allocator);
    owned.fillTd();
    try heap_emit.emitToDataSource(self.allocator, self.ds_slot, owned.td);
}

// ---- TraceData construction ------------------------------------------------

const TraceDataOwned = struct {
    strings: [][]const u8,
    mappings: []heap_emit.Mapping,
    frames: []heap_emit.Frame,
    callstacks: []heap_emit.Callstack,
    samples: []heap_emit.HeapSample,
    td: heap_emit.TraceData,

    fn fillTd(self: *TraceDataOwned) void {
        self.td.strings = self.strings;
        self.td.mappings = self.mappings;
        self.td.frames = self.frames;
        self.td.callstacks = self.callstacks;
        self.td.samples = self.samples;
    }

    fn deinit(self: *TraceDataOwned, gpa: std.mem.Allocator) void {
        for (self.strings) |s| gpa.free(s);
        for (self.callstacks) |c| gpa.free(c.frame_iids);
        gpa.free(self.strings);
        gpa.free(self.mappings);
        gpa.free(self.frames);
        gpa.free(self.callstacks);
        gpa.free(self.samples);
    }
};

fn buildTraceData(
    gpa: std.mem.Allocator,
    pid: u32,
    sampling_interval: u64,
    sizes_map: *const std.AutoHashMap(u64, AllocStats),
    target_images: []const dyld_images.Image,
    sym: *symbolizer.Symbolizer,
    snapshot_ts_ns: u64,
) !TraceDataOwned {
    var strings: std.ArrayList([]const u8) = .empty;
    defer strings.deinit(gpa);
    var mappings: std.ArrayList(heap_emit.Mapping) = .empty;
    defer mappings.deinit(gpa);

    for (target_images, 0..) |img, idx| {
        const iid = idx + 1;
        try strings.append(gpa, try gpa.dupe(u8, img.path));
        try mappings.append(gpa, .{
            .iid = iid,
            .path_string_iid = iid,
            .start = img.base_avma,
            .end = img.base_avma,
            .load_bias = 0,
        });
    }
    var frames: std.ArrayList(heap_emit.Frame) = .empty;
    defer frames.deinit(gpa);
    var callstacks: std.ArrayList(heap_emit.Callstack) = .empty;
    defer callstacks.deinit(gpa);
    var samples: std.ArrayList(heap_emit.HeapSample) = .empty;
    defer samples.deinit(gpa);

    var frame_by_pc: std.AutoHashMap(u64, u64) = .init(gpa);
    defer frame_by_pc.deinit();

    var name_buf: [256]u8 = undefined;
    var next_callstack_iid: u64 = 1;
    var it = sizes_map.iterator();
    while (it.next()) |entry| {
        const site = entry.value_ptr;

        var frame_iids_buf: std.ArrayList(u64) = .empty;
        defer frame_iids_buf.deinit(gpa);

        for (site.pcs[0..site.pc_count]) |pc| {
            const gop = try frame_by_pc.getOrPut(pc);
            if (!gop.found_existing) {
                const k = symbolizer.resolve(sym, pc, &name_buf);
                const name_str = if (k > 0) name_buf[0..k] else "?";
                const owned_name = try gpa.dupe(u8, name_str);
                try strings.append(gpa, owned_name);
                const fn_iid = strings.items.len;

                var j: usize = 0;
                while (j < target_images.len and target_images[j].base_avma <= pc) : (j += 1) {}
                const map_iid: u64 = if (j > 0) j else 1;
                const map_base = if (j > 0) target_images[j - 1].base_avma else 0;

                const frame_iid = frames.items.len + 1;
                try frames.append(gpa, .{
                    .iid = frame_iid,
                    .function_name_iid = fn_iid,
                    .mapping_iid = map_iid,
                    .rel_pc = pc - map_base,
                });
                gop.value_ptr.* = frame_iid;
            }
            try frame_iids_buf.append(gpa, gop.value_ptr.*);
        }

        const cs_iid = next_callstack_iid;
        next_callstack_iid += 1;
        try callstacks.append(gpa, .{
            .iid = cs_iid,
            .frame_iids = try gpa.dupe(u64, frame_iids_buf.items),
        });
        try samples.append(gpa, .{
            .callstack_iid = cs_iid,
            .self_allocated = site.total_size,
            .alloc_count = site.count,
        });
    }

    return .{
        .strings = try strings.toOwnedSlice(gpa),
        .mappings = try mappings.toOwnedSlice(gpa),
        .frames = try frames.toOwnedSlice(gpa),
        .callstacks = try callstacks.toOwnedSlice(gpa),
        .samples = try samples.toOwnedSlice(gpa),
        .td = .{
            .pid = pid,
            .sampling_interval_bytes = sampling_interval,
            .timestamp_ns = snapshot_ts_ns,
            .strings = &.{},
            .mappings = &.{},
            .frames = &.{},
            .callstacks = &.{},
            .samples = &.{},
        },
    };
}
