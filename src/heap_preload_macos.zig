//! macOS DYLD_INSERT_LIBRARIES preload — full dormant heap client.
//!
//! Loaded into a target via:
//!     DYLD_INSERT_LIBRARIES=$(pwd)/zig-out/lib/libsismo_heap.dylib \
//!         zig-out/bin/sample-target
//!
//! Lifecycle:
//!   1. dyld load: `__DATA,__mod_init_func` runs `moduleInit`, which
//!      spawns the listener thread. State starts as `enabled = false`.
//!   2. Listener thread: binds the per-PID Unix socket, blocks on
//!      `accept`. Until sismo connects, the malloc shim hot-path is
//!      a single `bool.load(.acquire)` + branch (~1 ns).
//!   3. On sismo attach: receives shm fd via SCM_RIGHTS, attaches
//!      the ring buffer, atomically flips `enabled = true`. Subsequent
//!      mallocs are captured.
//!   4. On sismo detach (EOF on the control connection): flips
//!      `enabled = false`, tears down the ring, returns to step 2.
//!
//! Phase A: capture is `(alloc_size, alloc_address, sequence)` only.
//! Stack snapshot + register capture lands in Phase B.

const std = @import("std");
const builtin = @import("builtin");
const wire = @import("heap_wire.zig");
const ring = @import("heap_ring.zig");
const protocol = @import("heap_protocol.zig");

comptime {
    if (builtin.os.tag != .macos) {
        @compileError("heap_preload_macos is macOS-only; the Linux LD_PRELOAD and Windows IAT-hook variants live in sibling modules once we get there");
    }
}

// `malloc` is kept as a local extern (rather than std.c.malloc) so its
// address feeds the dyld interpose pair below — the symbol reference
// here is what dyld rewrites in the target image.
extern "c" fn malloc(size: usize) ?*anyopaque;

fn nowNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

// ---- Per-thread re-entrancy guard ----------------------------------------
// Without this, the listener thread's own pthread_create / mmap / etc. would
// recurse into our shim and probably deadlock on the ring's spinlock (or
// at minimum produce nonsense records about our own allocations).
threadlocal var in_capture: bool = false;

// ---- Per-thread Poisson sampler ------------------------------------------
// Direct port of heapprofd's `sampler.h::Sampler`. Each thread keeps an
// `interval_to_next_sample` countdown drawn from `Exponential(1/interval)`;
// each malloc decrements it by `alloc_sz`; when it hits ≤ 0, the alloc is
// sampled with weight = sampling_interval × num_crossings (so the recorded
// `sample_size` ≈ unbiased estimate of the byte mass this sample represents
// in the unsampled population).
//
// Allocations larger than the interval are always sampled at their real size.
//
// Seed per thread from clock + thread-local self pointer to avoid
// correlated sequences across threads.

const Sampler = struct {
    sampling_interval: u64,
    rate: f64,
    interval_to_next: i64,
    rng: std.Random.Xoshiro256,

    fn init(interval: u64, seed: u64) Sampler {
        var rng = std.Random.Xoshiro256.init(seed);
        var s = Sampler{
            .sampling_interval = interval,
            .rate = 1.0 / @as(f64, @floatFromInt(interval)),
            .interval_to_next = 0,
            .rng = rng,
        };
        s.interval_to_next = s.nextInterval();
        _ = &rng;
        return s;
    }

    fn nextInterval(self: *Sampler) i64 {
        // Inverse-CDF sampling for Exp(rate=1/interval): given U ~ U(0,1],
        // x = -ln(U) / rate has the right distribution. Add 1 to convert
        // "failures before next success" (geometric, the discrete analog)
        // to "interval including next success" — same +1 heapprofd does.
        var r = self.rng.random();
        var u: f64 = @as(f64, @floatFromInt(r.int(u64))) / @as(f64, @floatFromInt(std.math.maxInt(u64)));
        if (u <= 0) u = 1e-300; // numerical guard against log(0)
        const x = -std.math.log(f64, std.math.e, u) / self.rate;
        return @as(i64, @intFromFloat(x)) + 1;
    }

    fn sampleSize(self: *Sampler, alloc_sz: u64) u64 {
        // Allocations >= the sampling interval are always sampled at
        // their real size (no statistical scaling needed; they're the
        // dominant contribution to total bytes anyway).
        if (alloc_sz >= self.sampling_interval) return alloc_sz;

        self.interval_to_next -= @intCast(alloc_sz);
        var num_samples: u64 = 0;
        while (self.interval_to_next <= 0) {
            self.interval_to_next += self.nextInterval();
            num_samples += 1;
        }
        // 0 = skip this allocation. Otherwise the recorded sample_size
        // is sampling_interval × num_crossings: the byte-mass this
        // sampled record stands in for.
        return self.sampling_interval * num_samples;
    }
};

threadlocal var t_sampler: ?Sampler = null;
threadlocal var t_sampler_gen: u64 = 0;
// Set to attach.config.sample_interval at attach time; bumped via
// generation counter so each thread re-inits its sampler on first
// malloc after an attach. Pre-attach value is just a placeholder —
// the malloc shim reads it only when enabled, by which point the
// orchestrator has set the real interval.
var g_sampling_interval: u64 = 4 * 1024; // matches heapprofd default
var g_session_generation = std.atomic.Value(u64).init(0);

inline fn ensureSamplerForThisThread() *Sampler {
    const cur_gen = g_session_generation.load(.acquire);
    if (t_sampler == null or t_sampler_gen != cur_gen) {
        var ts: std.c.timespec = undefined;
        _ = std.c.clock_gettime(.MONOTONIC, &ts);
        const seed: u64 = @as(u64, @intCast(ts.nsec)) ^ @intFromPtr(&t_sampler);
        t_sampler = Sampler.init(g_sampling_interval, seed);
        t_sampler_gen = cur_gen;
    }
    return &t_sampler.?;
}

// ---- Global state --------------------------------------------------------

// Single-element heap state. Pointer to a heap-allocated RingBuffer when
// active. Loaded by the malloc shim (acquire); stored by the listener
// thread (release). When `enabled` is false, this is null and
// the malloc shim never reads it.
var g_enabled = std.atomic.Value(bool).init(false);
var g_rb: ?*ring.RingBuffer = null; // protected by store-release / load-acquire of g_enabled
var g_seq = std.atomic.Value(u64).init(1);
var g_listener_started = std.atomic.Value(bool).init(false);

// Per-emit drop counter (visible at detach time via stderr).
var g_dropped = std.atomic.Value(u64).init(0);
var g_emitted = std.atomic.Value(u64).init(0);

// ---- Listener thread (control plane) -------------------------------------

fn listenerThreadEntry(_: ?*anyopaque) callconv(.c) ?*anyopaque {
    in_capture = true; // never re-enter the shim from this thread
    const pid = std.c.getpid();
    var listener = protocol.listenForAttach(pid) catch {
        debugLog("sismo-heap: listenForAttach failed\n");
        return null;
    };
    // Don't `defer listener.close()` — we want the socket to outlive
    // any single attach session. The listener stays bound for the
    // lifetime of the process.

    while (true) {
        var attach = protocol.acceptAndReceive(&listener) catch {
            // Brief backoff and retry. EBADF / EINTR / etc. shouldn't
            // tear down the whole listener.
            sleepUs(50_000);
            continue;
        };

        // Attach the ring. We dynamically allocate it (via libc malloc,
        // which our own shim will skip because in_capture is true).
        const rb_storage = std.c.malloc(@sizeOf(ring.RingBuffer)) orelse {
            attach.closeAll();
            continue;
        };
        const rb_ptr: *ring.RingBuffer = @ptrCast(@alignCast(rb_storage));
        rb_ptr.* = ring.RingBuffer.attach(attach.shm_fd, attach.config.ring_size) catch {
            std.c.free(rb_storage);
            attach.closeAll();
            continue;
        };

        g_seq.store(1, .monotonic);
        g_emitted.store(0, .monotonic);
        g_dropped.store(0, .monotonic);
        // Stash the sampling interval and bump the generation so each
        // thread re-inits its threadlocal Sampler on its next malloc.
        // sample_interval==0 is treated as "always sample" (legacy
        // spike default before sampling existed).
        g_sampling_interval = if (attach.config.sample_interval == 0) 1 else attach.config.sample_interval;
        _ = g_session_generation.fetchAdd(1, .release);
        g_rb = rb_ptr; // published via release of g_enabled below
        g_enabled.store(true, .release);
        var msg_buf2: [128]u8 = undefined;
        const m2 = std.fmt.bufPrint(
            &msg_buf2,
            "sismo-heap: attached, sampling_interval={d}\n",
            .{g_sampling_interval},
        ) catch "sismo-heap: attached\n";
        _ = std.c.write(2, m2.ptr, m2.len);

        // Block on the control connection until EOF. Any byte that
        // arrives is a no-op for now; we use the connection as a
        // liveness signal only.
        var b: [1]u8 = undefined;
        _ = std.c.read(attach.conn_fd, &b, 1);

        // Detach: stop captures, tear down the ring, free.
        g_enabled.store(false, .release);
        const emitted = g_emitted.load(.monotonic);
        const dropped = g_dropped.load(.monotonic);
        var msg_buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(
            &msg_buf,
            "sismo-heap: detached (emitted={d} dropped={d})\n",
            .{ emitted, dropped },
        ) catch "sismo-heap: detached\n";
        _ = std.c.write(2, msg.ptr, msg.len);

        rb_ptr.destroy();
        std.c.free(rb_storage);
        g_rb = null;
        _ = std.c.close(attach.conn_fd);
    }
}

fn sleepUs(us: u64) void {
    const ts: std.c.timespec = .{
        .sec = @intCast(us / std.time.us_per_s),
        .nsec = @intCast((us % std.time.us_per_s) * std.time.ns_per_us),
    };
    _ = std.c.nanosleep(&ts, null);
}

fn debugLog(s: []const u8) void {
    _ = std.c.write(2, s.ptr, s.len);
}

// ---- Module init (runs at dyld load) -------------------------------------

fn moduleInit() callconv(.c) void {
    // Defensive: spawn the listener thread once, even if multiple
    // ctor entries somehow ran (shouldn't, but harmless guard).
    if (g_listener_started.swap(true, .acq_rel)) return;
    in_capture = true;
    var thread_handle: std.c.pthread_t = undefined;
    _ = std.c.pthread_create(&thread_handle, null, listenerThreadEntry, null);
    in_capture = false;
    debugLog("sismo-heap: preload loaded, listener thread spawned\n");
}

// dyld scans __DATA,__mod_init_func at load time. Each entry is a
// function pointer that's invoked before any other code in the image.
export const sismo_heap_ctor linksection("__DATA,__mod_init_func") =
    &moduleInit;

// ---- Malloc intercept (data plane) ---------------------------------------

/// Bytes of stack we copy on each captured allocation.
/// 8 KB is heapprofd's default — enough to cover most call chains
/// while keeping the per-record cost bounded.
const STACK_SNAPSHOT_BYTES: usize = 8192;

/// register_data layout for arch == .arm64 (sismo convention):
///   bytes [0..8)   = pc  (the user's call-site PC)
///   bytes [8..16)  = lr  (the user's parent frame's return address)
///   bytes [16..24) = fp  (the user's frame pointer, saved at call time)
/// stack_pointer field of AllocMetadata holds sp at the call site.
const RegBlockArm64 = extern struct {
    pc: u64,
    lr: u64,
    fp: u64,
    _padding: u64 = 0,
};

/// Read our own caller's regs by walking one FP-chain frame back. Our
/// shim's prologue has saved [user_fp | user_lr] at our_fp[0..16];
/// user_sp at the call site is just past that block.
inline fn captureUserSnapshot() RegBlockArm64 {
    const pc: u64 = @returnAddress();
    const our_fp_addr: usize = @frameAddress();
    const our_fp: *const [2]u64 = @ptrFromInt(our_fp_addr);
    return .{
        .pc = pc,
        .fp = our_fp[0], // user's saved fp
        .lr = our_fp[1], // user's saved lr
    };
}

inline fn captureUserSp() u64 {
    // user_sp at the call site = byte just above our saved (fp,lr) block.
    return @as(u64, @frameAddress()) + 16;
}

fn sismoMallocShim(size: usize) callconv(.c) ?*anyopaque {
    // FAST PATH: dormant. One acquire-load + branch.
    if (!g_enabled.load(.acquire)) return malloc(size);

    // Re-entrancy guard. If our own capture path allocated, fall
    // through to the real malloc without recursing.
    if (in_capture) return malloc(size);

    in_capture = true;
    defer in_capture = false;

    // Poisson sampling decision (heapprofd-style). Done BEFORE we
    // touch the ring or capture stacks — for unsampled allocs we just
    // pay the threadlocal sampler decrement, which is sub-nanosecond
    // when the countdown stays positive.
    const sampler = ensureSamplerForThisThread();
    const sample_size = sampler.sampleSize(size);
    if (sample_size == 0) return malloc(size);

    // Capture caller registers BEFORE doing the real malloc — once
    // we call into libc, our frame might be modified.
    const regs = captureUserSnapshot();
    const user_sp = captureUserSp();

    const ptr = malloc(size);

    if (g_rb) |rb| {
        const payload_size = @sizeOf(wire.AllocMetadata) + STACK_SNAPSHOT_BYTES;
        const slot = rb.beginWrite(payload_size);
        if (slot) |s| {
            const seq = g_seq.fetchAdd(1, .monotonic);
            const meta: *wire.AllocMetadata = @ptrCast(@alignCast(s.ptr));
            meta.* = .{
                .sequence_number = seq,
                .alloc_size = size,
                .sample_size = sample_size, // weighted estimate
                .alloc_address = @intFromPtr(ptr),
                .stack_pointer = user_sp,
                .clock_monotonic_coarse_ts = nowNs(),
                .register_data = std.mem.zeroes([wire.MAX_REGISTER_DATA_BYTES]u8),
                .heap_id = 0,
                .arch = .arm64,
            };
            // Pack the user regs at the head of register_data per the
            // sismo arm64 convention.
            const reg_block: *RegBlockArm64 = @ptrCast(@alignCast(&meta.register_data));
            reg_block.* = regs;

            // Snapshot 8 KB of stack starting at user_sp. The stack
            // grows down; we copy upward (toward higher addresses).
            // The pages between sp and sp+8KB are part of the user's
            // stack region (assumed mapped — main thread always is;
            // pthread defaults are 512KB). For deeper safety we'd
            // probe-and-truncate; out of scope for the spike.
            const snapshot_dst: [*]u8 = s.ptr + @sizeOf(wire.AllocMetadata);
            const snapshot_src: [*]const u8 = @ptrFromInt(user_sp);
            @memcpy(snapshot_dst[0..STACK_SNAPSHOT_BYTES], snapshot_src[0..STACK_SNAPSHOT_BYTES]);

            rb.endWrite(s);
            _ = g_emitted.fetchAdd(1, .monotonic);
        } else {
            _ = g_dropped.fetchAdd(1, .monotonic);
        }
    }

    return ptr;
}

const InterposePair = extern struct {
    new_func: *const anyopaque,
    orig_func: *const anyopaque,
};

export const sismo_interpose_malloc linksection("__DATA,__interpose") =
    InterposePair{
        .new_func = @ptrCast(&sismoMallocShim),
        .orig_func = @ptrCast(&malloc),
    };
