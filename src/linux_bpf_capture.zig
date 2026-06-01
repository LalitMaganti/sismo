// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Linux CPU collector: an in-process libbpf loader for the BPF program in
//! `src/c/sismo_bpf/sched.bpf.c` — sismo's per-thread CPU profiler. It:
//!
//!   - opens the hardware-supported subset of the candidate PMU counters as a
//!     per-CPU counting group and parks the fds in the counters_pe map,
//!   - attaches the sched_switch + per-CPU timer hooks,
//!   - drains the ringbuf on a worker thread and, while the data source is
//!     active, emits each timer-tick record as a Perfetto PerfSample —
//!     thread-scoped timebase/follower counts plus an interned callstack.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const perfetto_proto = @import("perfetto_proto.zig");
const proc_maps = @import("linux_proc_maps.zig");
const ProtoWriter = @import("proto_writer.zig").ProtoWriter;
// PMU event encodings per Intel CPU model, generated from Intel's perfmon DB by
// python/tools/gen_pmu_events.py. On x86 we resolve the active counters from
// this at runtime (by CPUID) instead of hardcoding raw configs.
const pmu = @import("gen/pmu_events.zig");

const c = @cImport({
    @cInclude("bpf/libbpf.h");
    @cInclude("bpf/bpf.h");
    @cInclude("src/c/sismo_bpf/sismo_bpf.h");
});

const perfetto = @cImport({
    @cInclude("src/c/perfetto_shim.h");
});

comptime {
    if (builtin.os.tag != .linux) @compileError("linux_bpf_capture is Linux-only");
}

/// Producer name; must match the `sismo_vendor` entry cmd_record adds to the
/// TraceConfig, otherwise traced never activates the source and every
/// `sismo_ds_emit` is a no-op.
pub const DS_NAME = "sismo.linux_cpu_samples";

/// A counter's hardware source: either a generic perf HARDWARE event or a raw
/// PMU event code (PERF_TYPE_RAW) for events the generic enum doesn't cover
/// (e.g. ARM Top-Down slot events).
const Src = union(enum) {
    hw: linux.PERF.COUNT.HW,
    raw: u32,
};

/// Candidate PMU counters, organised into multiplexed groups. Group 0 is the
/// Top-Down Level-1 set — co-scheduled so its ratios are exact within the
/// group; group 1 carries the cache/branch vitals. When the two groups together
/// exceed the PMU's counter count the kernel time-shares them, and read_advance
/// (BPF) scales each interval back to a full-period estimate. Within a group,
/// any member the PMU can't co-schedule fails to open and is dropped (feature
/// detection). On aarch64 group 0 uses the architectural slot/op events for a
/// true L1 breakdown (Retiring / Bad-Speculation / Frontend / Backend);
/// elsewhere it falls back to the generic stalled-cycles split (coarse L1).
/// COUNTERS.len must not exceed SISMO_MAX_COUNTERS in sismo_bpf.h.
const Counter = struct { group: u8, src: Src, name: []const u8 };
const COUNTERS: []const Counter = switch (builtin.cpu.arch) {
    .aarch64 => &[_]Counter{
        .{ .group = 0, .src = .{ .hw = .CPU_CYCLES }, .name = "cpu-cycles" },
        .{ .group = 0, .src = .{ .hw = .INSTRUCTIONS }, .name = "instructions" },
        // ARMv8 architectural PMU event numbers, as PERF_TYPE_RAW config.
        .{ .group = 0, .src = .{ .raw = 0x3A }, .name = "op-retired" },
        .{ .group = 0, .src = .{ .raw = 0x3B }, .name = "op-spec" },
        .{ .group = 0, .src = .{ .raw = 0x3D }, .name = "stall-slot-frontend" },
        .{ .group = 0, .src = .{ .raw = 0x3E }, .name = "stall-slot-backend" },
        .{ .group = 1, .src = .{ .hw = .CACHE_MISSES }, .name = "cache-misses" },
        .{ .group = 1, .src = .{ .hw = .BRANCH_MISSES }, .name = "branch-misses" },
    },
    // x86_64 resolves its counters at runtime from the perfmon table (by
    // CPUID); this generic set is only the fallback when the CPU model isn't in
    // the table.
    else => &[_]Counter{
        .{ .group = 0, .src = .{ .hw = .CPU_CYCLES }, .name = "cpu-cycles" },
        .{ .group = 0, .src = .{ .hw = .INSTRUCTIONS }, .name = "instructions" },
        .{ .group = 0, .src = .{ .hw = .STALLED_CYCLES_FRONTEND }, .name = "stalled-cycles-frontend" },
        .{ .group = 0, .src = .{ .hw = .STALLED_CYCLES_BACKEND }, .name = "stalled-cycles-backend" },
        .{ .group = 1, .src = .{ .hw = .CACHE_MISSES }, .name = "cache-misses" },
        .{ .group = 1, .src = .{ .hw = .BRANCH_MISSES }, .name = "branch-misses" },
    },
};
comptime {
    if (COUNTERS.len > c.SISMO_MAX_COUNTERS) @compileError("COUNTERS exceeds SISMO_MAX_COUNTERS");
}

// Maps a generated pmu role to the STABLE sismo counter name the trace carries
// (the UI's counter catalog keys on these) and the group it belongs to: the
// Top-Down L1 set co-schedules in group 0, the cache/branch vitals in group 1.
fn roleName(role: pmu.Role) []const u8 {
    return switch (role) {
        .cycles => "cpu-cycles",
        .instructions => "instructions",
        .slots => "slots",
        .retired => "topdown-slots-retired",
        .fetch_bubbles => "topdown-fetch-bubbles",
        .cache_miss => "cache-misses",
        .branch_miss => "branch-misses",
    };
}

fn roleGroup(role: pmu.Role) u8 {
    return switch (role) {
        .cache_miss, .branch_miss => 1,
        else => 0,
    };
}

// The slot-based Top-Down set: only meaningful when the `slots` fixed counter
// is present (slots is the denominator; retired/fetch_bubbles are its numerators
// and feed no other strategy). Gated together on CPUID-enumerated slots support.
fn isTopdownRole(role: pmu.Role) bool {
    return switch (role) {
        .slots, .retired, .fetch_bubbles => true,
        else => false,
    };
}

const CpuId = struct { family: u16, model: u16, stepping: u8 };

// Reads the running CPU's vendor/family/model/stepping from /proc/cpuinfo.
// Returns null on non-Intel or parse failure (caller falls back).
fn readCpuId() ?CpuId {
    const fd = std.posix.openat(std.posix.AT.FDCWD, "/proc/cpuinfo", .{}, 0) catch return null;
    defer _ = linux.close(fd);
    var buf: [8192]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return null;
    const text = buf[0..n];
    if (std.mem.indexOf(u8, text, "GenuineIntel") == null) return null;
    const fam = cpuinfoField(text, "cpu family") orelse return null;
    const mdl = cpuinfoField(text, "model") orelse return null;
    const stp = cpuinfoField(text, "stepping") orelse 0;
    return .{
        .family = @intCast(fam),
        .model = @intCast(mdl),
        .stepping = @intCast(stp),
    };
}

// First "<key> : <int>" line's integer. Exact-match on the trimmed key so
// "model" doesn't pick up "model name".
fn cpuinfoField(text: []const u8, key: []const u8) ?u64 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.mem.eql(u8, std.mem.trim(u8, line[0..colon], " \t"), key)) continue;
        const rhs = std.mem.trim(u8, line[colon + 1 ..], " \t");
        var toks = std.mem.tokenizeScalar(u8, rhs, ' ');
        const tok = toks.next() orelse return null;
        return std.fmt.parseInt(u64, tok, 10) catch null;
    }
    return null;
}

fn cpuidLeaf(leaf: u32, subleaf: u32) [4]u32 {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [a] "={eax}" (eax),
          [b] "={ebx}" (ebx),
          [cc] "={ecx}" (ecx),
          [d] "={edx}" (edx),
        : [leaf] "{eax}" (leaf),
          [sub] "{ecx}" (subleaf),
    );
    return .{ eax, ebx, ecx, edx };
}

// Whether the slots fixed counter + PERF_METRICS Top-Down are present, read from
// CPUID leaf 0x0A (Architectural Performance Monitoring) — the SAME enumeration
// the kernel/perf use (`union cpuid10_eax/edx` in arch/x86; slots is fixed
// counter 3). Version >= 5 with fixed-counter-3 in the ECX support bitmap is the
// architectural signal. A KVM guest exposing only a v2 PMU reports false here
// even where the host counter would physically pass through — which is correct:
// perf likewise refuses `slots`/--topdown in that case. We trust the
// enumeration, never a counts-it-tick probe.
fn topdownEnumerated() bool {
    if (builtin.cpu.arch != .x86_64) return false;
    const r = cpuidLeaf(0x0A, 0);
    const version = r[0] & 0xff; // eax.split.version_id
    const fixed_support = r[2]; // ecx: per-fixed-counter support bitmap (v>=5)
    return version >= 5 and (fixed_support & (@as(u32, 1) << 3)) != 0;
}

// vvvvvvvvvvvvvvvvvvvvvvvvvvvvvv  TEMPORARY HACK  vvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
// DO NOT GENERALISE. DELETE once the L1 TMA UI is validated on real ICL+ silicon
// or a mediated-vPMU host. This exists ONLY to unblock UI work on one dev VM.
//
// That VM spoofs its CPUID as family 6 / model 134 / stepping 0 so perf sees a
// non-hybrid PMU; KVM consequently exposes only a v2 vPMU, so CPUID 0x0A (and
// thus topdownEnumerated(), correctly) reports NO slots fixed counter. But the
// real silicon underneath is Golden Cove, which DOES service raw 0x400/0x2c2/
// 0x19c via passthrough (verified: r0400 == 6*cycles). So the slot-based TMA
// counters physically work even though nothing enumerates them.
//
// This forces exactly those counters for that one spoofed signature, gated on
// the hypervisor bit so it can never fire on real Snowridge hardware. It is a
// lie about the PMU; the honest path is topdownEnumerated() below.
const VM_HACK_COUNTERS = [_]Counter{
    .{ .group = 0, .src = .{ .raw = 0x3c }, .name = "cpu-cycles" },
    .{ .group = 0, .src = .{ .raw = 0xc0 }, .name = "instructions" },
    .{ .group = 0, .src = .{ .raw = 0x400 }, .name = "slots" },
    .{ .group = 0, .src = .{ .raw = 0x2c2 }, .name = "topdown-slots-retired" },
    .{ .group = 0, .src = .{ .raw = 0x19c }, .name = "topdown-fetch-bubbles" },
    .{ .group = 1, .src = .{ .raw = 0x412e }, .name = "cache-misses" },
    .{ .group = 1, .src = .{ .raw = 0xc5 }, .name = "branch-misses" },
};
fn vmSlotsHackCounters() ?[]const Counter {
    if (builtin.cpu.arch != .x86_64) return null;
    const id = readCpuId() orelse return null;
    if (id.family != 6 or id.model != 134 or id.stepping != 0) return null;
    if ((cpuidLeaf(1, 0)[2] & (@as(u32, 1) << 31)) == 0) return null; // hypervisor bit
    return &VM_HACK_COUNTERS;
}
// ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  TEMPORARY HACK  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

// The active candidate counters for this host: on x86 resolved from the perfmon
// table by CPUID (into `buf`), else the comptime fallback for the build arch.
fn selectCounters(buf: *[c.SISMO_MAX_COUNTERS]Counter) []const Counter {
    if (vmSlotsHackCounters()) |list| return list; // TEMPORARY — see hack above.
    if (builtin.cpu.arch == .x86_64) {
        if (countersFromTable(buf)) |list| return list;
    }
    return COUNTERS;
}

// Looks up this CPU model in the generated table and builds the counter list
// (role → stable name + group + raw config). Prefers the non-Atom (P-core /
// non-hybrid) row when a model has both. Null if the model isn't in the table.
fn countersFromTable(buf: *[c.SISMO_MAX_COUNTERS]Counter) ?[]const Counter {
    const id = readCpuId() orelse return null;
    var best: ?*const pmu.Model = null;
    for (&pmu.MODELS) |*m| {
        if (m.family != id.family or m.model != id.model) continue;
        if (m.steppings.len > 0 and
            std.mem.indexOfScalar(u8, m.steppings, id.stepping) == null) continue;
        best = m;
        if (!std.mem.eql(u8, m.core, "Atom")) break; // prefer P-core / non-hybrid
    }
    const m = best orelse return null;
    // Trust the PMU's own enumeration: if the slots fixed counter isn't present,
    // drop the whole slot-based Top-Down set (matching perf), keeping only the
    // counters the hardware actually advertises.
    const td = topdownEnumerated();
    var n: usize = 0;
    for (m.events) |ev| {
        if (n >= buf.len) break;
        if (isTopdownRole(ev.role) and !td) continue;
        buf[n] = .{
            .group = roleGroup(ev.role),
            .src = .{ .raw = @intCast(ev.config) },
            .name = roleName(ev.role),
        };
        n += 1;
    }
    return buf[0..n];
}

// The kernel-side object, compiled by clang and embedded by build.zig.
const bpf_obj_bytes = @embedFile("sched.bpf.o");

pub const Stats = struct {
    samples: u64,
    threads: u32,
    busiest_cycles: u64,
};

/// Frame interning key: a module-relative pc within a given mapping.
// `name_iid` is 0 for the usual offline-symbolized frame (named later from
// mapping + rel_pc) and non-zero for frames we name inline — kernel frames,
// whose name is interned into function_names and whose rel_pc is 0.
const FrameKey = struct { mapping_iid: u64, rel_pc: u64, name_iid: u64 };

/// Per-sequence callstack interning state. Mirrors the iids written into the
/// trace's InternedData tables so each entry is emitted exactly once; reset
/// whenever a fresh incremental-state-cleared sequence begins. All access is
/// from the worker thread.
const Interner = struct {
    paths: std.StringHashMapUnmanaged(u64) = .empty,
    build_ids: std.StringHashMapUnmanaged(u64) = .empty, // raw build-id bytes -> iid
    func_names: std.StringHashMapUnmanaged(u64) = .empty, // function name -> iid
    mappings: std.AutoHashMapUnmanaged(u64, u64) = .empty, // map.start -> iid
    frames: std.AutoHashMapUnmanaged(FrameKey, u64) = .empty,
    callstacks: std.StringHashMapUnmanaged(u64) = .empty, // frame-id bytes -> iid
    next_path: u64 = 1,
    next_build_id: u64 = 1,
    next_func_name: u64 = 1,
    next_mapping: u64 = 1,
    next_frame: u64 = 1,
    next_callstack: u64 = 1,

    fn reset(self: *Interner, gpa: std.mem.Allocator) void {
        freeKeys(&self.paths, gpa);
        freeKeys(&self.build_ids, gpa);
        freeKeys(&self.func_names, gpa);
        freeKeys(&self.callstacks, gpa);
        self.paths.deinit(gpa);
        self.build_ids.deinit(gpa);
        self.func_names.deinit(gpa);
        self.mappings.deinit(gpa);
        self.frames.deinit(gpa);
        self.callstacks.deinit(gpa);
        self.* = .{};
    }

    fn freeKeys(m: *std.StringHashMapUnmanaged(u64), gpa: std.mem.Allocator) void {
        var it = m.keyIterator();
        while (it.next()) |k| gpa.free(k.*);
    }
};

pub const Capture = struct {
    gpa: std.mem.Allocator,
    obj: *c.struct_bpf_object,
    rb: *c.struct_ring_buffer,
    links: std.ArrayList(*c.struct_bpf_link),
    perf_fds: std.ArrayList(i32),
    worker: ?std.Thread,
    exit_requested: std.atomic.Value(bool),
    /// tid -> latest cumulative cpu-cycles (counters[0]); drives the shutdown
    /// summary (distinct-thread count + busiest thread).
    acc: std.AutoHashMap(u32, u64),
    samples: u64,

    /// Target tgid; used to read /proc/<pid>/maps for stack symbolization.
    target_pid: u32,
    /// Address-space map of the target, parsed lazily on the first emitted
    /// sample (by then the workload has mapped its libraries) and re-parsed
    /// (bounded to ~1/s) when a PC misses, to pick up later dlopen()s.
    maps: ?proc_maps.Maps,
    maps_tried: bool,
    /// CLOCK_MONOTONIC ns of the last maps parse (0 = never).
    last_maps_ns: u64,
    interner: Interner,

    /// Session-global kernel-symbol dictionary: BPF-assigned id -> name. Fed by
    /// SISMO_EVT_KSYM records. Unlike `interner` this is NOT reset between
    /// incremental-state-cleared sequences — the BPF program defines each id
    /// once for the whole recording, so a later sequence must still resolve ids
    /// it saw defined in an earlier one. Names are owned by `ksym_arena`.
    ksym_names: std.AutoHashMapUnmanaged(u32, []const u8),
    ksym_arena: std.heap.ArenaAllocator,

    /// The active candidate counters for this host (perfmon table on x86, else
    /// the comptime fallback), backed by `counters_buf` when table-derived.
    counters: []const Counter,
    counters_buf: [c.SISMO_MAX_COUNTERS]Counter,

    /// Indices into `counters` that actually opened (the hardware-supported
    /// subset), in priority order. active_slots[0] is the timebase; the rest are
    /// followers. n_active == 0 means no PMU counters (stacks only).
    active_slots: [c.SISMO_MAX_COUNTERS]u8,
    n_active: usize,

    /// Data source slot from `sismo_ds_register`. Emission is gated on the
    /// session activating this source (`active`).
    ds_slot: u32,
    active: std.atomic.Value(bool),
    /// Set on each start so the worker re-emits PerfSampleDefaults at the head
    /// of the (incremental-state-cleared) sequence before any sample.
    need_defaults: std.atomic.Value(bool),

    pub fn init(gpa: std.mem.Allocator, target_pid: u32) !*Capture {
        const self = try gpa.create(Capture);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .obj = undefined,
            .rb = undefined,
            .links = .empty,
            .perf_fds = .empty,
            .worker = null,
            .exit_requested = std.atomic.Value(bool).init(false),
            .acc = std.AutoHashMap(u32, u64).init(gpa),
            .samples = 0,
            .target_pid = target_pid,
            .maps = null,
            .maps_tried = false,
            .ksym_names = .empty,
            .ksym_arena = std.heap.ArenaAllocator.init(gpa),
            .last_maps_ns = 0,
            .interner = .{},
            .counters = &.{},
            .counters_buf = undefined,
            .active_slots = undefined,
            .n_active = 0,
            .ds_slot = std.math.maxInt(u32),
            .active = std.atomic.Value(bool).init(false),
            .need_defaults = std.atomic.Value(bool).init(false),
        };
        // Resolve the candidate counters now that `self` is allocated (the
        // table-derived list is backed by self.counters_buf).
        self.counters = selectCounters(&self.counters_buf);

        const desc_bytes = try perfetto_proto.encodeDataSourceDescriptor(
            gpa,
            .{ .name = DS_NAME, .will_notify_on_stop = false },
        );
        defer gpa.free(desc_bytes);
        const slot = perfetto.sismo_ds_register(
            desc_bytes.ptr,
            desc_bytes.len,
            onSetup,
            onStart,
            onStop,
            onFlush,
            self,
        );
        if (slot == std.math.maxInt(u32)) return error.PerfettoDsRegisterFailed;
        self.ds_slot = slot;
        errdefer {
            self.acc.deinit();
            self.links.deinit(gpa);
            self.perf_fds.deinit(gpa);
        }

        const obj = c.bpf_object__open_mem(bpf_obj_bytes.ptr, bpf_obj_bytes.len, null) orelse
            return error.BpfOpen;
        errdefer c.bpf_object__close(obj);
        if (c.bpf_object__load(obj) != 0) return error.BpfLoad;
        self.obj = obj;

        const counters_fd = c.bpf_map__fd(c.bpf_object__find_map_by_name(obj, "counters_pe") orelse return error.NoMap);
        const cfg_fd = c.bpf_map__fd(c.bpf_object__find_map_by_name(obj, "cfg") orelse return error.NoMap);
        const events_fd = c.bpf_map__fd(c.bpf_object__find_map_by_name(obj, "events") orelse return error.NoMap);

        // Open the candidate counters as a per-CPU counting group and park each
        // fd at counters_pe[slot*SISMO_MAX_CPUS + cpu]. A follower the PMU can't
        // co-schedule fails to open and is dropped. The active set is decided on
        // CPU 0 (homogeneous CPUs) and opened identically on the rest.
        const max_cpus: u32 = @intCast(c.SISMO_MAX_CPUS);
        const ncpu: u32 = @min(@as(u32, @intCast(c.libbpf_num_possible_cpus())), max_cpus);
        var opened = [_]bool{false} ** c.SISMO_MAX_COUNTERS;
        var cpu: u32 = 0;
        while (cpu < ncpu and self.counters.len > 0) : (cpu += 1) {
            // Each group is its own co-scheduled set: the first member that
            // opens becomes the group leader, the rest join it. A member the
            // PMU can't fit is dropped; a whole group can be absent.
            var group_leader: i32 = -1;
            var cur_group: u8 = self.counters[0].group;
            for (self.counters, 0..) |ctr, cslot| {
                if (ctr.group != cur_group) {
                    cur_group = ctr.group;
                    group_leader = -1;
                }
                const fd = openCounter(cpu, ctr.src, group_leader) orelse continue;
                if (group_leader == -1) group_leader = fd;
                try self.perf_fds.append(gpa, fd);
                const fd_u: u32 = @intCast(fd);
                var idx: u32 = @intCast(cslot * @as(usize, max_cpus) + cpu);
                _ = c.bpf_map_update_elem(counters_fd, &idx, &fd_u, 0);
                if (cpu == 0) opened[cslot] = true;
            }
        }
        for (opened, 0..) |on, cslot| {
            if (on) {
                self.active_slots[self.n_active] = @intCast(cslot);
                self.n_active += 1;
            }
        }

        var zero: u32 = 0;
        _ = c.bpf_map_update_elem(cfg_fd, &zero, &target_pid, 0);

        try self.attach("on_sched_switch");

        // Per-CPU cycles-PMU overflow → on_tick (the sampler + counter flush).
        const tick_prog = c.bpf_object__find_program_by_name(obj, "on_tick") orelse return error.NoProg;
        cpu = 0;
        while (cpu < ncpu) : (cpu += 1) {
            const tfd = openSampler(cpu) orelse continue;
            const link = c.bpf_program__attach_perf_event(tick_prog, tfd);
            if (link) |l| {
                try self.links.append(gpa, l);
                try self.perf_fds.append(gpa, tfd);
            } else {
                _ = std.c.close(tfd);
            }
        }

        self.rb = c.ring_buffer__new(events_fd, onEvent, self, null) orelse return error.RingBuf;
        errdefer c.ring_buffer__free(self.rb);

        self.worker = try std.Thread.spawn(.{}, workerEntry, .{self});
        return self;
    }

    fn attach(self: *Capture, prog_name: [*:0]const u8) !void {
        const prog = c.bpf_object__find_program_by_name(self.obj, prog_name) orelse return error.NoProg;
        const link = c.bpf_program__attach(prog) orelse return error.Attach;
        try self.links.append(self.gpa, link);
    }

    pub fn shutdown(self: *Capture) Stats {
        self.exit_requested.store(true, .release);
        if (self.worker) |w| w.join();

        var busiest: u64 = 0;
        var it = self.acc.valueIterator();
        while (it.next()) |cycles| busiest = @max(busiest, cycles.*);
        const stats: Stats = .{
            .samples = self.samples,
            .threads = self.acc.count(),
            .busiest_cycles = busiest,
        };

        c.ring_buffer__free(self.rb);
        for (self.links.items) |l| _ = c.bpf_link__destroy(l);
        for (self.perf_fds.items) |fd| _ = std.c.close(fd);
        c.bpf_object__close(self.obj);
        self.links.deinit(self.gpa);
        self.perf_fds.deinit(self.gpa);
        self.acc.deinit();
        self.interner.reset(self.gpa);
        self.ksym_names.deinit(self.gpa);
        self.ksym_arena.deinit();
        if (self.maps) |*m| m.deinit();
        const gpa = self.gpa;
        gpa.destroy(self);
        return stats;
    }

    fn handle(self: *Capture, hdr: *const c.struct_sismo_hdr) void {
        // KSYM definitions are recorded unconditionally (even before the source
        // is active): the BPF program emits each id once for the whole session,
        // so we must capture every definition or later samples can't resolve it.
        if (hdr.type == c.SISMO_EVT_KSYM) {
            self.handleKsym(@ptrCast(@alignCast(hdr)));
            return;
        }
        if (hdr.type != c.SISMO_EVT_SAMPLE) return;
        self.samples += 1;
        const rec: *const c.struct_sismo_sample_rec = @ptrCast(@alignCast(hdr));
        // counters[0] (cpu-cycles) is cumulative — the latest reading is the
        // running total. Drives the shutdown summary only.
        self.acc.put(hdr.tid, rec.counters[0]) catch {};

        // Emit into the trace only while the session has this source active.
        // Runs on the worker thread (the ringbuf callback), so the defaults and
        // every sample share one TraceWriter sequence.
        if (!self.active.load(.acquire)) return;
        if (self.need_defaults.swap(false, .acq_rel)) {
            // Fresh incremental-state-cleared sequence: drop any interning the
            // previous session emitted so iids start over in lockstep with
            // trace_processor's reset interning tables.
            self.interner.reset(self.gpa);
            self.emitDefaults();
        }
        self.emitSample(rec);
    }

    /// Record a kernel-symbol definition. Stores id -> bare function name in the
    /// session dictionary, stripping the `+0xoff/0xsize` suffix `%pB` appends
    /// (symbol-relative, so KASLR-safe, but the flamegraph wants the name). Each
    /// id is defined once; repeats are ignored.
    fn handleKsym(self: *Capture, rec: *const c.struct_sismo_ksym_rec) void {
        const gop = self.ksym_names.getOrPut(self.gpa, rec.id) catch return;
        if (gop.found_existing) return;

        var name: []const u8 = &rec.name;
        if (std.mem.indexOfScalar(u8, name, 0)) |z| name = name[0..z];
        if (std.mem.indexOfScalar(u8, name, '+')) |p| name = name[0..p];

        gop.value_ptr.* = self.ksym_arena.allocator().dupe(u8, name) catch {
            _ = self.ksym_names.remove(rec.id);
            return;
        };
    }

    fn emitDefaults(self: *Capture) void {
        const gpa = self.gpa;
        // timebase = active_slots[0], followers = the rest (all thread-scoped).
        // With no PMU counters, fall back to a bare cpu-clock timebase.
        var followers_buf: [c.SISMO_MAX_COUNTERS]perfetto_proto.PerfEventName = undefined;
        var nf: usize = 0;
        var timebase_name: []const u8 = "cpu-clock";
        if (self.n_active > 0) {
            timebase_name = self.counters[self.active_slots[0]].name;
            var i: usize = 1;
            while (i < self.n_active) : (i += 1) {
                followers_buf[nf] = .{ .name = self.counters[self.active_slots[i]].name };
                nf += 1;
            }
        }
        const psd = perfetto_proto.encodePerfSampleDefaults(gpa, .{
            .timebase = .{ .name = timebase_name },
            .followers = followers_buf[0..nf],
            .sample_scope = .thread,
        }) catch return;
        defer gpa.free(psd);
        const tpd = perfetto_proto.encodeTracePacketDefaults(
            gpa,
            perfetto_proto.BUILTIN_CLOCK_MONOTONIC,
            psd,
        ) catch return;
        defer gpa.free(tpd);
        const body = perfetto_proto.encodeTracePacketBody(
            gpa,
            0,
            perfetto_proto.SEQ_INCREMENTAL_STATE_CLEARED,
            perfetto_proto.TP_FIELD_TRACE_PACKET_DEFAULTS,
            tpd,
        ) catch return;
        defer gpa.free(body);
        perfetto.sismo_ds_emit(self.ds_slot, body.ptr, body.len);
    }

    fn emitSample(self: *Capture, rec: *const c.struct_sismo_sample_rec) void {
        const gpa = self.gpa;
        const hdr = &rec.hdr;

        // Intern the sample's stack; any newly-seen mappings/frames/callstacks
        // are written into `idw` (an InternedData) to ride along in this packet.
        var idw = ProtoWriter.init(gpa);
        defer idw.deinit();
        const cs_iid = self.internCallstack(rec, &idw);

        // Project the cumulative per-thread counters onto the active set:
        // timebase = active_slots[0], followers = the rest, in order.
        var follower_buf: [c.SISMO_MAX_COUNTERS]u64 = undefined;
        var nf: usize = 0;
        var timebase_count: u64 = 0;
        if (self.n_active > 0) {
            timebase_count = rec.counters[self.active_slots[0]];
            var i: usize = 1;
            while (i < self.n_active) : (i += 1) {
                follower_buf[nf] = rec.counters[self.active_slots[i]];
                nf += 1;
            }
        }
        const ps = perfetto_proto.encodePerfSample(gpa, .{
            .cpu = hdr.cpu,
            .pid = hdr.pid,
            .tid = hdr.tid,
            .timebase_count = timebase_count,
            .follower_counts = follower_buf[0..nf],
            .callstack_iid = cs_iid,
        }) catch return;
        defer gpa.free(ps);

        // TracePacket { timestamp, sequence_flags, interned_data?, perf_sample }.
        var tp = ProtoWriter.init(gpa);
        defer tp.deinit();
        tp.writeUint64(8, hdr.ts) catch return;
        tp.writeUint32(13, perfetto_proto.SEQ_NEEDS_INCREMENTAL_STATE) catch return;
        if (idw.bytes().len > 0) tp.writeMessage(12, idw.bytes()) catch return;
        tp.writeMessage(perfetto_proto.TP_FIELD_PERF_SAMPLE, ps) catch return;
        const body = tp.bytes();
        perfetto.sismo_ds_emit(self.ds_slot, body.ptr, body.len);
    }

    /// Parse the target's address space on first use (the workload has mapped
    /// its libraries by the time samples flow). A parse failure just disables
    /// stack symbolization; samples still carry counters.
    fn ensureMaps(self: *Capture, now_ns: u64) void {
        if (self.maps_tried) return;
        self.maps_tried = true;
        self.maps = proc_maps.parse(self.gpa, self.target_pid) catch null;
        self.last_maps_ns = now_ns;
    }

    /// Re-read the target's maps, at most once per second, to pick up libraries
    /// dlopen()'d after the initial parse. Existing mappings keep their interned
    /// iids (keyed by start avma); only new ones are added.
    fn reparseMaps(self: *Capture, now_ns: u64) void {
        if (now_ns -% self.last_maps_ns < std.time.ns_per_s) return;
        self.last_maps_ns = now_ns;
        const fresh = proc_maps.parse(self.gpa, self.target_pid) catch return;
        if (self.maps) |*old| old.deinit();
        self.maps = fresh;
    }

    /// Intern the sample's full callstack and return its iid (0 if empty).
    ///
    /// The frame_ids list is "bottom frame first" (root first, leaf last) — the
    /// order trace_processor assigns depth in, taking the last frame as the leaf
    /// the sample's callsite points to. BPF hands us each section leaf-first, so
    /// we flip each before appending. Kernel frames sit above (are called from)
    /// the user section — a syscall/interrupt boundary — so they come after the
    /// user frames, making the kernel leaf the innermost frame.
    fn internCallstack(self: *Capture, rec: *const c.struct_sismo_sample_rec, idw: *ProtoWriter) u64 {
        var combined: [c.SISMO_MAX_STACK + c.SISMO_MAX_KERNEL_STACK]u64 = undefined;
        var total: usize = 0;

        // User section: resolve each PC to (mapping, file-offset). Skipped when
        // the target's maps couldn't be parsed; kernel frames can still stand.
        self.ensureMaps(rec.hdr.ts);
        if (self.maps != null) {
            const nr: usize = @min(rec.hdr.nr_frames, @as(u32, @intCast(c.SISMO_MAX_STACK)));
            var fids: [c.SISMO_MAX_STACK]u64 = undefined;
            var n: usize = 0;
            var reparsed = false;
            var i: usize = 0;
            while (i < nr) : (i += 1) {
                const pc = rec.stack[i];
                if (pc == 0) continue;
                var m = self.maps.?.find(pc);
                if (m == null and !reparsed) {
                    // A miss may be a freshly dlopen()'d library — reparse once.
                    reparsed = true;
                    self.reparseMaps(rec.hdr.ts);
                    m = self.maps.?.find(pc);
                }
                const mm = m orelse continue;
                // rel_pc is the absolute pc; paired with load_bias = base_avma
                // (see internMapping), `rel_pc - load_bias` is the image-relative
                // address the symbolizer resolves, with a positive per-module base.
                const rel_pc = pc;
                const mapping_iid = self.internMapping(mm, idw) catch return 0;
                const frame_iid = self.internFrame(.{ .mapping_iid = mapping_iid, .rel_pc = rel_pc, .name_iid = 0 }, idw) catch return 0;
                fids[n] = frame_iid;
                n += 1;
            }
            std.mem.reverse(u64, fids[0..n]);
            for (fids[0..n]) |fid| {
                combined[total] = fid;
                total += 1;
            }
        }

        // Kernel section: each id names a frame in the [kernel.kallsyms] mapping
        // (rel_pc 0, name inline). Unknown ids — a definition we never saw, or a
        // kallsyms miss — fall back to "[kernel]".
        const knr: usize = @min(rec.hdr.nr_kernel_frames, @as(u32, @intCast(c.SISMO_MAX_KERNEL_STACK)));
        if (knr > 0) {
            var kfids: [c.SISMO_MAX_KERNEL_STACK]u64 = undefined;
            var kn: usize = 0;
            var kmap: u64 = 0; // 0 = not yet interned (iids start at 1)
            var i: usize = 0;
            while (i < knr) : (i += 1) {
                const id = rec.kernel_ids[i];
                if (id == 0) continue;
                if (kmap == 0) kmap = self.internKernelMapping(idw) catch return 0;
                const name = self.ksym_names.get(id) orelse "[kernel]";
                const name_iid = self.internFuncName(name, idw) catch return 0;
                const frame_iid = self.internFrame(.{ .mapping_iid = kmap, .rel_pc = 0, .name_iid = name_iid }, idw) catch return 0;
                kfids[kn] = frame_iid;
                kn += 1;
            }
            std.mem.reverse(u64, kfids[0..kn]);
            for (kfids[0..kn]) |fid| {
                combined[total] = fid;
                total += 1;
            }
        }

        if (total == 0) return 0;
        return self.internCallstackIds(combined[0..total], idw) catch 0;
    }

    /// Intern `bytes` into `map`, emitting an InternedString { iid=1, str=2 }
    /// under `field` on first sight. `field` is the InternedData field the
    /// string table lives in (17 = mapping_paths, 16 = build_ids).
    fn internString(
        self: *Capture,
        map: *std.StringHashMapUnmanaged(u64),
        next: *u64,
        field: u32,
        bytes: []const u8,
        idw: *ProtoWriter,
    ) !u64 {
        const gop = try map.getOrPut(self.gpa, bytes);
        if (gop.found_existing) return gop.value_ptr.*;
        gop.key_ptr.* = try self.gpa.dupe(u8, bytes);
        const iid = next.*;
        next.* += 1;
        gop.value_ptr.* = iid;
        var s = ProtoWriter.init(self.gpa);
        defer s.deinit();
        try s.writeUint64(1, iid);
        try s.writeString(2, bytes);
        try idw.writeMessage(field, s.bytes());
        return iid;
    }

    fn internPath(self: *Capture, path: []const u8, idw: *ProtoWriter) !u64 {
        return self.internString(&self.interner.paths, &self.interner.next_path, 17, path, idw);
    }

    fn internBuildId(self: *Capture, raw: []const u8, idw: *ProtoWriter) !u64 {
        return self.internString(&self.interner.build_ids, &self.interner.next_build_id, 16, raw, idw);
    }

    fn internFuncName(self: *Capture, name: []const u8, idw: *ProtoWriter) !u64 {
        return self.internString(&self.interner.func_names, &self.interner.next_func_name, 5, name, idw);
    }

    fn internMapping(self: *Capture, m: *const proc_maps.Mapping, idw: *ProtoWriter) !u64 {
        const gop = try self.interner.mappings.getOrPut(self.gpa, m.start);
        if (gop.found_existing) return gop.value_ptr.*;
        const iid = self.interner.next_mapping;
        self.interner.next_mapping += 1;
        gop.value_ptr.* = iid;
        const path_iid = try self.internPath(m.path, idw);
        const build_id_iid: u64 = if (m.build_id.len > 0)
            try self.internBuildId(m.build_id, idw)
        else
            0;
        // InternedData.mappings (19): Mapping { iid=1, build_id=2, start=4,
        // end=5, load_bias=6, exact_offset=8, path_string_ids=7 }. load_bias is
        // the file's base avma: a positive, per-module-distinct base, with
        // `rel_pc(=pc) - load_bias` the image-relative address the symbolizer
        // wants — correct for PIE and non-PIE (start-offset can go negative).
        const load_bias = m.base_avma;
        var mp = ProtoWriter.init(self.gpa);
        defer mp.deinit();
        try mp.writeUint64(1, iid);
        if (build_id_iid != 0) try mp.writeUint64(2, build_id_iid);
        try mp.writeUint64(4, m.start);
        try mp.writeUint64(5, m.end);
        try mp.writeUint64(6, load_bias);
        try mp.writeUint64(8, m.offset);
        try mp.writeUint64(7, path_iid);
        try idw.writeMessage(19, mp.bytes());
        return iid;
    }

    /// The synthetic mapping every kernel frame shares. Named "[kernel.kallsyms]"
    /// so trace_processor classifies the frames as kernel; it carries no address
    /// range or build-id, since kernel frames are named inline (function_name_id)
    /// rather than symbolized offline. Keyed by the sentinel start 0 — real
    /// mappings never start at 0.
    fn internKernelMapping(self: *Capture, idw: *ProtoWriter) !u64 {
        const gop = try self.interner.mappings.getOrPut(self.gpa, 0);
        if (gop.found_existing) return gop.value_ptr.*;
        const iid = self.interner.next_mapping;
        self.interner.next_mapping += 1;
        gop.value_ptr.* = iid;
        const path_iid = try self.internPath("[kernel.kallsyms]", idw);
        var mp = ProtoWriter.init(self.gpa);
        defer mp.deinit();
        try mp.writeUint64(1, iid);
        try mp.writeUint64(7, path_iid);
        try idw.writeMessage(19, mp.bytes());
        return iid;
    }

    fn internFrame(self: *Capture, key: FrameKey, idw: *ProtoWriter) !u64 {
        const gop = try self.interner.frames.getOrPut(self.gpa, key);
        if (gop.found_existing) return gop.value_ptr.*;
        const iid = self.interner.next_frame;
        self.interner.next_frame += 1;
        gop.value_ptr.* = iid;
        // InternedData.frames (6): Frame { iid=1, function_name_id=2,
        // mapping_id=3, rel_pc=4 }. function_name_id is set only for inline-named
        // (kernel) frames; offline-symbolized user frames leave it 0.
        var f = ProtoWriter.init(self.gpa);
        defer f.deinit();
        try f.writeUint64(1, iid);
        if (key.name_iid != 0) try f.writeUint64(2, key.name_iid);
        try f.writeUint64(3, key.mapping_iid);
        try f.writeUint64(4, key.rel_pc);
        try idw.writeMessage(6, f.bytes());
        return iid;
    }

    fn internCallstackIds(self: *Capture, fids: []const u64, idw: *ProtoWriter) !u64 {
        const key_bytes = std.mem.sliceAsBytes(fids);
        const gop = try self.interner.callstacks.getOrPut(self.gpa, key_bytes);
        if (gop.found_existing) return gop.value_ptr.*;
        gop.key_ptr.* = try self.gpa.dupe(u8, key_bytes);
        const iid = self.interner.next_callstack;
        self.interner.next_callstack += 1;
        gop.value_ptr.* = iid;
        // InternedData.callstacks (7): Callstack { iid=1, frame_ids=2 }.
        // frame_ids is bottom-frame-first (root first, leaf last); the caller
        // reverses the leaf-first BPF stack to match.
        var cs = ProtoWriter.init(self.gpa);
        defer cs.deinit();
        try cs.writeUint64(1, iid);
        for (fids) |fid| try cs.writeUint64(2, fid);
        try idw.writeMessage(7, cs.bytes());
        return iid;
    }

    fn onSetup(_: ?*anyopaque, _: ?*const anyopaque, _: usize) callconv(.c) void {}

    fn onStart(user_arg: ?*anyopaque) callconv(.c) void {
        const self: *Capture = @ptrCast(@alignCast(user_arg.?));
        self.need_defaults.store(true, .release);
        self.active.store(true, .release);
    }

    fn onStop(user_arg: ?*anyopaque, _: ?*anyopaque) callconv(.c) void {
        const self: *Capture = @ptrCast(@alignCast(user_arg.?));
        self.active.store(false, .release);
    }

    fn onFlush(_: ?*anyopaque, flusher: ?*anyopaque) callconv(.c) void {
        if (flusher) |f| perfetto.sismo_flush_done(f);
    }
};

fn onEvent(ctx: ?*anyopaque, data: ?*anyopaque, size: usize) callconv(.c) c_int {
    _ = size;
    const self: *Capture = @ptrCast(@alignCast(ctx.?));
    self.handle(@ptrCast(@alignCast(data.?)));
    return 0;
}

fn workerEntry(self: *Capture) void {
    while (!self.exit_requested.load(.acquire)) {
        _ = c.ring_buffer__consume(self.rb);
        const ts: std.c.timespec = .{ .sec = 0, .nsec = 20 * std.time.ns_per_ms };
        _ = std.c.nanosleep(&ts, null);
    }
    _ = c.ring_buffer__consume(self.rb);
}

// Open one counting event (pid=-1, the given cpu) as a member of a perf group:
// `group_fd` = -1 starts a new group (the leader), otherwise joins that leader.
// Members of a group are co-scheduled, so one past the PMU's per-group capacity
// fails to open here and is dropped. Distinct groups, by contrast, are
// time-multiplexed by the kernel — carrying more events than the PMU has
// counters (read_advance scales for it).
fn openCounter(cpu: u32, src: Src, group_fd: i32) ?i32 {
    var attr = std.mem.zeroes(linux.perf_event_attr);
    attr.size = @sizeOf(linux.perf_event_attr);
    switch (src) {
        .hw => |h| {
            attr.type = .HARDWARE;
            attr.config = @intFromEnum(h);
        },
        .raw => |r| {
            attr.type = .RAW;
            attr.config = r;
        },
    }
    const rc = linux.perf_event_open(&attr, -1, @intCast(cpu), group_fd, 0);
    const s: isize = @bitCast(rc);
    return if (s < 0) null else @intCast(s);
}

// Sample on the cycles PMU (CPU_CLK_UNHALTED) at a fixed period rather than a
// wall-clock timer, so every sample is an equal slice of cycles — the same
// denominator the TMA/IPC/MPKI attribution uses. A prime period avoids aliasing
// against code that runs on a regular cadence. ~1M cycles lands near 1-3 kHz
// depending on core clock.
fn openSampler(cpu: u32) ?i32 {
    var attr = std.mem.zeroes(linux.perf_event_attr);
    attr.type = .HARDWARE;
    attr.size = @sizeOf(linux.perf_event_attr);
    attr.config = @intFromEnum(linux.PERF.COUNT.HW.CPU_CYCLES);
    attr.sample_period_or_freq = 1_000_003; // cycles (freq mode left off)
    const rc = linux.perf_event_open(&attr, -1, @intCast(cpu), -1, 0);
    const s: isize = @bitCast(rc);
    return if (s < 0) null else @intCast(s);
}
