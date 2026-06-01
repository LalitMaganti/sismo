// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Hand-rolled byte builders for the Perfetto proto messages sismo
//! emits. The C++ side is glue only — every byte that goes on the wire
//! is built here in Zig.
//!
//! Field numbers are sourced from the vendored proto schemas at
//! `third_party/src/perfetto/protos/...`. Wire format primitives live
//! in `proto_writer.zig`.

const std = @import("std");
const ProtoWriter = @import("proto_writer.zig").ProtoWriter;

// ---------------------------------------------------------------------------
// DataSourceDescriptor (protos/perfetto/common/data_source_descriptor.proto)
//
// Ridden via `sismo_ds_register(desc_bytes, ...)` — Zig builds, C++
// parses with `DataSourceDescriptor::ParseFromArray`.
// ---------------------------------------------------------------------------

pub const DataSourceDescriptor = struct {
    name: []const u8,
    will_notify_on_stop: bool = true,
    will_notify_on_start: bool = false,
    /// Serialized `VmProgram` bytes. Empty = no protovm_program (the
    /// data source is not ProtoVM-backed). When non-empty, traced will
    /// instantiate a per-buffer ProtoVM and apply patch packets to it.
    /// Build via `encodeVmProgram` below.
    protovm_program: []const u8 = &.{},
};

pub fn encodeDataSourceDescriptor(
    gpa: std.mem.Allocator,
    desc: DataSourceDescriptor,
) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    try w.writeString(1, desc.name);
    if (desc.will_notify_on_stop) try w.writeBool(2, true);
    if (desc.will_notify_on_start) try w.writeBool(3, true);
    if (desc.protovm_program.len > 0) try w.writeMessage(10, desc.protovm_program);
    return w.buf.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// TraceConfig (protos/perfetto/config/trace_config.proto)
//
// Built consumer-side, parsed by `TracingSession::Setup`. Sismo
// supports three modes (`Mode` below) which map to combinations of
// fill_policy + write_into_file / duration_ms.
// ---------------------------------------------------------------------------

pub const Mode = enum { ring, capped, file };

pub const TrackEventEntry = struct {
    /// `enabled_categories`. "*" = all categories.
    enabled_categories: []const []const u8 = &.{"*"},
};

pub const SismoVendorEntry = struct {
    /// e.g. "sismo.macos_sched", "sismo.heap", "sismo.macos_cpu_samples".
    name: []const u8,
    /// Serialized SismoXxxConfig bytes (sismo_config.zig encoders).
    /// Goes into `DataSourceConfig.sismo_config` (vendor field 2000).
    sismo_config: []const u8 = &.{},
    /// When non-zero, traced runs the producer's `protovm_program`
    /// against patch packets up to this memory cap. Triggers two side
    /// effects on the encoded TraceConfig: the data source's
    /// `DataSourceConfig.protovm_config.memory_limit_kb` is set, and
    /// the BufferConfig that carries this DS is forced to V2 (ProtoVM
    /// is V2-only). Zero (default) skips ProtoVM entirely.
    protovm_memory_limit_kb: u32 = 0,
};

pub const LinuxFtraceEntry = struct {
    // Today: hardcoded sched events. Future: configurable.
};

/// One entry per `data_sources { config { ... } }` block in the
/// TraceConfig. Sismo builds this set from per-DS toggles in
/// cmd_record.zig; cmd_datasource.zig only ever has a producer-side
/// view, never builds TraceConfigs. Linux CPU sampling is the in-process BPF
/// collector (a `sismo_vendor` source), not an upstream perf data source.
pub const DataSourceEntry = union(enum) {
    track_event: TrackEventEntry,
    sismo_vendor: SismoVendorEntry,
    linux_ftrace: LinuxFtraceEntry,
};

pub const TraceConfig = struct {
    mode: Mode,
    buffer_size_kb: u32,
    duration_ms: u32 = 0, // honored only when mode == .capped
    output_path: []const u8 = "", // honored only when mode == .file
    max_file_size_bytes: u64 = 0, // honored only when mode == .file
    data_sources: []const DataSourceEntry,
    /// Sets `unique_session_name` so an external consumer (e.g.
    /// `sismo snapshot`) can attach via CloneTrace by name. Sismo
    /// always uses "sismo_record" today; callers shouldn't override
    /// unless they're doing something exotic.
    session_name: []const u8 = "sismo_record",
};

const DSC_SISMO_CONFIG_FIELD: u32 = 2000;
const DSC_TRACK_EVENT_CONFIG_FIELD: u32 = 113;
const DSC_FTRACE_CONFIG_FIELD: u32 = 100;
const DSC_PROTOVM_CONFIG_FIELD: u32 = 12;

fn encodeTrackEventConfig(gpa: std.mem.Allocator, te: TrackEventEntry) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    // TrackEventConfig.enabled_categories = repeated string field 2.
    // (Field 1 is `disabled_categories` — writing "*" there disables
    // EVERYTHING, the exact inverse. Caught after sample-target's
    // track_event packets vanished; trace_config dump showed
    // `disabled_categories: "*"`.)
    for (te.enabled_categories) |cat| try w.writeString(2, cat);
    return w.buf.toOwnedSlice(gpa);
}

/// FtraceConfig: emits sched_switch / sched_waking / sched_wakeup /
/// sched_process_exit + power/cpu_frequency + power/cpu_idle +
/// compact_sched.enabled. Field numbers per
/// `protos/perfetto/config/ftrace/ftrace_config.proto`:
///   ftrace_events = 1 (repeated string)
///   compact_sched = 12 (CompactSchedConfig submsg; .enabled = field 1)
///
/// power/cpu_frequency + power/cpu_idle drive trace_processor's `cpufreq`
/// / `cpuidle` counter tracks, which the `linux.cpu.utilization.*` stdlib
/// turns into the megacycle / frequency figures the CPU views read. DVFS
/// tracepoints only fire on a transition, so a core pinned at one
/// frequency for the whole trace yields no events — the views degrade to
/// runtime-only and hide the frequency-derived numbers.
fn encodeFtraceConfig(gpa: std.mem.Allocator, _: LinuxFtraceEntry) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    const events = [_][]const u8{
        "sched/sched_switch",
        "sched/sched_waking",
        "sched/sched_wakeup",
        "sched/sched_process_exit",
        "power/cpu_frequency",
        "power/cpu_idle",
    };
    for (events) |e| try w.writeString(1, e);

    var compact = ProtoWriter.init(gpa);
    defer compact.deinit();
    try compact.writeBool(1, true); // CompactSchedConfig.enabled
    try w.writeMessage(12, compact.bytes());
    return w.buf.toOwnedSlice(gpa);
}

fn encodeDataSourceConfig(
    gpa: std.mem.Allocator,
    entry: DataSourceEntry,
) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    switch (entry) {
        .track_event => |te| {
            try w.writeString(1, "track_event");
            const tec = try encodeTrackEventConfig(gpa, te);
            defer gpa.free(tec);
            try w.writeMessage(DSC_TRACK_EVENT_CONFIG_FIELD, tec);
        },
        .sismo_vendor => |sv| {
            try w.writeString(1, sv.name);
            if (sv.sismo_config.len > 0) {
                try w.writeMessage(DSC_SISMO_CONFIG_FIELD, sv.sismo_config);
            }
            if (sv.protovm_memory_limit_kb > 0) {
                var pvc = ProtoWriter.init(gpa);
                defer pvc.deinit();
                // ProtoVmConfig.memory_limit_kb (field 1, uint32).
                try pvc.writeUint32(1, sv.protovm_memory_limit_kb);
                try w.writeMessage(DSC_PROTOVM_CONFIG_FIELD, pvc.bytes());
                // No target_buffer override — sismo runs everything
                // on a single V2 buffer (index 0). traced sets up
                // the per-buffer Vm instance there automatically.
            }
        },
        .linux_ftrace => |lf| {
            try w.writeString(1, "linux.ftrace");
            const fc = try encodeFtraceConfig(gpa, lf);
            defer gpa.free(fc);
            try w.writeMessage(DSC_FTRACE_CONFIG_FIELD, fc);
        },
    }
    return w.buf.toOwnedSlice(gpa);
}

fn encodeBufferConfig(
    gpa: std.mem.Allocator,
    size_kb: u32,
    fill_policy: u32, // 0=UNSPECIFIED, 1=RING_BUFFER, 2=DISCARD
    experimental_v2: bool,
) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    try w.writeUint32(1, size_kb); // size_kb
    if (fill_policy != 0) try w.writeUint32(4, fill_policy); // fill_policy
    if (experimental_v2) try w.writeUint32(8, 1); // experimental_mode = TRACE_BUFFER_V2
    return w.buf.toOwnedSlice(gpa);
}

pub fn encodeTraceConfig(
    gpa: std.mem.Allocator,
    cfg: TraceConfig,
) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();

    // buffers (field 1, repeated BufferConfig). FILE mode uses
    // RING_BUFFER per Perfetto's recommendation — DISCARD with
    // write_into_file causes silent data loss. Single buffer for
    // everything, always V2 — required by ProtoVM (`sismo.macos_sched`),
    // tolerated by the InternedData-heavy sources (track_event /
    // heap / perf_sample) once trace_processor's ProtoVm cascade is
    // well-behaved (DST shape correct, memory cap large enough).
    {
        const fp: u32 = if (cfg.mode == .capped) 2 else 1;
        const buf_msg = try encodeBufferConfig(gpa, cfg.buffer_size_kb, fp, true);
        defer gpa.free(buf_msg);
        try w.writeMessage(1, buf_msg);
    }

    // data_sources (field 2, repeated DataSource).
    // DataSource.config = field 1.
    for (cfg.data_sources) |entry| {
        const dsc = try encodeDataSourceConfig(gpa, entry);
        defer gpa.free(dsc);
        var ds_msg = ProtoWriter.init(gpa);
        defer ds_msg.deinit();
        try ds_msg.writeMessage(1, dsc);
        try w.writeMessage(2, ds_msg.bytes());
    }

    // unique_session_name (field 22).
    try w.writeString(22, cfg.session_name);

    switch (cfg.mode) {
        .ring => {},
        .capped => {
            try w.writeUint32(3, cfg.duration_ms); // duration_ms
        },
        .file => {
            try w.writeBool(8, true); // write_into_file
            try w.writeUint64(10, cfg.max_file_size_bytes); // max_file_size_bytes
            try w.writeUint32(9, 1000); // file_write_period_ms — flush ring → file
            try w.writeString(29, cfg.output_path); // output_path
        },
    }

    return w.buf.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// TracePacket envelope helpers
//
// `sismo_ds_emit(slot, packet_bytes, len)` accepts the *body* of a
// TracePacket (the field-tagged contents inside a NewTracePacket()
// handle). The C++ glue wraps it; these builders take a payload +
// timestamp and emit the body bytes.
// ---------------------------------------------------------------------------

const TP_FIELD_TIMESTAMP: u32 = 8;
const TP_FIELD_SEQUENCE_FLAGS: u32 = 13;

/// Build a TracePacket body containing (timestamp, sequence_flags?,
/// payload-as-field). `payload_field_tag` is the field number inside
/// TracePacket where the payload sits (e.g. 66 for perf_sample, 117 for
/// generic_kernel_task_state_event). `payload_bytes` is the already-
/// encoded sub-message body. Pass `sequence_flags = 0` to omit the field.
pub fn encodeTracePacketBody(
    gpa: std.mem.Allocator,
    timestamp_ns: u64,
    sequence_flags: u32,
    payload_field_tag: u32,
    payload_bytes: []const u8,
) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    if (timestamp_ns != 0) try w.writeUint64(TP_FIELD_TIMESTAMP, timestamp_ns);
    if (sequence_flags != 0) try w.writeUint32(TP_FIELD_SEQUENCE_FLAGS, sequence_flags);
    try w.writeMessage(payload_field_tag, payload_bytes);
    return w.buf.toOwnedSlice(gpa);
}

/// In-place variant of `encodeTracePacketBody` for hot-path callers
/// that hold a persistent scratch `*ProtoWriter`. Caller is
/// responsible for `clear()`-ing the writer before each use.
pub fn encodeTracePacketBodyInto(
    w: *ProtoWriter,
    timestamp_ns: u64,
    payload_field_tag: u32,
    payload_bytes: []const u8,
) !void {
    if (timestamp_ns != 0) try w.writeUint64(TP_FIELD_TIMESTAMP, timestamp_ns);
    try w.writeMessage(payload_field_tag, payload_bytes);
}

// ---------------------------------------------------------------------------
// PerfSample (TracePacket field 17)
// schema: protos/perfetto/trace/profiling/perf_sample.proto
// ---------------------------------------------------------------------------

pub const TP_FIELD_PERF_SAMPLE: u32 = 66;
pub const TP_FIELD_TRACE_PACKET_DEFAULTS: u32 = 59;

/// TracePacket.sequence_flags values (trace_packet.proto SequenceFlags).
pub const SEQ_INCREMENTAL_STATE_CLEARED: u32 = 1;
pub const SEQ_NEEDS_INCREMENTAL_STATE: u32 = 2;

pub const PerfSample = struct {
    cpu: u32,
    pid: u32,
    tid: u32,
    /// 0 = no callstack (proto absence semantic).
    callstack_iid: u64 = 0,
    /// Cumulative timebase counter reading for this sample (field 6). 0 omits.
    timebase_count: u64 = 0,
    /// Cumulative follower counter readings (field 7), in the same order as
    /// `PerfSampleDefaults.followers`.
    follower_counts: []const u64 = &.{},
};

pub fn encodePerfSample(gpa: std.mem.Allocator, s: PerfSample) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    // PerfSample.cpu = 1, pid = 2, tid = 3, callstack_iid = 4, timebase_count
    // = 6, follower_counts = 7 — matches profiling/profile_packet.proto.
    try w.writeUint32(1, s.cpu);
    try w.writeUint32(2, s.pid);
    try w.writeUint32(3, s.tid);
    if (s.callstack_iid != 0) try w.writeUint64(4, s.callstack_iid);
    if (s.timebase_count != 0) try w.writeUint64(6, s.timebase_count);
    for (s.follower_counts) |fc| try w.writeUint64(7, fc);
    return w.buf.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// PerfSampleDefaults + TracePacketDefaults
// schema: profiling/profile_packet.proto, trace_packet_defaults.proto
//
// Emitted once per sequence on a SEQ_INCREMENTAL_STATE_CLEARED packet; every
// later PerfSample on the same sequence inherits the timebase/follower names
// and the sample scope.
// ---------------------------------------------------------------------------

/// PerfSampleDefaults.SampleScope (sismo extension). THREAD makes each sample's
/// counters per-thread, routed to thread-scoped counter tracks.
pub const SampleScope = enum(u32) {
    unspecified = 0,
    cpu = 1,
    thread = 2,
};

/// A named counting event. `name` becomes the counter track's display name.
pub const PerfEventName = struct {
    name: []const u8,
    /// PerfEvents.Timebase.frequency (informational; 0 omits). Only meaningful
    /// on the timebase.
    frequency: u64 = 0,
};

pub const PerfSampleDefaults = struct {
    timebase: PerfEventName,
    followers: []const PerfEventName = &.{},
    sample_scope: SampleScope = .unspecified,
};

pub fn encodePerfSampleDefaults(
    gpa: std.mem.Allocator,
    d: PerfSampleDefaults,
) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();

    // timebase = 1 (PerfEvents.Timebase: frequency = 2, name = 10).
    {
        var tb = ProtoWriter.init(gpa);
        defer tb.deinit();
        if (d.timebase.frequency != 0) try tb.writeUint64(2, d.timebase.frequency);
        try tb.writeString(10, d.timebase.name);
        try w.writeMessage(1, tb.bytes());
    }

    // followers = 4 (repeated FollowerEvent: name = 4).
    for (d.followers) |f| {
        var fe = ProtoWriter.init(gpa);
        defer fe.deinit();
        try fe.writeString(4, f.name);
        try w.writeMessage(4, fe.bytes());
    }

    // sample_scope = 5 (sismo extension).
    if (d.sample_scope != .unspecified) {
        try w.writeEnum(5, d.sample_scope);
    }
    return w.buf.toOwnedSlice(gpa);
}

/// BuiltinClock values (clock_snapshot.proto). MONOTONIC matches
/// bpf_ktime_get_ns().
pub const BUILTIN_CLOCK_MONOTONIC: u32 = 3;

/// Wrap PerfSampleDefaults bytes in a TracePacketDefaults
/// (perf_sample_defaults = field 12, timestamp_clock_id = field 58). The
/// result is the payload for
/// `encodeTracePacketBody(..., TP_FIELD_TRACE_PACKET_DEFAULTS, ...)`.
/// `timestamp_clock_id` = 0 omits the field (inherits the trace default).
pub fn encodeTracePacketDefaults(
    gpa: std.mem.Allocator,
    timestamp_clock_id: u32,
    perf_sample_defaults: []const u8,
) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    if (timestamp_clock_id != 0) try w.writeUint32(58, timestamp_clock_id);
    try w.writeMessage(12, perf_sample_defaults);
    return w.buf.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// GenericKernelTaskStateEvent (TracePacket field 117)
// schema: protos/perfetto/trace/generic_kernel/generic_task.proto
// ---------------------------------------------------------------------------

pub const TP_FIELD_GENERIC_KERNEL_TASK_STATE: u32 = 117;

pub const TaskState = enum(u32) {
    unknown = 0,
    created = 1,
    runnable = 2,
    running = 3,
    interruptible_sleep = 4,
    uninterruptible_sleep = 5,
    stopped = 6,
    dead = 7,
    destroyed = 8,
};

pub const KernelTaskStateEvent = struct {
    cpu: i32,
    comm: []const u8,
    tid: i64,
    state: TaskState,
    prio: i32,
};

pub fn encodeKernelTaskStateEvent(
    gpa: std.mem.Allocator,
    e: KernelTaskStateEvent,
) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    try encodeKernelTaskStateEventInto(&w, e);
    return w.buf.toOwnedSlice(gpa);
}

/// In-place variant for hot-path callers holding a persistent
/// `*ProtoWriter`. Caller `clear()`s before each call.
pub fn encodeKernelTaskStateEventInto(
    w: *ProtoWriter,
    e: KernelTaskStateEvent,
) !void {
    // Cap comm at 64 chars defensively (Mach thread name max in
    // practice). The C-side did this; preserve.
    const comm_capped = if (e.comm.len > 64) e.comm[0..64] else e.comm;
    try w.writeInt32(1, e.cpu);
    if (comm_capped.len > 0) try w.writeString(2, comm_capped);
    try w.writeInt64(3, e.tid);
    try w.writeEnum(4, e.state);
    try w.writeInt32(5, e.prio);
}

// ---------------------------------------------------------------------------
// GenericKernelProcessTree (TracePacket field 122)
// schema: protos/perfetto/trace/generic_kernel/generic_task.proto
//
// Direct full-tree dumps from the producer. Each emit replaces
// trace_processor's view of the listed pids/tids; missing entries are
// preserved (the schema is incremental, not exhaustive). Used as the
// stop-gap for thread/process-name attribution while the ProtoVM-backed
// patch path lands behind a flight-recorder gate.
// ---------------------------------------------------------------------------

pub const TP_FIELD_GENERIC_KERNEL_PROCESS_TREE: u32 = 122;

pub const ProcessEntry = struct {
    pid: i64,
    ppid: i64 = 0,
    cmdline: []const u8 = "",
};

pub const ThreadEntry = struct {
    tid: i64,
    pid: i64,
    comm: []const u8 = "",
    is_main_thread: bool = false,
    is_idle: bool = false,
};

fn encodeProcess(gpa: std.mem.Allocator, p: ProcessEntry) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    // Process.pid = 1, ppid = 2, cmdline = 3.
    try w.writeInt64(1, p.pid);
    if (p.ppid != 0) try w.writeInt64(2, p.ppid);
    if (p.cmdline.len > 0) try w.writeString(3, p.cmdline);
    return w.buf.toOwnedSlice(gpa);
}

fn encodeThread(gpa: std.mem.Allocator, t: ThreadEntry) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    // Thread.tid = 1, pid = 2, comm = 3, is_main_thread = 4, is_idle = 5.
    try w.writeInt64(1, t.tid);
    try w.writeInt64(2, t.pid);
    if (t.comm.len > 0) try w.writeString(3, t.comm);
    if (t.is_main_thread) try w.writeBool(4, true);
    if (t.is_idle) try w.writeBool(5, true);
    return w.buf.toOwnedSlice(gpa);
}

/// Build a `GenericKernelProcessTree` payload (the inner message that
/// rides at TracePacket field 122). The caller wraps the returned
/// bytes with `encodeTracePacketBody`.
pub fn encodeKernelProcessTree(
    gpa: std.mem.Allocator,
    processes: []const ProcessEntry,
    threads: []const ThreadEntry,
) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    for (processes) |p| {
        const pb = try encodeProcess(gpa, p);
        defer gpa.free(pb);
        try w.writeMessage(1, pb);
    }
    for (threads) |t| {
        const tb = try encodeThread(gpa, t);
        defer gpa.free(tb);
        try w.writeMessage(2, tb);
    }
    return w.buf.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// VmProgram (protos/perfetto/protovm/vm_program.proto)
//
// Sismo-side byte builders for ProtoVM bytecode. We hand-roll these
// rather than pull in a generated proto encoder — the schema's small
// (5 ops, one nesting level for sub-instructions) and the encoder
// sits in the cold path (program is built once at startup, encoded
// once into the DataSourceDescriptor).
//
// Wire format (proto2):
//   VmProgram.version       = 1, optional uint32
//   VmProgram.instructions  = 2, repeated VmInstruction
//
//   VmInstruction.select               = 1, oneof
//   VmInstruction.reg_load             = 2, oneof
//   VmInstruction.merge                = 3, oneof
//   VmInstruction.set                  = 4, oneof
//   VmInstruction.del                  = 5, oneof
//   VmInstruction.abort_level          = 6, optional enum
//   VmInstruction.nested_instructions  = 7, repeated VmInstruction
//
//   VmOpSelect.cursor               = 1, optional VmCursorEnum
//   VmOpSelect.relative_path        = 2, repeated PathComponent
//   VmOpSelect.create_if_not_exist  = 3, optional bool
//
//   PathComponent.field_id                          = 1, oneof
//   PathComponent.array_index                       = 2, oneof
//   PathComponent.map_key_field_id                  = 3, oneof
//   PathComponent.is_repeated                       = 5, optional bool
//   PathComponent.register_to_match                 = 6, optional uint32
//   PathComponent.store_foreach_index_into_register = 7, optional uint32
//
//   VmOpRegLoad.cursor       = 1, optional VmCursorEnum
//   VmOpRegLoad.dst_register = 2, optional uint32
//
//   VmOpMerge.skip_submessages = 1, optional bool
// ---------------------------------------------------------------------------

pub const Cursor = enum(u32) {
    unspecified = 0,
    src = 1,
    dst = 2,
    both = 3,
};

pub const AbortLevel = enum(u32) {
    /// Default = SKIP_CURRENT_INSTRUCTION_AND_BREAK_OUTER (proto2
    /// "default" in the schema's enum docstring). 0 here means "leave
    /// the field unset"; absence picks the proto2 default.
    unset = 0,
    skip_current = 1,
    skip_current_break_outer = 2,
    abort = 3,
};

pub const PathComponent = struct {
    /// Exactly one of field_id / array_index / map_key_field_id is
    /// non-null (the proto's `oneof field`). Non-null = use that
    /// variant; the others must be null for the component to be valid.
    field_id: ?u32 = null,
    array_index: ?u32 = null,
    map_key_field_id: ?u32 = null,
    is_repeated: bool = false,
    register_to_match: ?u32 = null,
    store_foreach_index_into_register: ?u32 = null,
};

fn encodePathComponent(gpa: std.mem.Allocator, pc: PathComponent) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    if (pc.field_id) |v| try w.writeUint32(1, v);
    if (pc.array_index) |v| try w.writeUint32(2, v);
    if (pc.map_key_field_id) |v| try w.writeUint32(3, v);
    if (pc.is_repeated) try w.writeBool(5, true);
    if (pc.register_to_match) |v| try w.writeUint32(6, v);
    if (pc.store_foreach_index_into_register) |v| try w.writeUint32(7, v);
    return w.buf.toOwnedSlice(gpa);
}

pub const Select = struct {
    cursor: Cursor = .unspecified,
    relative_path: []const PathComponent = &.{},
    create_if_not_exist: bool = false,
};

pub const RegLoad = struct {
    cursor: Cursor = .unspecified,
    dst_register: u32 = 0,
};

pub const Merge = struct { skip_submessages: bool = false };
pub const Set = struct {};
pub const Del = struct {};

pub const Op = union(enum) {
    select: Select,
    reg_load: RegLoad,
    merge: Merge,
    set: Set,
    del: Del,
};

pub const Instruction = struct {
    op: Op,
    abort_level: AbortLevel = .unset,
    nested: []const Instruction = &.{},
};

fn encodeSelect(gpa: std.mem.Allocator, s: Select) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    if (s.cursor != .unspecified) try w.writeEnum(1, s.cursor);
    for (s.relative_path) |pc| {
        const pcb = try encodePathComponent(gpa, pc);
        defer gpa.free(pcb);
        try w.writeMessage(2, pcb);
    }
    if (s.create_if_not_exist) try w.writeBool(3, true);
    return w.buf.toOwnedSlice(gpa);
}

fn encodeRegLoad(gpa: std.mem.Allocator, r: RegLoad) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    if (r.cursor != .unspecified) try w.writeEnum(1, r.cursor);
    try w.writeUint32(2, r.dst_register);
    return w.buf.toOwnedSlice(gpa);
}

fn encodeMerge(gpa: std.mem.Allocator, m: Merge) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    if (m.skip_submessages) try w.writeBool(1, true);
    return w.buf.toOwnedSlice(gpa);
}

fn encodeInstruction(gpa: std.mem.Allocator, ins: Instruction) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    switch (ins.op) {
        .select => |s| {
            const sb = try encodeSelect(gpa, s);
            defer gpa.free(sb);
            try w.writeMessage(1, sb);
        },
        .reg_load => |r| {
            const rb = try encodeRegLoad(gpa, r);
            defer gpa.free(rb);
            try w.writeMessage(2, rb);
        },
        .merge => |m| {
            const mb = try encodeMerge(gpa, m);
            defer gpa.free(mb);
            try w.writeMessage(3, mb);
        },
        .set => {
            // VmOpSet has no fields; emit an empty length-delimited
            // sub-message so the oneof tag is present.
            try w.writeMessage(4, &.{});
        },
        .del => {
            try w.writeMessage(5, &.{});
        },
    }
    if (ins.abort_level != .unset) {
        try w.writeEnum(6, ins.abort_level);
    }
    for (ins.nested) |n| {
        const nb = try encodeInstruction(gpa, n);
        defer gpa.free(nb);
        try w.writeMessage(7, nb);
    }
    return w.buf.toOwnedSlice(gpa);
}

pub const VmProgram = struct {
    version: u32 = 0,
    instructions: []const Instruction = &.{},
};

pub fn encodeVmProgram(gpa: std.mem.Allocator, prog: VmProgram) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    if (prog.version != 0) try w.writeUint32(1, prog.version);
    for (prog.instructions) |ins| {
        const ib = try encodeInstruction(gpa, ins);
        defer gpa.free(ib);
        try w.writeMessage(2, ib);
    }
    return w.buf.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// macos_sched ProtoVM program
//
// Mirrors `GenericKernelProcessTree` packets emitted by the sched
// producer into traced's per-buffer ProtoVM DST state. In flight-
// recorder (ring) mode the ring eventually overwrites old packets;
// without this program the consumer sees only whichever packets
// happened to survive in the ring at read time, so long-lived threads
// lose their names. With the program, traced intercepts overwritten
// packets, applies them as merges into a maintained DST, and surfaces
// the DST verbatim in `TracePacket.protovms.instance.state` at
// trace-read time. The DST shape mirrors `GenericKernelProcessTree`
// exactly so trace_processor consumes it without further translation.
//
// In file mode the ring never overwrites — the program never runs and
// adds zero overhead. The protovm_program in the descriptor is inert.
//
// Field number reference (TracePacket -> GenericKernelProcessTree ->
// {Process, Thread}) is sourced from
// `protos/perfetto/trace/{trace_packet, generic_kernel/generic_task}.proto`.
// ---------------------------------------------------------------------------

/// Build the VmProgram bytes for the macos_sched data source. Caller
/// owns the returned slice; pass it as `protovm_program` to
/// `encodeDataSourceDescriptor`. Bounded allocation; a few hundred
/// bytes total.
///
/// **DST shape matters.** trace_processor's
/// `ProtoVmIncrementalTracing::TryProcessPatch` synthesizes a
/// TracePacket from the DST by serializing the DST's root *directly*
/// into a `TracePacket*`, so the DST's top-level fields end up as
/// TracePacket's fields. So the DST is keyed under field 122
/// (`TracePacket.generic_kernel_process_tree`) — anything else would
/// alias TracePacket's field 1 as `FtraceEventBundle`, reinterpreting the
/// first stored pid as `FtraceEventBundle.cpu` and tripping
/// trace_processor's `cpu < 1024` corruption check on load. (Caught
/// 2026-05-02 by traceconv: "CPU 80881 is greater than maximum allowed
/// of 1024".)
pub fn macosSchedVmProgram(gpa: std.mem.Allocator) ![]u8 {
    // Field numbers — mirrored across SRC and DST. SRC patches are
    // emitted as TracePackets carrying `generic_kernel_process_tree`
    // at field 122 (an inline GenericKernelProcessTree submessage);
    // DST is shaped as a TracePacket too, with its own field 122
    // holding the maintained tree. So the path to the same
    // `processes`/`threads` slots is `[122, 1|2, ...]` on both
    // sides — symmetric.
    const tp_tree: u32 = TP_FIELD_GENERIC_KERNEL_PROCESS_TREE;
    const f_processes: u32 = 1;
    const f_threads: u32 = 2;
    const f_process_pid: u32 = 1;
    const f_thread_tid: u32 = 1;
    const reg: u32 = 0; // R0 holds the merge-key (pid or tid) per iteration.

    const proc_block: Instruction = .{
        // foreach Process in patch.processes — each iteration leaves
        // SRC pointed at the Process body so the nested instructions
        // can read its fields and key its DST counterpart.
        .op = .{ .select = .{
            .relative_path = &.{.{ .field_id = f_processes, .is_repeated = true }},
        } },
        // SKIP_CURRENT: if the patch has no `processes` field, skip this
        // block but still try the threads block. Default BREAK_OUTER would
        // wrongly skip threads too.
        .abort_level = .skip_current,
        .nested = &.{
            // Read Process.pid → R0
            .{
                .op = .{ .select = .{
                    .relative_path = &.{.{ .field_id = f_process_pid }},
                } },
                .nested = &.{.{ .op = .{ .reg_load = .{ .dst_register = reg } } }},
            },
            // Select-or-create
            // DST.generic_kernel_process_tree.processes[pid=R0],
            // merge SRC Process into it. The leading `field_id =
            // tp_tree` step is what keeps the DST root TracePacket-
            // shaped (see fn-level doc).
            .{
                .op = .{ .select = .{
                    .cursor = .dst,
                    .create_if_not_exist = true,
                    .relative_path = &.{
                        .{ .field_id = tp_tree },
                        .{ .field_id = f_processes },
                        .{ .map_key_field_id = f_process_pid, .register_to_match = reg },
                    },
                } },
                .nested = &.{.{ .op = .{ .merge = .{} } }},
            },
        },
    };

    const thread_block: Instruction = .{
        .op = .{ .select = .{
            .relative_path = &.{.{ .field_id = f_threads, .is_repeated = true }},
        } },
        .abort_level = .skip_current,
        .nested = &.{
            .{
                .op = .{ .select = .{
                    .relative_path = &.{.{ .field_id = f_thread_tid }},
                } },
                .nested = &.{.{ .op = .{ .reg_load = .{ .dst_register = reg } } }},
            },
            .{
                .op = .{ .select = .{
                    .cursor = .dst,
                    .create_if_not_exist = true,
                    .relative_path = &.{
                        .{ .field_id = tp_tree },
                        .{ .field_id = f_threads },
                        .{ .map_key_field_id = f_thread_tid, .register_to_match = reg },
                    },
                } },
                .nested = &.{.{ .op = .{ .merge = .{} } }},
            },
        },
    };

    // Top-level: descend SRC into TracePacket.generic_kernel_process_tree.
    // For non-tree packets (sched events from this same producer) the
    // field is absent, so the program halts via the default BREAK_OUTER.
    const top: Instruction = .{
        .op = .{ .select = .{
            .relative_path = &.{.{ .field_id = tp_tree }},
        } },
        .nested = &.{ proc_block, thread_block },
    };

    return encodeVmProgram(gpa, .{ .instructions = &.{top} });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "encodeBufferConfig emits experimental_mode V2" {
    const bytes = try encodeBufferConfig(std.testing.allocator, 1024, 1, true);
    defer std.testing.allocator.free(bytes);
    // Look for tag 8<<3|0 = 0x40, value 1.
    var found = false;
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        if (bytes[i] == 0x40 and i + 1 < bytes.len and bytes[i + 1] == 0x01) found = true;
    }
    try std.testing.expect(found);
}

test "encodeVmProgram empty roundtrips to a single varint=0 prefix or zero bytes" {
    const bytes = try encodeVmProgram(std.testing.allocator, .{});
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqual(@as(usize, 0), bytes.len);
}

test "encodeVmProgram with one Del instruction" {
    const ins = [_]Instruction{.{ .op = .{ .del = .{} } }};
    const bytes = try encodeVmProgram(std.testing.allocator, .{ .instructions = &ins });
    defer std.testing.allocator.free(bytes);
    // Expected wire: tag(2)<<3|2 = 0x12, len=N, [tag(5)<<3|2 = 0x2a, len=0]
    // Inner: 0x2a 0x00 → 2 bytes; outer wraps that with 0x12 0x02.
    const expected = [_]u8{ 0x12, 0x02, 0x2a, 0x00 };
    try std.testing.expectEqualSlices(u8, &expected, bytes);
}

test "encodeKernelProcessTree single thread" {
    const threads = [_]ThreadEntry{.{ .tid = 7, .pid = 3, .comm = "hi" }};
    const bytes = try encodeKernelProcessTree(std.testing.allocator, &.{}, &threads);
    defer std.testing.allocator.free(bytes);
    // Wire format expected (Thread submessage at field 2):
    //   outer: tag(2<<3|2)=0x12, len=N, body
    //   body:  tag(1<<3|0)=0x08, varint(7)
    //          tag(2<<3|0)=0x10, varint(3)
    //          tag(3<<3|2)=0x1a, varint(2), 'h', 'i'
    // body = 08 07 10 03 1a 02 68 69  → 8 bytes
    const expected = [_]u8{ 0x12, 0x08, 0x08, 0x07, 0x10, 0x03, 0x1a, 0x02, 'h', 'i' };
    try std.testing.expectEqualSlices(u8, &expected, bytes);
}

test "macosSchedVmProgram matches Perfetto's gen-proto serialization byte-for-byte" {
    // Reference bytes come from a `protos::gen::VmProgram` of the same
    // structure (TracePacket field 122 → foreach Process → merge into
    // DST.processes; foreach Thread → merge into DST.threads), serialized
    // via SerializeAsString() and hex-dumped. Any drift in the Zig encoder
    // from the proto wire format is caught here before the bytes reach
    // traced. Regenerate via the C++ scratch program in the encoder
    // doc-comment if the program structure intentionally changes.
    const expected_hex =
        "126e0a041202087a3a320a0612040801280130013a0c0a04120208013a041" ++
        "20210003a180a1208021202087a1202080112041801300018013a021a003" ++
        "a320a0612040802280130013a0c0a04120208013a04120210003a180a120" ++
        "8021202087a1202080212041801300018013a021a00";
    const bytes = try macosSchedVmProgram(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    var hex_buf: [4096]u8 = undefined;
    var i: usize = 0;
    for (bytes) |b| {
        const w = try std.fmt.bufPrint(hex_buf[i..], "{x:0>2}", .{b});
        i += w.len;
    }
    try std.testing.expectEqualSlices(u8, expected_hex, hex_buf[0..i]);
}

test "encodePerfSample carries timebase + follower counts" {
    const counts = [_]u64{ 100, 200 };
    const bytes = try encodePerfSample(std.testing.allocator, .{
        .cpu = 1,
        .pid = 7,
        .tid = 9,
        .timebase_count = 4242,
        .follower_counts = &counts,
    });
    defer std.testing.allocator.free(bytes);
    // timebase_count is field 6 (tag 6<<3|0 = 0x30); follower_counts field 7
    // (tag 7<<3|0 = 0x38) appears once per value.
    var saw_timebase = false;
    var followers: usize = 0;
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        if (bytes[i] == 0x30) saw_timebase = true;
        if (bytes[i] == 0x38) followers += 1;
    }
    try std.testing.expect(saw_timebase);
    try std.testing.expectEqual(@as(usize, 2), followers);
}

test "encodePerfSampleDefaults emits thread scope" {
    const followers = [_]PerfEventName{.{ .name = "instructions" }};
    const bytes = try encodePerfSampleDefaults(std.testing.allocator, .{
        .timebase = .{ .name = "cpu-cycles", .frequency = 1000 },
        .followers = &followers,
        .sample_scope = .thread,
    });
    defer std.testing.allocator.free(bytes);
    // sample_scope = field 5 (tag 5<<3|0 = 0x28), value 2 (THREAD).
    var found = false;
    var i: usize = 0;
    while (i + 1 < bytes.len) : (i += 1) {
        if (bytes[i] == 0x28 and bytes[i + 1] == 0x02) found = true;
    }
    try std.testing.expect(found);
}

test "encodeDataSourceConfig sismo_vendor with protovm_memory_limit" {
    const entry: DataSourceEntry = .{ .sismo_vendor = .{
        .name = "sismo.x",
        .protovm_memory_limit_kb = 128,
    } };
    const bytes = try encodeDataSourceConfig(std.testing.allocator, entry);
    defer std.testing.allocator.free(bytes);
    // Look for tag (12<<3|2)=0x62 followed by ProtoVmConfig {
    //   memory_limit_kb=128 (tag (1<<3|0)=0x08, varint(128)=0x80 0x01)
    // }: outer = 0x62 0x03 0x08 0x80 0x01.
    var found = false;
    var i: usize = 0;
    while (i + 4 < bytes.len) : (i += 1) {
        if (bytes[i] == 0x62 and bytes[i + 1] == 0x03 and bytes[i + 2] == 0x08 and bytes[i + 3] == 0x80 and bytes[i + 4] == 0x01) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}
