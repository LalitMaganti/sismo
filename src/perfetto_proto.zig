//! Hand-rolled byte builders for the Perfetto proto messages sismo
//! emits. Replaces the old C-side encoders in `perfetto_shim.c`. Per
//! the architectural call (see auto-memory `project_perfetto_integration`),
//! the C++ side is glue only — every byte that goes on the wire is
//! built here in Zig.
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
};

pub const LinuxFtraceEntry = struct {
    // Today: hardcoded sched events. Future: configurable.
};

pub const LinuxPerfEntry = struct {
    /// Scopes the producer to a single tgid via
    /// `callstack_sampling.scope.target_pid`. 0 = system-wide.
    target_pid: i32 = 0,
};

/// One entry per `data_sources { config { ... } }` block in the
/// TraceConfig. Sismo builds this set from per-DS toggles in
/// cmd_record.zig; cmd_datasource.zig only ever has a producer-side
/// view, never builds TraceConfigs.
pub const DataSourceEntry = union(enum) {
    track_event: TrackEventEntry,
    sismo_vendor: SismoVendorEntry,
    linux_ftrace: LinuxFtraceEntry,
    linux_perf: LinuxPerfEntry,
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
const DSC_PERF_EVENT_CONFIG_FIELD: u32 = 111;

fn encodeTrackEventConfig(gpa: std.mem.Allocator, te: TrackEventEntry) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    // TrackEventConfig.enabled_categories = repeated string field 1.
    for (te.enabled_categories) |cat| try w.writeString(1, cat);
    return w.buf.toOwnedSlice(gpa);
}

/// FtraceConfig: hand-rolled (the C SDK had no generated builder).
/// Today emits sched_switch / sched_waking / sched_wakeup /
/// sched_process_exit + compact_sched.enabled — matches what the C
/// shim produced. Field numbers per `protos/perfetto/config/ftrace/
/// ftrace_config.proto`:
///   ftrace_events = 1 (repeated string)
///   compact_sched = 12 (CompactSchedConfig submsg; .enabled = field 1)
fn encodeFtraceConfig(gpa: std.mem.Allocator, _: LinuxFtraceEntry) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    const events = [_][]const u8{
        "sched/sched_switch",
        "sched/sched_waking",
        "sched/sched_wakeup",
        "sched/sched_process_exit",
    };
    for (events) |e| try w.writeString(1, e);

    var compact = ProtoWriter.init(gpa);
    defer compact.deinit();
    try compact.writeBool(1, true); // CompactSchedConfig.enabled
    try w.writeMessage(12, compact.bytes());
    return w.buf.toOwnedSlice(gpa);
}

/// PerfEventConfig: hand-rolled. Emits 1 kHz timebase + DWARF user
/// unwinding + kernel frames, optionally scoped to target_pid. Field
/// numbers per `protos/perfetto/config/profiling/perf_event_config.proto`:
///   timebase = 15 (PerfEvents.Timebase submsg; .frequency = field 2)
///   callstack_sampling = 16 (CallstackSampling submsg)
///     .scope = 1 (Scope submsg; .target_pid = repeated int32 field 1)
///     .kernel_frames = 2
///     .user_frames = 3 (UnwindMode enum: UNWIND_DWARF = 2)
fn encodePerfEventConfig(gpa: std.mem.Allocator, p: LinuxPerfEntry) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();

    var timebase = ProtoWriter.init(gpa);
    defer timebase.deinit();
    try timebase.writeUint64(2, 1000); // frequency = 1 kHz
    try w.writeMessage(15, timebase.bytes());

    var cs = ProtoWriter.init(gpa);
    defer cs.deinit();
    if (p.target_pid > 0) {
        var scope = ProtoWriter.init(gpa);
        defer scope.deinit();
        try scope.writeUint32(1, @bitCast(p.target_pid)); // target_pid
        try cs.writeMessage(1, scope.bytes());
    }
    try cs.writeBool(2, true); // kernel_frames
    try cs.writeUint32(3, 2); // user_frames = UNWIND_DWARF
    try w.writeMessage(16, cs.bytes());

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
        },
        .linux_ftrace => |lf| {
            try w.writeString(1, "linux.ftrace");
            const fc = try encodeFtraceConfig(gpa, lf);
            defer gpa.free(fc);
            try w.writeMessage(DSC_FTRACE_CONFIG_FIELD, fc);
        },
        .linux_perf => |lp| {
            try w.writeString(1, "linux.perf");
            const pec = try encodePerfEventConfig(gpa, lp);
            defer gpa.free(pec);
            try w.writeMessage(DSC_PERF_EVENT_CONFIG_FIELD, pec);
        },
    }
    return w.buf.toOwnedSlice(gpa);
}

fn encodeBufferConfig(
    gpa: std.mem.Allocator,
    size_kb: u32,
    fill_policy: u32, // 0=UNSPECIFIED, 1=RING_BUFFER, 2=DISCARD
) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    try w.writeUint32(1, size_kb); // size_kb
    if (fill_policy != 0) try w.writeUint32(4, fill_policy); // fill_policy
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
    // write_into_file causes silent data loss.
    {
        const fp: u32 = if (cfg.mode == .capped) 2 else 1;
        const buf_msg = try encodeBufferConfig(gpa, cfg.buffer_size_kb, fp);
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
// TracePacket (the field-tagged contents that sit inside a
// NewTracePacket() handle). The C++ glue wraps it; here we provide
// builders that accept a payload + timestamp and emit the body bytes.
// ---------------------------------------------------------------------------

const TP_FIELD_TIMESTAMP: u32 = 8;
const TP_FIELD_SEQUENCE_FLAGS: u32 = 13;

/// Build a TracePacket body containing (timestamp, payload-as-field).
/// `payload_field_tag` is the field number inside TracePacket where
/// the payload sits (e.g. 17 for perf_sample, 117 for
/// generic_kernel_task_state_event). `payload_bytes` is the already-
/// encoded sub-message body.
pub fn encodeTracePacketBody(
    gpa: std.mem.Allocator,
    timestamp_ns: u64,
    payload_field_tag: u32,
    payload_bytes: []const u8,
) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    if (timestamp_ns != 0) try w.writeUint64(TP_FIELD_TIMESTAMP, timestamp_ns);
    try w.writeMessage(payload_field_tag, payload_bytes);
    return w.buf.toOwnedSlice(gpa);
}

pub fn encodeTracePacketBodyWithFlags(
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

// ---------------------------------------------------------------------------
// PerfSample (TracePacket field 17)
// schema: protos/perfetto/trace/profiling/perf_sample.proto
// ---------------------------------------------------------------------------

pub const TP_FIELD_PERF_SAMPLE: u32 = 17;

pub const PerfSample = struct {
    cpu: u32,
    pid: u32,
    tid: u32,
    /// 0 = no callstack (proto absence semantic).
    callstack_iid: u64 = 0,
};

pub fn encodePerfSample(gpa: std.mem.Allocator, s: PerfSample) ![]u8 {
    var w = ProtoWriter.init(gpa);
    errdefer w.deinit();
    // PerfSample.cpu = 1, pid = 2, tid = 3, callstack_iid = 4 — matches
    // the proto schema in profiling/perf_sample.proto.
    try w.writeUint32(1, s.cpu);
    try w.writeUint32(2, s.pid);
    try w.writeUint32(3, s.tid);
    if (s.callstack_iid != 0) try w.writeUint64(4, s.callstack_iid);
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
    // Cap comm at 64 chars defensively (Mach thread name max in
    // practice). The C-side did this; preserve.
    const comm_capped = if (e.comm.len > 64) e.comm[0..64] else e.comm;
    try w.writeUint32(1, @bitCast(e.cpu));
    if (comm_capped.len > 0) try w.writeString(2, comm_capped);
    try w.writeUint64(3, @bitCast(e.tid));
    try w.writeUint32(4, @intFromEnum(e.state));
    try w.writeUint32(5, @bitCast(e.prio));
    return w.buf.toOwnedSlice(gpa);
}
