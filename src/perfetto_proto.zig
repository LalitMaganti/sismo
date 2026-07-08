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
// TracePacket envelope helpers
//
// `sismo_ds_emit(slot, packet_bytes, len)` accepts the *body* of a
// TracePacket (the field-tagged contents inside a NewTracePacket()
// handle). The C++ glue wraps it.
//
// The TracePacket body wrapper (timestamp + sequence_flags + payload-as-field)
// is encoded in rust-bridge/src/proto.rs (sismo_encode_trace_packet_body),
// called from macos_cpu_samples_capture and macos_sched_capture.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// PerfSample (TracePacket field 17)
// schema: protos/perfetto/trace/profiling/perf_sample.proto
// ---------------------------------------------------------------------------

pub const TP_FIELD_PERF_SAMPLE: u32 = 66;

/// TracePacket.sequence_flags values (trace_packet.proto SequenceFlags).
pub const SEQ_INCREMENTAL_STATE_CLEARED: u32 = 1;
pub const SEQ_NEEDS_INCREMENTAL_STATE: u32 = 2;

// The PerfSample body is encoded in rust-bridge/src/proto.rs
// (sismo_encode_perf_sample), called from linux_bpf_capture's emitSample and
// macos_cpu_samples_capture.

// PerfSampleDefaults + TracePacketDefaults (the once-per-sequence defaults
// packet) are built in rust-bridge/src/proto.rs
// (sismo_encode_perf_defaults_packet), called from linux_bpf_capture's
// emitDefaults.

/// BuiltinClock values (clock_snapshot.proto). MONOTONIC matches
/// bpf_ktime_get_ns().
pub const BUILTIN_CLOCK_MONOTONIC: u32 = 3;

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

// The GenericKernelTaskStateEvent body is encoded in
// rust-bridge/src/proto.rs (sismo_encode_kernel_task_state_event), called
// from macos_sched_capture's emitTaskState.

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
/// rides at TracePacket field 122). The caller wraps the returned bytes
/// with `sismo_encode_trace_packet_body` (rust-bridge/src/proto.rs).
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
/// `sismo_encode_data_source_descriptor` (rust-bridge/src/session_config.rs).
/// Bounded allocation; a few hundred bytes total.
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

