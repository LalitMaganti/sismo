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
