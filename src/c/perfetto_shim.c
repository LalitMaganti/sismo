// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the Apache License, Version 2.0.

#include "perfetto_shim.h"

#include <stdlib.h>
#include <string.h>

// Real Perfetto C SDK public headers, sourced from the vendored
// subtree at third_party/src/perfetto/include/. Replaces the
// previously-vendored perfetto_c.h amalgamation.
#include "perfetto/public/abi/heap_buffer.h"
#include "perfetto/public/data_source.h"
#include "perfetto/public/pb_msg.h"
#include "perfetto/public/pb_utils.h"
#include "perfetto/public/producer.h"
#include "perfetto/public/protos/config/data_source_config.pzc.h"
#include "perfetto/public/protos/config/trace_config.pzc.h"
#include "perfetto/public/protos/config/track_event/track_event_config.pzc.h"
#include "perfetto/public/protos/trace/trace_packet.pzc.h"
#include "perfetto/public/tracing_session.h"

// -----------------------------------------------------------------------------
// Producer
// -----------------------------------------------------------------------------

void sismo_perfetto_init(void) {
    struct PerfettoProducerInitArgs args = PERFETTO_PRODUCER_INIT_ARGS_INIT();
    args.backends = PERFETTO_BACKEND_SYSTEM;
    PerfettoProducerInit(args);
}

// -----------------------------------------------------------------------------
// Data source
// -----------------------------------------------------------------------------

struct PerfettoDs* sismo_perfetto_ds_alloc(void) {
    struct PerfettoDs* ds = (struct PerfettoDs*)malloc(sizeof(struct PerfettoDs));
    if (!ds) return NULL;
    // PERFETTO_DS_INIT() expansion: {&perfetto_atomic_false, NULL}.
    ds->enabled = &perfetto_atomic_false;
    ds->impl = NULL;
    return ds;
}

void sismo_perfetto_ds_free(struct PerfettoDs* ds) {
    free(ds);
}

bool sismo_perfetto_ds_register(struct PerfettoDs* ds, const char* name) {
    return PerfettoDsRegister(ds, name, PerfettoDsParamsDefault());
}

// ---- Lifecycle callbacks (muxer pattern) -------------------------------

// Bundle of caller callbacks + their user_arg. Lives for the program's
// lifetime — the SDK doesn't expose a deregister hook so we leak it on
// purpose (one allocation per registered DS, bounded).
struct CbBundle {
    SismoDsOnSetup on_setup;
    SismoDsOnStart on_start;
    SismoDsOnStop on_stop;
    SismoDsOnFlush on_flush;
    void* user_arg;
};

// SDK-side OnStart trampoline. Just forwards to the producer's
// caller-supplied callback. Discards the SDK's per-instance args —
// the producer's worker doesn't need them.
static void shim_on_start_cb(struct PerfettoDsImpl* ds_impl,
                             PerfettoDsInstanceIndex inst_id,
                             void* user_arg,
                             void* inst_ctx,
                             struct PerfettoDsOnStartArgs* args) {
    (void)ds_impl; (void)inst_id; (void)inst_ctx; (void)args;
    struct CbBundle* b = (struct CbBundle*)user_arg;
    if (b && b->on_start) b->on_start(b->user_arg);
}

// SDK-side OnStop trampoline. Postpones the stop so the worker can
// drain + emit + ack on its own schedule. The producer is required to
// call sismo_perfetto_stop_done(stopper) eventually, otherwise the
// session stays in the stopping state until torn down.
static void shim_on_stop_cb(struct PerfettoDsImpl* ds_impl,
                            PerfettoDsInstanceIndex inst_id,
                            void* user_arg,
                            void* inst_ctx,
                            struct PerfettoDsOnStopArgs* args) {
    (void)ds_impl; (void)inst_id; (void)inst_ctx;
    struct CbBundle* b = (struct CbBundle*)user_arg;
    struct PerfettoDsAsyncStopper* stopper = PerfettoDsOnStopArgsPostpone(args);
    if (b && b->on_stop) b->on_stop(b->user_arg, stopper);
    // If the caller didn't supply on_stop we still need to ack the
    // postponed stop so the service doesn't deadlock.
    if (!b || !b->on_stop) PerfettoDsStopDone(stopper);
}

// SDK-side OnFlush trampoline. Postpones the flush so the worker can
// take its time emitting accumulated data (heap dumps in particular
// require symbolicating a few hundred PCs, far too slow for the IO
// thread).
static void shim_on_flush_cb(struct PerfettoDsImpl* ds_impl,
                             PerfettoDsInstanceIndex inst_id,
                             void* user_arg,
                             void* inst_ctx,
                             struct PerfettoDsOnFlushArgs* args) {
    (void)ds_impl; (void)inst_id; (void)inst_ctx;
    struct CbBundle* b = (struct CbBundle*)user_arg;
    struct PerfettoDsAsyncFlusher* flusher = PerfettoDsOnFlushArgsPostpone(args);
    if (b && b->on_flush) b->on_flush(b->user_arg, flusher);
    if (!b || !b->on_flush) PerfettoDsFlushDone(flusher);
}

// SDK-side OnSetup trampoline. The SDK hands us the serialized
// DataSourceConfig bytes; we forward unchanged to the producer's
// callback (which scans for our vendor field 2000 — see
// `src/sismo_config.zig`). We don't use the SDK's per-instance
// context, so return NULL.
static void* shim_on_setup_cb(struct PerfettoDsImpl* ds_impl,
                              PerfettoDsInstanceIndex inst_id,
                              void* ds_config,
                              size_t ds_config_size,
                              void* user_arg,
                              struct PerfettoDsOnSetupArgs* args) {
    (void)ds_impl; (void)inst_id; (void)args;
    struct CbBundle* b = (struct CbBundle*)user_arg;
    if (b && b->on_setup) b->on_setup(b->user_arg, ds_config, ds_config_size);
    return NULL;
}

bool sismo_perfetto_ds_register_with_callbacks(
    struct PerfettoDs* ds,
    const char* name,
    SismoDsOnSetup on_setup,
    SismoDsOnStart on_start,
    SismoDsOnStop on_stop,
    SismoDsOnFlush on_flush,
    void* user_arg) {
    struct CbBundle* b = (struct CbBundle*)malloc(sizeof(struct CbBundle));
    if (!b) return false;
    b->on_setup = on_setup;
    b->on_start = on_start;
    b->on_stop = on_stop;
    b->on_flush = on_flush;
    b->user_arg = user_arg;

    struct PerfettoDsParams params = PerfettoDsParamsDefault();
    params.on_setup_cb = shim_on_setup_cb;
    params.on_start_cb = shim_on_start_cb;
    params.on_stop_cb = shim_on_stop_cb;
    params.on_flush_cb = shim_on_flush_cb;
    params.user_arg = b;
    // PerfettoDsParamsDefault sets will_notify_on_stop=true already,
    // which is what we need for the postpone+stop_done path.
    return PerfettoDsRegister(ds, name, params);
}

void sismo_perfetto_stop_done(void* stopper) {
    if (stopper) PerfettoDsStopDone((struct PerfettoDsAsyncStopper*)stopper);
}

void sismo_perfetto_flush_done(void* flusher) {
    if (flusher) PerfettoDsFlushDone((struct PerfettoDsAsyncFlusher*)flusher);
}

// -----------------------------------------------------------------------------
// Hand-rolled proto encoding for messages the C SDK doesn't expose
// builders for (PerfSample, InternedData/Frame/Callstack/Mapping).
//
// Wire format reference: https://protobuf.dev/programming-guides/encoding/
//   - varint: 7 bits per byte little-endian, MSB = continuation
//   - tag: (field_num << 3) | wire_type, written as varint
//   - LEN: tag, varint(byte_length), bytes
// -----------------------------------------------------------------------------

// TracePacket field numbers (from perfetto_c.h, also in
// protos/perfetto/trace/trace_packet.proto):
#define SISMO_TP_FIELD_PERF_SAMPLE 66

// PerfSample field numbers (from
// protos/perfetto/trace/profiling/profile_packet.proto):
#define SISMO_PS_FIELD_CPU            1
#define SISMO_PS_FIELD_PID            2
#define SISMO_PS_FIELD_TID            3
#define SISMO_PS_FIELD_CALLSTACK_IID  5

// Wire types.
#define SISMO_WIRE_VARINT 0
#define SISMO_WIRE_LEN    2

static inline uint8_t* write_tag(uint32_t field_num, uint32_t wire_type, uint8_t* p) {
    return PerfettoPbWriteVarInt((field_num << 3) | wire_type, p);
}

// Write a (tag, varint) field into a buffer. Returns the new write ptr.
static inline uint8_t* write_varint_field(uint32_t field_num, uint64_t value, uint8_t* p) {
    p = write_tag(field_num, SISMO_WIRE_VARINT, p);
    p = PerfettoPbWriteVarInt(value, p);
    return p;
}

// Build a PerfSample body into `buf` (must hold ~64 bytes; this proto
// has only ~6 fields and we set at most 4 varints). Returns end ptr.
static uint8_t* build_perf_sample(
    uint8_t* buf,
    uint32_t cpu,
    uint32_t pid,
    uint32_t tid,
    uint64_t callstack_iid) {
    uint8_t* p = buf;
    p = write_varint_field(SISMO_PS_FIELD_CPU, cpu, p);
    p = write_varint_field(SISMO_PS_FIELD_PID, pid, p);
    p = write_varint_field(SISMO_PS_FIELD_TID, tid, p);
    if (callstack_iid != 0) {
        p = write_varint_field(SISMO_PS_FIELD_CALLSTACK_IID, callstack_iid, p);
    }
    return p;
}

// TracePacket.sequence_flags is field 13, varint.
#define SISMO_TP_FIELD_SEQUENCE_FLAGS 13

int sismo_perfetto_ds_emit_payload(
    struct PerfettoDs* ds,
    uint64_t timestamp_ns,
    uint32_t sequence_flags,
    uint32_t payload_field_tag,
    const uint8_t* payload_bytes,
    size_t payload_len) {
    int n = 0;
    PERFETTO_DS_TRACE(*ds, ctx) {
        struct PerfettoDsRootTracePacket root;
        PerfettoDsTracerPacketBegin(&ctx, &root);
        perfetto_protos_TracePacket_set_timestamp(&root.msg, timestamp_ns);
        if (sequence_flags) {
            PerfettoPbMsgAppendVarInt(&root.msg, (SISMO_TP_FIELD_SEQUENCE_FLAGS << 3) | 0);
            PerfettoPbMsgAppendVarInt(&root.msg, sequence_flags);
        }
        // Append (tag + length-varint + payload) for the sub-message.
        PerfettoPbMsgAppendVarInt(&root.msg, (payload_field_tag << 3) | 2);
        PerfettoPbMsgAppendVarInt(&root.msg, payload_len);
        PerfettoPbMsgAppendBytes(&root.msg, payload_bytes, payload_len);
        PerfettoDsTracerPacketEnd(&ctx, &root);
        n++;
    }
    return n;
}

int sismo_perfetto_ds_emit_perf_sample(
    struct PerfettoDs* ds,
    uint64_t timestamp_ns,
    uint32_t cpu,
    uint32_t pid,
    uint32_t tid,
    uint64_t callstack_iid) {
    int n = 0;
    PERFETTO_DS_TRACE(*ds, ctx) {
        struct PerfettoDsRootTracePacket root;
        PerfettoDsTracerPacketBegin(&ctx, &root);
        perfetto_protos_TracePacket_set_timestamp(&root.msg, timestamp_ns);

        // Build PerfSample body in a stack buffer, then inject as a
        // length-delimited sub-message of TracePacket.
        uint8_t body[64];
        uint8_t* body_end = build_perf_sample(body, cpu, pid, tid, callstack_iid);
        size_t body_len = (size_t)(body_end - body);

        PerfettoPbMsgAppendVarInt(
            &root.msg,
            (SISMO_TP_FIELD_PERF_SAMPLE << 3) | SISMO_WIRE_LEN);
        PerfettoPbMsgAppendVarInt(&root.msg, body_len);
        PerfettoPbMsgAppendBytes(&root.msg, body, body_len);

        PerfettoDsTracerPacketEnd(&ctx, &root);
        n++;
    }
    return n;
}

// -----------------------------------------------------------------------------
// GenericKernelTaskStateEvent — TracePacket field 117. Same hand-rolled
// proto encoding pattern as PerfSample. Field numbers from
// protos/perfetto/trace/generic_kernel/generic_task_state_event.proto.
// -----------------------------------------------------------------------------

#define SISMO_TP_FIELD_KERNEL_TASK_STATE 117

#define SISMO_KTS_FIELD_CPU   1
#define SISMO_KTS_FIELD_COMM  2
#define SISMO_KTS_FIELD_TID   3
#define SISMO_KTS_FIELD_STATE 4
#define SISMO_KTS_FIELD_PRIO  5

// Worst case body size (5 varints up to ~5B each + comm tag/len/16B).
#define SISMO_KTS_MAX_BODY_BYTES 64

static uint8_t* build_kernel_task_state(
    uint8_t* buf,
    int32_t cpu,
    const char* comm,
    size_t comm_len,
    int32_t tid,
    SismoTaskState state,
    int32_t prio) {
    uint8_t* p = buf;
    p = write_varint_field(SISMO_KTS_FIELD_CPU, (uint32_t)cpu, p);
    if (comm && comm_len > 0) {
        // string field: tag, varint(len), bytes
        p = write_tag(SISMO_KTS_FIELD_COMM, SISMO_WIRE_LEN, p);
        p = PerfettoPbWriteVarInt(comm_len, p);
        memcpy(p, comm, comm_len);
        p += comm_len;
    }
    p = write_varint_field(SISMO_KTS_FIELD_TID, (uint32_t)tid, p);
    p = write_varint_field(SISMO_KTS_FIELD_STATE, (uint32_t)state, p);
    p = write_varint_field(SISMO_KTS_FIELD_PRIO, (uint32_t)prio, p);
    return p;
}

int sismo_perfetto_ds_emit_kernel_task_state(
    struct PerfettoDs* ds,
    uint64_t timestamp_ns,
    int32_t cpu,
    const char* comm,
    size_t comm_len,
    int32_t tid,
    SismoTaskState state,
    int32_t prio) {
    // Cap comm_len defensively — Mach thread name is 64 chars max in
    // practice; anything beyond that is almost certainly a bug upstream.
    if (comm_len > 64) comm_len = 64;
    int n = 0;
    PERFETTO_DS_TRACE(*ds, ctx) {
        struct PerfettoDsRootTracePacket root;
        PerfettoDsTracerPacketBegin(&ctx, &root);
        perfetto_protos_TracePacket_set_timestamp(&root.msg, timestamp_ns);

        uint8_t body[SISMO_KTS_MAX_BODY_BYTES + 64];
        uint8_t* body_end = build_kernel_task_state(
            body, cpu, comm, comm_len, tid, state, prio);
        size_t body_len = (size_t)(body_end - body);

        PerfettoPbMsgAppendVarInt(
            &root.msg,
            (SISMO_TP_FIELD_KERNEL_TASK_STATE << 3) | SISMO_WIRE_LEN);
        PerfettoPbMsgAppendVarInt(&root.msg, body_len);
        PerfettoPbMsgAppendBytes(&root.msg, body, body_len);

        PerfettoDsTracerPacketEnd(&ctx, &root);
        n++;
    }
    return n;
}

// -----------------------------------------------------------------------------
// Trace config builder
// -----------------------------------------------------------------------------

// Field number we use as a vendor extension on Perfetto's
// DataSourceConfig — see src/sismo_config.zig and protos/sismo_config.proto.
#define SISMO_DSC_SISMO_CONFIG_FIELD 2000

int sismo_perfetto_build_config(
    SismoMode mode,
    const SismoDsConfigEntry* entries,
    size_t n_entries,
    uint32_t buffer_size_kb,
    uint32_t duration_ms,
    uint64_t max_file_size_bytes,
    const char* output_path,
    void** cfg_out,
    size_t* cfg_len_out) {

    if (!entries || n_entries == 0 || !cfg_out || !cfg_len_out) return 1;
    if (mode == SISMO_MODE_FILE && !output_path) return 1;

    struct PerfettoPbMsgWriter writer;
    struct PerfettoHeapBuffer* hb = PerfettoHeapBufferCreate(&writer.writer);
    if (!hb) return 2;

    struct perfetto_protos_TraceConfig cfg;
    PerfettoPbMsgInit(&cfg.msg, &writer);

    // buffers { size_kb: ..., fill_policy: ... }
    // FILE mode also uses RING_BUFFER per Perfetto's recommendation
    // (the DISCARD policy with write_into_file causes mysterious data
    // loss; trace_processor warns about this combination).
    {
        struct perfetto_protos_TraceConfig_BufferConfig buf;
        perfetto_protos_TraceConfig_begin_buffers(&cfg, &buf);
        perfetto_protos_TraceConfig_BufferConfig_set_size_kb(&buf, buffer_size_kb);
        if (mode == SISMO_MODE_CAPPED) {
            perfetto_protos_TraceConfig_BufferConfig_set_fill_policy(
                &buf, perfetto_protos_TraceConfig_BufferConfig_DISCARD);
        } else {
            perfetto_protos_TraceConfig_BufferConfig_set_fill_policy(
                &buf, perfetto_protos_TraceConfig_BufferConfig_RING_BUFFER);
        }
        perfetto_protos_TraceConfig_end_buffers(&cfg, &buf);
    }

    // One `data_sources { config { name; ... } }` entry per ds. For
    // "track_event" we also emit a TrackEventConfig with
    // enabled_categories=["*"] so all categories fire (the SDK
    // defaults to all-disabled). For any entry with extra_bytes set,
    // we append our vendor extension at field 2000 carrying the
    // serialized SismoXxxConfig — the producer's on_setup decodes it.
    for (size_t i = 0; i < n_entries; i++) {
        const SismoDsConfigEntry* e = &entries[i];
        if (!e->name) continue;
        struct perfetto_protos_TraceConfig_DataSource ds;
        perfetto_protos_TraceConfig_begin_data_sources(&cfg, &ds);
        {
            struct perfetto_protos_DataSourceConfig dsc;
            perfetto_protos_TraceConfig_DataSource_begin_config(&ds, &dsc);
            perfetto_protos_DataSourceConfig_set_cstr_name(&dsc, e->name);
            if (strcmp(e->name, "track_event") == 0) {
                struct perfetto_protos_TrackEventConfig tec;
                perfetto_protos_DataSourceConfig_begin_track_event_config(&dsc, &tec);
                perfetto_protos_TrackEventConfig_set_cstr_enabled_categories(&tec, "*");
                perfetto_protos_DataSourceConfig_end_track_event_config(&dsc, &tec);
            }
            if (e->extra_bytes && e->extra_bytes_size > 0) {
                // Append (tag, length-varint, bytes) at field 2000 of
                // DataSourceConfig. The SDK doesn't expose a setter
                // for this vendor field, so we hand-write the wire
                // bytes through the message's append primitives.
                PerfettoPbMsgAppendVarInt(&dsc.msg,
                    ((uint64_t)SISMO_DSC_SISMO_CONFIG_FIELD << 3) | 2);
                PerfettoPbMsgAppendVarInt(&dsc.msg, e->extra_bytes_size);
                PerfettoPbMsgAppendBytes(&dsc.msg,
                    (const uint8_t*)e->extra_bytes, e->extra_bytes_size);
            }
            perfetto_protos_TraceConfig_DataSource_end_config(&ds, &dsc);
        }
        perfetto_protos_TraceConfig_end_data_sources(&cfg, &ds);
    }

    // Mark the session by name so a separate consumer (the clone path
    // in perfetto_clone.cc) can attach via TracingSession::CloneTrace
    // without needing a tsid handle. The recorder is the only producer
    // of sessions named "sismo_record"; if multiple sessions ever use
    // the same name, CloneTrace clones an arbitrary matching one.
    perfetto_protos_TraceConfig_set_cstr_unique_session_name(&cfg, "sismo_record");

    if (mode == SISMO_MODE_CAPPED) {
        perfetto_protos_TraceConfig_set_duration_ms(&cfg, duration_ms);
    } else if (mode == SISMO_MODE_FILE) {
        perfetto_protos_TraceConfig_set_write_into_file(&cfg, true);
        perfetto_protos_TraceConfig_set_max_file_size_bytes(
            &cfg, max_file_size_bytes);
        // Flush ring → file every 1s (default is 5s). Tighter cadence
        // bounds the in-ring residency at ~1s of producer output, so
        // even a firehose (kdebug at ~50K events/s) stays well inside
        // the 128 MB ring without overwriting earlier chunks. Also
        // limits crash-loss to ~1s of trace, which matters for the
        // long-tracing mode.
        perfetto_protos_TraceConfig_set_file_write_period_ms(&cfg, 1000);
        perfetto_protos_TraceConfig_set_cstr_output_path(&cfg, output_path);
    }

    PerfettoPbMsgFinalize(&cfg.msg);
    size_t size = PerfettoStreamWriterGetWrittenSize(&writer.writer);

    void* buf = malloc(size);
    if (!buf) {
        PerfettoHeapBufferDestroy(hb, &writer.writer);
        return 3;
    }
    PerfettoHeapBufferCopyInto(hb, &writer.writer, buf, size);
    PerfettoHeapBufferDestroy(hb, &writer.writer);

    *cfg_out = buf;
    *cfg_len_out = size;
    return 0;
}

void sismo_perfetto_free_config(void* cfg) {
    free(cfg);
}

// Session lifecycle (sismo_consumer_session_*) and clone-to-file
// (sismo_consumer_clone_to_file) live in sismo_consumer.cc, expressed
// via the Perfetto C++ SDK. The C surface is declared in
// perfetto_shim.h alongside these producer-side functions.
