// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the Apache License, Version 2.0.
//
// Thin C shim around the Perfetto C SDK so Zig can drive the SDK without
// having to translate the macro-heavy public header. The SDK's user-facing
// helpers (PERFETTO_DS_INIT, PERFETTO_DS_TRACE, the static-inline producer
// init, etc.) are easier to wrap once in C than to expand by hand on each
// call site in Zig.

#ifndef SISMO_SRC_C_PERFETTO_SHIM_H_
#define SISMO_SRC_C_PERFETTO_SHIM_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque to Zig — full layout lives in perfetto_c.h.
struct PerfettoDs;

// Opaque consumer-side session handle. Layout lives in
// sismo_consumer.cc; the C++ implementation owns a
// std::unique_ptr<perfetto::TracingSession>.
struct SismoConsumerSession;

// Three TraceConfig flavors matching the master plan's three profiling modes.
typedef enum SismoMode {
    SISMO_MODE_RING = 0,    // Flight recorder: ring buffer, snapshot on demand.
    SISMO_MODE_CAPPED = 1,  // Bounded by duration_ms.
    SISMO_MODE_FILE = 2,    // write_into_file=true, capped by max_file_size_bytes.
} SismoMode;

// Initialize the global Perfetto producer. Always uses the SYSTEM
// backend — every sismo producer connects to the hosted traced socket
// at PERFETTO_PRODUCER_SOCK_NAME (set by the orchestrator). There is
// no in-process variant; sismo-record is always the orchestrator that
// hosts the socket and owns the consumer session.
void sismo_perfetto_init(void);

// Allocate + zero-init a PerfettoDs. Caller frees with sismo_perfetto_ds_free.
struct PerfettoDs* sismo_perfetto_ds_alloc(void);
void sismo_perfetto_ds_free(struct PerfettoDs* ds);

// Register a data source by name. Returns true on success.
bool sismo_perfetto_ds_register(struct PerfettoDs* ds, const char* name);

// Lifecycle callback variant. The producer registers `on_start` and
// `on_stop` against the data source; the SDK invokes them on the
// producer's IO thread when a tracing session enables/disables this
// instance. Both callbacks are expected to return *quickly* — they
// signal a worker thread that owns the actual capture state.
//
// `on_stop` receives an opaque stopper handle (a `PerfettoDsAsyncStopper*`).
// The producer's worker thread, after it has finished its final drain
// and any flush-on-stop emission, must call
// `sismo_perfetto_stop_done(stopper)` so the tracing service can
// finalize the session. Until that happens the session remains in the
// "stopping" state.
//
// `user_arg` is forwarded to all callbacks unchanged. Use it to pass
// a per-producer state pointer (the worker thread state, etc.).
//
// `on_setup`: fired before `on_start` once Perfetto has built the
// data source instance for this session. `dsc_bytes` /
// `dsc_bytes_size` is the serialized `DataSourceConfig` proto — the
// caller is expected to find its sismo-specific config inside (we
// embed at field 2000; see `src/sismo_config.zig`). The caller
// stores whatever it parsed for the worker to use during its setup
// phase; the SDK doesn't expose a per-instance context that would
// help here, so just stash it on the per-DS state pointed to by
// `user_arg`.
//
// `on_flush` is the right place to emit any data the producer has
// been accumulating in-process — heap dumps, batched counters,
// anything that's snapshot-on-demand rather than streamed. Perfetto
// fires it periodically AND once before stop; emitting on flush
// ensures the data lands in the trace even if the consumer reads
// mid-session (RING_BUFFER + write_into_file). `on_stop` is for
// tear-down only.
typedef void (*SismoDsOnSetup)(void* user_arg, const void* dsc_bytes, size_t dsc_bytes_size);
typedef void (*SismoDsOnStart)(void* user_arg);
typedef void (*SismoDsOnStop)(void* user_arg, void* stopper);
typedef void (*SismoDsOnFlush)(void* user_arg, void* flusher);

bool sismo_perfetto_ds_register_with_callbacks(
    struct PerfettoDs* ds,
    const char* name,
    SismoDsOnSetup on_setup,
    SismoDsOnStart on_start,
    SismoDsOnStop on_stop,
    SismoDsOnFlush on_flush,
    void* user_arg);

// Ack a postponed stop / flush. `handle` is the opaque pointer the
// producer received in the matching callback.
void sismo_perfetto_stop_done(void* stopper);
void sismo_perfetto_flush_done(void* flusher);

// Emit a TracePacket containing a PerfSample sub-message. Field setters
// for PerfSample aren't exposed by the C SDK, so we hand-roll the proto
// wire format using the SDK's exposed PerfettoPbMsgAppend{Bytes,VarInt}
// primitives. `callstack_iid == 0` means "no callstack" (PerfSample
// proto treats absence as the default).
int sismo_perfetto_ds_emit_perf_sample(
    struct PerfettoDs* ds,
    uint64_t timestamp_ns,
    uint32_t cpu,
    uint32_t pid,
    uint32_t tid,
    uint64_t callstack_iid);

// TaskStateEnum values from
// protos/perfetto/trace/generic_kernel/generic_task_state_event.proto.
// Used by sismo_perfetto_ds_emit_kernel_task_state.
typedef enum SismoTaskState {
    SISMO_TASK_STATE_UNKNOWN = 0,
    SISMO_TASK_STATE_CREATED = 1,
    SISMO_TASK_STATE_RUNNABLE = 2,
    SISMO_TASK_STATE_RUNNING = 3,
    SISMO_TASK_STATE_INTERRUPTIBLE_SLEEP = 4,
    SISMO_TASK_STATE_UNINTERRUPTIBLE_SLEEP = 5,
    SISMO_TASK_STATE_STOPPED = 6,
    SISMO_TASK_STATE_DEAD = 7,
    SISMO_TASK_STATE_DESTROYED = 8,
} SismoTaskState;

// Emit a TracePacket containing a GenericKernelTaskStateEvent
// sub-message. `comm` may be NULL; if non-NULL, `comm_len` bytes are
// written as a string field. Hand-rolled for the same reason as
// PerfSample — the C SDK doesn't expose field setters for these
// generic-kernel messages.
int sismo_perfetto_ds_emit_kernel_task_state(
    struct PerfettoDs* ds,
    uint64_t timestamp_ns,
    int32_t cpu,
    const char* comm,
    size_t comm_len,
    int32_t tid,
    SismoTaskState state,
    int32_t prio);

// Emit a TracePacket whose payload is a single length-delimited
// sub-message at field tag `payload_field_tag`. The caller supplies
// the already-encoded sub-message bytes. `sequence_flags` is OR'd into
// TracePacket.sequence_flags — pass 1 (SEQ_INCREMENTAL_STATE_CLEARED)
// on the FIRST packet of a sequence carrying InternedData, else
// trace_processor rejects the interned data with
// `interned_data_skipped_incremental_state_invalid`.
//
// Returns the number of packet copies emitted (0 if no tracing session
// is active, non-zero per active instance).
int sismo_perfetto_ds_emit_payload(
    struct PerfettoDs* ds,
    uint64_t timestamp_ns,
    uint32_t sequence_flags,
    uint32_t payload_field_tag,
    const uint8_t* payload_bytes,
    size_t payload_len);

// Per-data-source entry for `sismo_perfetto_build_config`.
// `extra_bytes` (size `extra_bytes_size`) is embedded at field 2000
// of the inner `DataSourceConfig` — that's where the producer's
// `on_setup` callback finds its `SismoXxxConfig` (see
// `src/sismo_config.zig`). Pass `extra_bytes = NULL`,
// `extra_bytes_size = 0` for data sources that don't need
// sismo-specific config (e.g. Perfetto's stock `track_event`).
//
// `target_pid` is consulted only for the Linux producer entries
// `linux.perf` and `linux.ftrace`. Zero means system-wide capture; a
// positive value scopes the producer to the given pid (samples for
// linux.perf via PerfEventConfig.callstack_sampling.scope.target_pid;
// process state ftrace events stay system-wide because traced_probes
// can't filter ftrace by pid). Ignored for sismo-vendor data sources.
typedef struct SismoDsConfigEntry {
    const char* name;
    const void* extra_bytes;
    size_t extra_bytes_size;
    int32_t target_pid;
} SismoDsConfigEntry;

// Allocate a serialized `TraceConfig` proto for the given mode. Each
// entry becomes a `data_sources { config { name; sismo_config = 2000
// } }` block in the TraceConfig. Returns 0 on success.
//
//   ring:   `buffer_size_kb` honored
//   capped: `buffer_size_kb` + `duration_ms` honored
//   file:   `buffer_size_kb` + `max_file_size_bytes` + `output_path`
//           honored. `output_path` is required (the C ABI doesn't
//           expose an FD-passing setup variant).
//
// Caller frees the returned config buffer via
// `sismo_perfetto_free_config`.
int sismo_perfetto_build_config(
    SismoMode mode,
    const SismoDsConfigEntry* entries,
    size_t n_entries,
    uint32_t buffer_size_kb,
    uint32_t duration_ms,
    uint64_t max_file_size_bytes,
    const char* output_path,
    void** cfg_out,
    size_t* cfg_len_out);

void sismo_perfetto_free_config(void* cfg);

// Consumer-side session lifecycle. Implemented in sismo_consumer.cc
// via the Perfetto C++ SDK (TracingSession). Used by `sismo record`
// (the recorder's main session) and exposed as plain-C entry points
// so Zig can call them without a C++ shim.
struct SismoConsumerSession* sismo_consumer_session_create(void);
// Returns 0 on success, non-zero if the supplied bytes don't parse
// as a valid TraceConfig protobuf.
int sismo_consumer_session_setup(struct SismoConsumerSession* session,
                                 const void* cfg_bytes,
                                 size_t cfg_len);
void sismo_consumer_session_start_blocking(struct SismoConsumerSession* session);
void sismo_consumer_session_stop_blocking(struct SismoConsumerSession* session);
void sismo_consumer_session_destroy(struct SismoConsumerSession* session);

// Chunk callback invoked by sismo_consumer_clone_and_stream as the
// cloned session's trace is read out. Fires on a Perfetto-internal
// thread, possibly multiple times for one clone — the final
// invocation has `has_more = false`. Caller (Zig) handles file I/O,
// progress, error accumulation, etc.
typedef void (*SismoTraceChunkCb)(const void* data,
                                   size_t size,
                                   bool has_more,
                                   void* user_arg);

// Snapshot the in-progress tracing session named `source_session_name`
// *without stopping it*, streaming its trace bytes to `cb` chunk by
// chunk. Uses C++ TracingSession::CloneTrace (read-only attach) +
// ReadTrace (chunked async read). The source session is unaffected.
//
// Used by `sismo snapshot` from its own short-lived process. The C++
// side handles only the Perfetto IPC; Zig opens/writes/closes the
// output file via `cb`. Lets all path/file-error logic stay on the
// Zig side where the rest of sismo's path handling lives.
//
// Returns 0 on success, non-zero on clone IPC failure / clone timeout
// (the chunk callback's own write errors are the caller's to track
// via `user_arg`).
int sismo_consumer_clone_and_stream(const char* source_session_name,
                                    SismoTraceChunkCb cb,
                                    void* user_arg);

// Query the tracing service for its current state — list of connected
// producers + registered data sources. Returns serialized
// `TracingServiceState` proto bytes (schema in
// `protos/perfetto/common/tracing_service_state.proto`).
//
// The session may be in any state (post-create, post-setup, etc.); this
// is read-only.
//
// `out_buf` is provided by the caller; on success `*written` is set to
// the byte count written. If the state doesn't fit (`out_buf_size` too
// small), returns 3 and `*written` is set to the required size so the
// caller can retry with a larger buffer.
//
// Returns 0 on success, non-zero on RPC failure / serialize failure /
// buffer too small.
//
// Used by `sismo record --external-...` to poll for the appearance of
// expected data source names before starting the session.
int sismo_consumer_query_service_state(struct SismoConsumerSession* session,
                                       void* out_buf,
                                       size_t out_buf_size,
                                       size_t* written);

#ifdef __cplusplus
}
#endif

#endif  // SISMO_SRC_C_PERFETTO_SHIM_H_
