// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

// C ABI exposed by sismo's C++ glue (perfetto_ds.cc, sismo_consumer.cc,
// sismo_traced.cc) to Zig. The C++ side is *minimal glue over the
// public Perfetto C++ SDK*; all proto encoding (DataSourceDescriptor,
// TraceConfig, payloads, VmProgram, ...) lives in Zig — see
// `src/perfetto_proto.zig` and the producer-specific encoders in each
// capture module. The C++ shim does not interpret any proto bytes
// other than parsing the descriptor blob immediately before passing
// it to `DataSource::Register`.

#ifndef SISMO_SRC_C_PERFETTO_SHIM_H_
#define SISMO_SRC_C_PERFETTO_SHIM_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque consumer-side session handle. Layout lives in
// sismo_consumer.cc; the C++ implementation owns a
// std::unique_ptr<perfetto::TracingSession>.
struct SismoConsumerSession;

// ---------------------------------------------------------------------------
// Consumer surface (sismo_consumer.cc)
// ---------------------------------------------------------------------------

struct SismoConsumerSession* sismo_consumer_session_create(void);

// Returns 0 on success, non-zero if the supplied bytes don't parse as
// a valid TraceConfig protobuf. The caller built `cfg_bytes` in Zig
// via `perfetto_proto.encodeTraceConfig` (see src/perfetto_proto.zig).
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

// ---------------------------------------------------------------------------
// Producer surface (perfetto_ds.cc) — public C++ SDK based.
//
//   - `sismo_init(prod_sock)` initializes the global C++ Tracing client
//     pointed at the in-process traced's producer socket.
//   - `sismo_ds_register(desc_bytes, ..., callbacks, user_arg)` parses
//     the Zig-built `DataSourceDescriptor` (which may include
//     `protovm_program` for ProtoVM-backed data sources) and registers
//     a slot. Returns a slot handle (0..7) or UINT32_MAX on failure.
//   - `sismo_ds_emit(handle, packet_bytes, len)` emits a TracePacket
//     whose body is the verbatim Zig-built bytes (timestamp + payload
//     + ...). Cheap no-op if the slot has no active instances.
//   - `sismo_stop_done(handle)` / `sismo_flush_done(handle)` ack the
//     async stop/flush. The handle is the opaque pointer the producer
//     received in its on_stop / on_flush callback.
//
// All proto encoding (descriptor, payloads, VmProgram, TraceConfig)
// lives in Zig — see `src/perfetto_proto.zig`. C++ is glue only.
// ---------------------------------------------------------------------------
typedef void (*SismoDsOnSetup)(void* user_arg, const void* dsc_bytes, size_t dsc_size);
typedef void (*SismoDsOnStart)(void* user_arg);
typedef void (*SismoDsOnStop) (void* user_arg, void* stopper_handle);
typedef void (*SismoDsOnFlush)(void* user_arg, void* flusher_handle);

void sismo_init(const char* producer_socket);

uint32_t sismo_ds_register(const uint8_t* desc_bytes, size_t desc_len,
                           SismoDsOnSetup on_setup,
                           SismoDsOnStart on_start,
                           SismoDsOnStop  on_stop,
                           SismoDsOnFlush on_flush,
                           void*          user_arg);

void sismo_ds_emit(uint32_t slot,
                   const uint8_t* packet_bytes,
                   size_t packet_len);

void sismo_stop_done(void* handle);
void sismo_flush_done(void* handle);

#ifdef __cplusplus
}
#endif

#endif  // SISMO_SRC_C_PERFETTO_SHIM_H_
