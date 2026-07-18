// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

#ifndef SRC_C_SISMO_TRACE_QUERY_H_
#define SRC_C_SISMO_TRACE_QUERY_H_

// C ABI over the Perfetto trace_processor C++ library, used by the
// post-record symbolization step to pull the unsymbolized stack frames out
// of a recorded .pftrace without hand-parsing protobuf. The heavy lifting
// (proto parsing, interned-data joining) lives in trace_processor; sismo
// just runs one SQL query and symbolizes the result with wholesym.

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Invoked once per unsymbolized frame. `name`/`build_id` are NOT
// NUL-terminated — use the paired length. `build_id` is the lowercase-hex
// string as stored by trace_processor. All pointers are valid only for the
// duration of the call. Rows arrive grouped by (name, build_id, load_bias).
typedef void (*sismo_unsym_row_cb)(void* ctx,
                                   const char* name,
                                   size_t name_len,
                                   const char* build_id,
                                   size_t build_id_len,
                                   uint64_t rel_pc,
                                   uint64_t load_bias);

// Loads `trace_path` into trace_processor and runs the unsymbolized-frames
// query, invoking `cb(ctx, ...)` once per row. Returns 0 on success,
// non-zero on error (trace load or query failure); the error is logged to
// stderr.
int sismo_trace_query_unsymbolized(const char* trace_path,
                                   sismo_unsym_row_cb cb,
                                   void* ctx);

// Invoked once per module with its observed stack shape (DIA-0/DIA-1):
// `total` samples whose innermost frame is in the module, of which
// `single_frame` had a single user frame — the frame-pointer-omission
// truncation marker. `name`/`build_id` are NOT NUL-terminated; use the paired
// length. Pointers are valid only for the call.
typedef void (*sismo_stack_quality_cb)(void* ctx,
                                       const char* name,
                                       size_t name_len,
                                       const char* build_id,
                                       size_t build_id_len,
                                       uint64_t load_bias,
                                       uint64_t total,
                                       uint64_t single_frame);

// Loads `trace_path` and runs the per-module stack-shape query, invoking
// `cb(ctx, ...)` once per module. Returns 0 on success, non-zero on error.
int sismo_trace_query_stack_quality(const char* trace_path,
                                    sismo_stack_quality_cb cb,
                                    void* ctx);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // SRC_C_SISMO_TRACE_QUERY_H_
