// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

// Tiny C shim around Perfetto's C TrackEvent SDK
// (`perfetto/public/track_event.h`) for the sample-target workload.
//
// Why a shim instead of @cInclude'ing track_event.h directly from Zig:
// the SDK's user-facing API is macro-heavy (PERFETTO_TE_CATEGORIES_DEFINE,
// PERFETTO_TE, PERFETTO_TE_SLICE_BEGIN, …) and those macros don't survive
// translate-c. Wrapping them once in C and exposing four plain functions
// keeps the Zig side trivial.
//
// Init connects to PERFETTO_PRODUCER_SOCK_NAME (set by `sismo record`),
// registers the single `app` TrackEvent category, and is idempotent —
// safe to call more than once per process. All emit calls are no-ops
// until init has been called.

#ifndef SISMO_SRC_C_SAMPLE_TARGET_SDK_H_
#define SISMO_SRC_C_SAMPLE_TARGET_SDK_H_

#ifdef __cplusplus
extern "C" {
#endif

// Idempotent. Connects to PERFETTO_PRODUCER_SOCK_NAME (SYSTEM backend),
// initializes the C TrackEvent SDK, and registers the `app` category.
void sismo_target_te_init(void);

// Begin a SLICE_BEGIN event under the `app` category. `name` must
// outlive the call (typically a string literal).
void sismo_target_slice_begin(const char* name);

// End the most recently-begun slice on the current thread. Pairs with
// sismo_target_slice_begin.
void sismo_target_slice_end(void);

// Emit a one-shot instant event under the `app` category.
void sismo_target_instant(const char* name);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // SISMO_SRC_C_SAMPLE_TARGET_SDK_H_
