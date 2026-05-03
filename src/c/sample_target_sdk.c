// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

// Implementation of the sample-target TrackEvent shim. See header for
// the why; the macros below are the standard Perfetto C SDK setup
// distilled to a single category named `app`.

#include "src/c/sample_target_sdk.h"

#include <stdatomic.h>

#include "perfetto/public/producer.h"
#include "perfetto/public/te_category_macros.h"
#include "perfetto/public/te_macros.h"
#include "perfetto/public/track_event.h"

// Single category — sample-target only emits one stream of events.
#define SAMPLE_TARGET_CATEGORIES(C) \
  C(app, "app", "sample-target application events")

PERFETTO_TE_CATEGORIES_DEFINE(SAMPLE_TARGET_CATEGORIES)

// Idempotency guard. Multiple calls to sismo_target_te_init must be
// safe — the Perfetto producer + TrackEvent SDK can technically tolerate
// re-init, but re-registering the same category twice would leak the
// first registration's impl. atomic_flag is the lightest primitive that
// guarantees exactly-once.
static atomic_flag g_inited = ATOMIC_FLAG_INIT;

void sismo_target_te_init(void) {
  if (atomic_flag_test_and_set(&g_inited)) return;

  struct PerfettoProducerInitArgs args = PERFETTO_PRODUCER_INIT_ARGS_INIT();
  // SYSTEM backend connects to PERFETTO_PRODUCER_SOCK_NAME, set by
  // `sismo record` before spawning this workload. No fallback —
  // sample-target is only meaningful under sismo's hosted service.
  args.backends = PERFETTO_BACKEND_SYSTEM;
  PerfettoProducerInit(args);

  PerfettoTeInit();
  PERFETTO_TE_REGISTER_CATEGORIES(SAMPLE_TARGET_CATEGORIES);
}

void sismo_target_slice_begin(const char* name) {
  PERFETTO_TE(app, PERFETTO_TE_SLICE_BEGIN(name));
}

void sismo_target_slice_end(void) {
  PERFETTO_TE(app, PERFETTO_TE_SLICE_END());
}

void sismo_target_instant(const char* name) {
  PERFETTO_TE(app, PERFETTO_TE_INSTANT(name));
}
