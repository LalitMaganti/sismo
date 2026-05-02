// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the Apache License, Version 2.0.
//
// C ABI for the embedded Perfetto traced_probes producer (Linux only).
//
// `sismo record` hosts ProbesProducer in-process on a worker thread so
// the orchestrator captures kernel ftrace + procfs data without
// spawning a subprocess. The producer connects to the in-process
// `traced` (sismo_traced.cc) over a loopback Unix-domain socket.
//
// Lifecycle from the orchestrator (mirrors sismo_traced.h):
//   1. sismo_traced_probes_create(producer_sock) — blocks until the
//      worker reports ready (returns null on failure).
//   2. Recording work proceeds via the consumer-side session.
//   3. sismo_traced_probes_stop(svc) — signals the task runner to
//      return from its run loop. Safe from any thread. Idempotent.
//   4. sismo_traced_probes_destroy(svc) — joins the worker thread and
//      frees the handle. If stop() wasn't called, destroy() does it.
//
// Singleton caveat: ProbesProducer enforces a process-wide singleton
// via PERFETTO_CHECK at construction; calling create() twice in the
// same process aborts. Acceptable for v0.

#ifndef SISMO_SRC_C_SISMO_TRACED_PROBES_H_
#define SISMO_SRC_C_SISMO_TRACED_PROBES_H_

#ifdef __cplusplus
extern "C" {
#endif

struct SismoTracedProbes;

struct SismoTracedProbes* sismo_traced_probes_create(
    const char* producer_socket);

void sismo_traced_probes_stop(struct SismoTracedProbes* self);

void sismo_traced_probes_destroy(struct SismoTracedProbes* self);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // SISMO_SRC_C_SISMO_TRACED_PROBES_H_
