// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the Apache License, Version 2.0.
//
// C ABI for the embedded Perfetto tracing service.
//
// `sismo record` hosts a `ServiceIPCHost` in-process so that the
// workload (and any external SDK clients) can connect via
// PERFETTO_PRODUCER_SOCK_NAME, and so that sismo's own consumer-side
// session creation talks to a service it owns. The implementation
// lives in sismo_traced.cc; it spawns a worker thread that constructs
// the Perfetto `LockFreeTaskRunner` + `ServiceIPCHost`, binds the two
// Unix sockets, and runs the task runner until `stop()` is called.
//
// Lifecycle from the orchestrator:
//   1. main thread:  sismo_traced_create(producer_sock, consumer_sock)
//        — blocks until the worker reports ready (or null on failure).
//   2. main thread:  do recording work (sessions, etc).
//   3. main thread:  sismo_traced_stop(svc) — signals the task runner
//        to return from its run loop. Safe to call from any thread.
//   4. main thread:  sismo_traced_destroy(svc) — joins the worker and
//        frees the handle. If `stop()` wasn't called, destroy() will
//        do it itself rather than hang on join.

#ifndef SISMO_SRC_C_SISMO_TRACED_H_
#define SISMO_SRC_C_SISMO_TRACED_H_

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle. Full layout lives in sismo_traced.cc.
struct SismoTraced;

// Construct the embedded service and bind the two Unix sockets.
// Both paths are copied; caller may free after the call returns.
// Returns NULL if the service failed to start (socket bind failure,
// IPC host construction failure, etc — diagnostics on stderr).
struct SismoTraced* sismo_traced_create(const char* producer_socket,
                                        const char* consumer_socket);

// Signal the task runner to return from its internal run loop.
// Safe to call from any thread. Idempotent.
void sismo_traced_stop(struct SismoTraced* self);

// Join the worker thread and free the handle. If `stop()` was not
// called first, destroy() will call it rather than hang.
void sismo_traced_destroy(struct SismoTraced* self);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // SISMO_SRC_C_SISMO_TRACED_H_
