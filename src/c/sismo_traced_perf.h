// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

// C ABI for the embedded Perfetto traced_perf producer (Linux only).
//
// `sismo record` hosts PerfProducer in-process on a worker thread so
// the orchestrator captures perf_event_open CPU samples without
// spawning a subprocess. The producer connects to the in-process
// `traced` (sismo_traced.cc) over a loopback Unix-domain socket.
//
// Internally instantiates a DirectDescriptorGetter (Perfetto's
// non-Android getter for /proc/<pid>/maps + /mem fds) and passes it
// into the PerfProducer constructor along with the worker's TaskRunner.
//
// Lifecycle mirrors sismo_traced_probes.h.

#ifndef SISMO_SRC_C_SISMO_TRACED_PERF_H_
#define SISMO_SRC_C_SISMO_TRACED_PERF_H_

#ifdef __cplusplus
extern "C" {
#endif

struct SismoTracedPerf;

struct SismoTracedPerf* sismo_traced_perf_create(
    const char* producer_socket);

void sismo_traced_perf_stop(struct SismoTracedPerf* self);

void sismo_traced_perf_destroy(struct SismoTracedPerf* self);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // SISMO_SRC_C_SISMO_TRACED_PERF_H_
