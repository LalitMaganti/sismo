// src/c/sismo_traced_perf.cc — embed Perfetto's PerfProducer in-process.
//
// Mirrors sismo_traced_probes.cc. The extra wrinkle is that PerfProducer
// requires both a TaskRunner and a ProcDescriptorGetter at construction;
// upstream's traced_perf.cc:91 instantiates DirectDescriptorGetter
// default-constructed in the non-Android branch, which is exactly what
// sismo wants.

#include "sismo_traced_perf.h"

#include "perfetto/ext/base/lock_free_task_runner.h"
#include "src/profiling/perf/perf_producer.h"
#include "src/profiling/perf/proc_descriptors.h"

#include <atomic>
#include <memory>
#include <stdio.h>
#include <string>
#include <thread>

namespace {

struct State {
  std::unique_ptr<perfetto::base::MaybeLockFreeTaskRunner> task_runner;
  std::unique_ptr<perfetto::DirectDescriptorGetter> proc_fd_getter;
  std::unique_ptr<perfetto::profiling::PerfProducer> producer;
  std::string producer_socket;
  std::thread worker;

  std::atomic<bool> ready{false};
  std::atomic<bool> failed{false};
};

void RunWorker(State* s) {
  s->task_runner =
      std::make_unique<perfetto::base::MaybeLockFreeTaskRunner>();
  s->proc_fd_getter = std::make_unique<perfetto::DirectDescriptorGetter>();
  s->producer = std::make_unique<perfetto::profiling::PerfProducer>(
      s->proc_fd_getter.get(), s->task_runner.get());

  s->producer->ConnectWithRetries(s->producer_socket.c_str());

  s->ready.store(true, std::memory_order_release);
  s->task_runner->Run();

  s->producer.reset();
  s->proc_fd_getter.reset();
  s->task_runner.reset();
}

}  // namespace

struct SismoTracedPerf {
  State state;
};

extern "C" SismoTracedPerf* sismo_traced_perf_create(
    const char* producer_socket) {
  auto self = new SismoTracedPerf;
  self->state.producer_socket = producer_socket;
  self->state.worker = std::thread(RunWorker, &self->state);

  while (!self->state.ready.load(std::memory_order_acquire)) {
    std::this_thread::yield();
  }
  if (self->state.failed.load(std::memory_order_acquire)) {
    self->state.worker.join();
    delete self;
    return nullptr;
  }
  return self;
}

extern "C" void sismo_traced_perf_stop(SismoTracedPerf* self) {
  if (!self || !self->state.task_runner) return;
  self->state.task_runner->Quit();
}

extern "C" void sismo_traced_perf_destroy(SismoTracedPerf* self) {
  if (!self) return;
  if (self->state.worker.joinable()) {
    if (self->state.task_runner) self->state.task_runner->Quit();
    self->state.worker.join();
  }
  delete self;
}
