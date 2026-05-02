// src/c/sismo_traced_probes.cc — embed Perfetto's ProbesProducer in-process.
//
// Mirrors sismo_traced.cc's worker-thread skeleton: MaybeLockFreeTaskRunner
// pins to the constructing thread, so we build the runner *and* the
// producer inside the worker, signal "ready" once ConnectWithRetries has
// been issued, and let the runner block on Run() until Quit() is called
// from the orchestrator.

#include "sismo_traced_probes.h"

#include "perfetto/ext/base/lock_free_task_runner.h"
#include "src/traced/probes/probes_producer.h"

#include <atomic>
#include <memory>
#include <stdio.h>
#include <string>
#include <thread>

namespace {

struct State {
  std::unique_ptr<perfetto::base::MaybeLockFreeTaskRunner> task_runner;
  std::unique_ptr<perfetto::ProbesProducer> producer;
  std::string producer_socket;
  std::thread worker;

  std::atomic<bool> ready{false};
  std::atomic<bool> failed{false};
};

void RunWorker(State* s) {
  s->task_runner =
      std::make_unique<perfetto::base::MaybeLockFreeTaskRunner>();
  s->producer = std::make_unique<perfetto::ProbesProducer>();

  // ConnectWithRetries returns void and posts retries onto the
  // task_runner; failure surfaces later as OnDisconnect callbacks
  // rather than at this call site.
  s->producer->ConnectWithRetries(s->producer_socket.c_str(),
                                  s->task_runner.get());

  s->ready.store(true, std::memory_order_release);
  s->task_runner->Run();  // blocks until Quit()

  // Tear down on the same thread the objects were constructed on.
  // Reset the producer first so its destructor's posted tasks have a
  // live runner to dispatch on (or drop cleanly if Quit already drained).
  s->producer.reset();
  s->task_runner.reset();
}

}  // namespace

struct SismoTracedProbes {
  State state;
};

extern "C" SismoTracedProbes* sismo_traced_probes_create(
    const char* producer_socket) {
  auto self = new SismoTracedProbes;
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

extern "C" void sismo_traced_probes_stop(SismoTracedProbes* self) {
  if (!self || !self->state.task_runner) return;
  self->state.task_runner->Quit();
}

extern "C" void sismo_traced_probes_destroy(SismoTracedProbes* self) {
  if (!self) return;
  if (self->state.worker.joinable()) {
    if (self->state.task_runner) self->state.task_runner->Quit();
    self->state.worker.join();
  }
  delete self;
}
