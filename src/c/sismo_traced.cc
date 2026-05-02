// src/c/sismo_traced.cc — C++ implementation of the sismo_traced.h ABI.
//
// LockFreeTaskRunner pins itself to the constructing thread (see
// lock_free_task_runner.cc:55), and Run() asserts the same. So we
// construct the task runner *and* the ServiceIPCHost inside a worker
// thread spawned by create(), wait for "ready", then return control to
// the caller. stop() sets Quit() (safe cross-thread); destroy() joins.

#include "sismo_traced.h"

#include "perfetto/ext/base/lock_free_task_runner.h"
#include "perfetto/ext/tracing/ipc/service_ipc_host.h"

#include <atomic>
#include <list>
#include <memory>
#include <stdio.h>
#include <string>
#include <thread>
#include <unistd.h>

namespace {

struct State {
  // Owned by the worker thread; only the pointer (for Quit() from main)
  // is touched cross-thread.
  std::unique_ptr<perfetto::base::MaybeLockFreeTaskRunner> task_runner;
  std::unique_ptr<perfetto::ServiceIPCHost> host;
  std::string producer_socket;
  std::string consumer_socket;
  std::thread worker;

  // Cross-thread signalling: set by worker after Start() succeeds (or
  // fails). Polled by create() before returning.
  std::atomic<bool> ready{false};
  std::atomic<bool> failed{false};
};

void RunWorker(State* s) {
  s->task_runner =
      std::make_unique<perfetto::base::MaybeLockFreeTaskRunner>();
  s->host = perfetto::ServiceIPCHost::CreateInstance(s->task_runner.get());
  if (!s->host) {
    fprintf(stderr,
            "sismo_traced: ServiceIPCHost::CreateInstance failed\n");
    s->failed.store(true, std::memory_order_release);
    s->ready.store(true, std::memory_order_release);
    return;
  }

  unlink(s->producer_socket.c_str());
  unlink(s->consumer_socket.c_str());

  std::list<perfetto::ListenEndpoint> producer_eps;
  producer_eps.emplace_back(perfetto::ListenEndpoint(s->producer_socket));
  if (!s->host->Start(std::move(producer_eps),
                      perfetto::ListenEndpoint(s->consumer_socket))) {
    fprintf(stderr,
            "sismo_traced: Start() failed (producer=%s consumer=%s)\n",
            s->producer_socket.c_str(), s->consumer_socket.c_str());
    s->failed.store(true, std::memory_order_release);
    s->ready.store(true, std::memory_order_release);
    return;
  }

  s->ready.store(true, std::memory_order_release);
  s->task_runner->Run();  // blocks until Quit()
}

}  // namespace

struct SismoTraced {
  State state;
};

extern "C" SismoTraced* sismo_traced_create(const char* producer_socket,
                                            const char* consumer_socket) {
  auto self = new SismoTraced;
  self->state.producer_socket = producer_socket;
  self->state.consumer_socket = consumer_socket;
  self->state.worker = std::thread(RunWorker, &self->state);

  // Spin briefly until the worker reports ready or failed. The window
  // is tiny (just enough for socket binds), so a yield-loop is fine.
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

extern "C" void sismo_traced_stop(SismoTraced* self) {
  if (!self || !self->state.task_runner) return;
  self->state.task_runner->Quit();
}

extern "C" void sismo_traced_destroy(SismoTraced* self) {
  if (!self) return;
  if (self->state.worker.joinable()) {
    // If caller forgot to stop(), do it ourselves rather than hang.
    if (self->state.task_runner) self->state.task_runner->Quit();
    self->state.worker.join();
  }
  delete self;
}
