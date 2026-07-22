// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

// Public C++ SDK based data source shim for sismo's in-process producer
// side.
//
// **Why public C++ SDK**: the C SDK's inline `PerfettoDsRegister`
// (`include/perfetto/public/data_source.h`) discards `protovm_program`
// when building the `DataSourceDescriptor` — we need that field for
// ring-buffer-safe ProcessTree updates in flight-recorder mode. The
// public C++ SDK's `DataSource<T>::Register(desc)` accepts a fully-
// formed descriptor.
//
// **Why per-slot templated subclasses**: `DataSource<T>` keys static
// members by T; multiple registrations need multiple T's. We satisfy
// this via `SismoSlot<N>` for compile-time-distinct N. Each slot's
// body is purely boilerplate — OnSetup/OnStart/OnStop/OnFlush
// delegate to a `g_bundles[Slot]` whose function pointers were set
// by `sismo_ds_register` before the registration call. **No data-
// source-specific logic in C++.** All proto encoding (descriptor,
// per-DS config, payloads, VmProgram) lives in Zig.

#include "perfetto_shim.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>

#include "perfetto/tracing/data_source.h"
#include "perfetto/tracing/tracing.h"
#include "protos/perfetto/common/data_source_descriptor.gen.h"
// For the off-CPU stream's second trace writer (same data source, own sequence).
#include "perfetto/tracing/buffer_exhausted_policy.h"
#include "perfetto/tracing/trace_writer_base.h"
#include "perfetto/tracing/internal/data_source_type.h"
#include "perfetto/tracing/internal/tracing_muxer.h"

namespace {

// Maximum number of data sources we can register from this process.
// Sismo today: track_event + sched + cpu + heap + privsep helpers ≈ 4.
// 8 leaves comfortable headroom for follow-on data sources without
// touching this file.
constexpr int kMaxSlots = 8;

struct CbBundle {
    SismoDsOnSetup on_setup = nullptr;
    SismoDsOnStart on_start = nullptr;
    SismoDsOnStop  on_stop  = nullptr;
    SismoDsOnFlush on_flush = nullptr;
    void*          user_arg = nullptr;
};

// One bundle per slot. Populated by `sismo_ds_register` before calling
// the slot's `Register`. Read from any thread by the SDK during
// callback dispatch — written-once-then-read-only, so an array of
// plain values is enough; no atomics needed.
std::array<CbBundle, kMaxSlots> g_bundles;

// Slot allocator. Single mutex protects the next-free counter.
int g_next_slot = 0;
std::mutex g_register_mu;

// Templated `DataSource<T>` subclass. One instantiation per Slot value
// gives us N distinct types, satisfying the SDK's per-T static-member
// requirement. The body is purely mechanical — every method just
// looks up `g_bundles[Slot]` and forwards.
template <int Slot>
class SismoSlot : public perfetto::DataSource<SismoSlot<Slot>> {
   public:
    using Base = perfetto::DataSource<SismoSlot<Slot>>;

    void OnSetup(const typename Base::SetupArgs& args) override {
        auto& cb = g_bundles[Slot];
        if (!cb.on_setup) return;
        // Round-trip the parsed config back to bytes — Zig gets the
        // serialized DataSourceConfig and scans it for field 2000.
        // One serialize per session start is negligible.
        std::string s = args.config->SerializeAsString();
        cb.on_setup(cb.user_arg, s.data(), s.size());
    }

    void OnStart(const typename Base::StartArgs&) override {
        auto& cb = g_bundles[Slot];
        if (cb.on_start) cb.on_start(cb.user_arg);
    }

    void OnStop(const typename Base::StopArgs& args) override {
        auto& cb = g_bundles[Slot];
        if (!cb.on_stop) return;
        // The SDK returns the async-stopper as a std::function<void()>.
        // We heap-allocate it and pass the raw pointer to Zig as an
        // opaque handle; Zig calls `sismo_stop_done(handle)` when its
        // worker has finished draining, which invokes + deletes.
        auto* fn = new std::function<void()>(args.HandleStopAsynchronously());
        cb.on_stop(cb.user_arg, static_cast<void*>(fn));
    }

    void OnFlush(const typename Base::FlushArgs& args) override {
        auto& cb = g_bundles[Slot];
        if (!cb.on_flush) return;
        auto* fn = new std::function<void()>(args.HandleFlushAsynchronously());
        cb.on_flush(cb.user_arg, static_cast<void*>(fn));
    }
};

// A second trace writer per slot for a data source's off-CPU sample stream:
// the SAME data source, but its own sequence, so it can carry its own
// PerfSampleDefaults (an off-cpu-ns timebase, distinct from the on-CPU cycle
// counter on the primary sequence). Created lazily on first emit from within
// Trace() — which yields the active instance — and reused on the emitting
// thread thereafter. Bound to one instance; recreated if the instance changes
// (a session restart). One emitter thread per slot, matching how the primary
// stream is emitted.
std::array<std::unique_ptr<perfetto::TraceWriterBase>, kMaxSlots> g_aux_writer;
std::array<uint32_t, kMaxSlots> g_aux_instance{};

// Idempotent guard around `Tracing::Initialize`. The consumer side
// (sismo_consumer.cc) also calls `Tracing::Initialize`; the SDK
// handles re-init for already-initialized backends, but we still
// short-circuit to avoid touching the env var on every call.
std::atomic<bool> g_init_done{false};

}  // namespace

// Per-slot static-member storage. `SismoSlot<N>` is a distinct type
// per N so we need one DECLARE+DEFINE pair each. The X-macro keeps
// the boilerplate aligned with `kMaxSlots` and the per-slot dispatch
// switches below.
#define SISMO_FOR_EACH_SLOT(X) X(0) X(1) X(2) X(3) X(4) X(5) X(6) X(7)

#define DECLARE_SLOT(N) PERFETTO_DECLARE_DATA_SOURCE_STATIC_MEMBERS(SismoSlot<N>);
SISMO_FOR_EACH_SLOT(DECLARE_SLOT)
#undef DECLARE_SLOT

#define DEFINE_SLOT(N) PERFETTO_DEFINE_DATA_SOURCE_STATIC_MEMBERS(SismoSlot<N>);
SISMO_FOR_EACH_SLOT(DEFINE_SLOT)
#undef DEFINE_SLOT

// ---------------------------------------------------------------------------
// C ABI (declared in perfetto_shim.h)
// ---------------------------------------------------------------------------

extern "C" void sismo_init(const char* producer_socket) {
    if (g_init_done.exchange(true)) return;
    // The public C++ SDK's `kSystemBackend` connects to the producer
    // socket named by env var `PERFETTO_PRODUCER_SOCK_NAME` (consulted
    // by `perfetto::GetProducerSocket()`). Set it before
    // `Tracing::Initialize`. Set rather than overwrite-only so the
    // caller's path wins even if the env had a stale value.
    if (producer_socket && *producer_socket) {
        ::setenv("PERFETTO_PRODUCER_SOCK_NAME", producer_socket, 1);
    }
    perfetto::TracingInitArgs args;
    args.backends = perfetto::kSystemBackend;
    perfetto::Tracing::Initialize(args);
}

extern "C" uint32_t sismo_ds_register(
    const uint8_t* desc_bytes, size_t desc_len,
    SismoDsOnSetup on_setup,
    SismoDsOnStart on_start,
    SismoDsOnStop  on_stop,
    SismoDsOnFlush on_flush,
    void*          user_arg) {
    if (!desc_bytes || desc_len == 0) return UINT32_MAX;

    perfetto::protos::gen::DataSourceDescriptor desc;
    if (!desc.ParseFromArray(desc_bytes, static_cast<int>(desc_len))) {
        std::fprintf(stderr, "sismo: sismo_ds_register: descriptor failed to parse\n");
        return UINT32_MAX;
    }

    int slot;
    {
        std::lock_guard<std::mutex> lk(g_register_mu);
        if (g_next_slot >= kMaxSlots) {
            std::fprintf(stderr,
                         "sismo: sismo_ds_register: out of slots (max %d)\n",
                         kMaxSlots);
            return UINT32_MAX;
        }
        slot = g_next_slot++;
        g_bundles[slot] = CbBundle{on_setup, on_start, on_stop, on_flush, user_arg};
    }

    // Dispatch to the per-slot Register. The X-macro keeps this in
    // sync with the per-slot DECLARE/DEFINE blocks above.
#define REGISTER_SLOT(N)                                              \
    case N:                                                           \
        if (!SismoSlot<N>::Register(desc)) {                          \
            std::fprintf(stderr,                                      \
                         "sismo: SismoSlot<%d>::Register failed\n", N); \
            return UINT32_MAX;                                        \
        }                                                             \
        break;
    switch (slot) {
        SISMO_FOR_EACH_SLOT(REGISTER_SLOT)
        default: return UINT32_MAX;
    }
#undef REGISTER_SLOT

    return static_cast<uint32_t>(slot);
}

extern "C" void sismo_ds_emit(uint32_t slot,
                              const uint8_t* packet_bytes,
                              size_t packet_len) {
    if (!packet_bytes || packet_len == 0) return;

    // `Trace([&](ctx){...})` only invokes the lambda for active
    // instances of this DataSource type, so calling it on an
    // un-enabled slot is cheap (no-op).
#define EMIT_SLOT(N)                                                          \
    case N:                                                                   \
        SismoSlot<N>::Trace([&](typename SismoSlot<N>::TraceContext ctx) {    \
            auto packet = ctx.NewTracePacket();                               \
            packet->AppendRawProtoBytes(packet_bytes, packet_len);            \
        });                                                                   \
        break;
    switch (slot) {
        SISMO_FOR_EACH_SLOT(EMIT_SLOT)
        default: break;
    }
#undef EMIT_SLOT
}

// Like sismo_ds_emit, but on the slot's SECOND sequence (the off-CPU stream).
// The bytes are a full TracePacket (PerfSampleDefaults or PerfSample) whose
// perf samples ride the off-cpu-ns timebase this sequence declares.
extern "C" void sismo_ds_emit_offcpu(uint32_t slot,
                                     const uint8_t* packet_bytes,
                                     size_t packet_len) {
  if (!packet_bytes || packet_len == 0) return;

#define EMIT_AUX_SLOT(N)                                                        \
  case N:                                                                       \
    SismoSlot<N>::Trace([&](typename SismoSlot<N>::TraceContext ctx) {          \
      uint32_t idx = ctx.instance_index();                                      \
      perfetto::internal::DataSourceStaticState* ss =                          \
          perfetto::DataSourceHelper<SismoSlot<N>>::type().static_state();      \
      if (!g_aux_writer[N] || g_aux_instance[N] != idx) {                       \
        perfetto::internal::DataSourceState* inst = ss->TryGet(idx);           \
        if (!inst) return;                                                      \
        g_aux_writer[N] =                                                       \
            perfetto::internal::TracingMuxer::Get()->CreateTraceWriter(         \
                ss, idx, inst, perfetto::BufferExhaustedPolicy::kDrop);         \
        g_aux_instance[N] = idx;                                                \
      }                                                                         \
      auto packet = g_aux_writer[N]->NewTracePacket();                          \
      packet->AppendRawProtoBytes(packet_bytes, packet_len);                    \
    });                                                                         \
    break;
  switch (slot) {
    SISMO_FOR_EACH_SLOT(EMIT_AUX_SLOT)
    default: break;
  }
#undef EMIT_AUX_SLOT
}

// Flush the slot's off-CPU trace writer so its buffered packets reach the
// service. The SDK flushes the primary sequence as part of the flush protocol,
// but the off-CPU writer is ours, so the worker flushes it explicitly (on the
// emitting thread) before acking a flush/stop, or its tail would be dropped.
extern "C" void sismo_ds_flush_offcpu(uint32_t slot) {
  if (slot < kMaxSlots && g_aux_writer[slot]) {
    g_aux_writer[slot]->Flush();
  }
}

// Destroy the per-slot aux writers while the SDK is still alive. Their
// destructors flush into the muxer-owned arbiter, so they must not survive
// Tracing::Shutdown() as process-exit statics.
extern "C" void sismo_ds_destroy_writers(void) {
    for (auto& w : g_aux_writer) w.reset();
}

extern "C" void sismo_stop_done(void* handle) {
    if (!handle) return;
    auto* fn = static_cast<std::function<void()>*>(handle);
    (*fn)();
    delete fn;
}

extern "C" void sismo_flush_done(void* handle) {
    if (!handle) return;
    auto* fn = static_cast<std::function<void()>*>(handle);
    (*fn)();
    delete fn;
}
