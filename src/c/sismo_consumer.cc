// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the Apache License, Version 2.0.
//
// Sismo's consumer-side surface, expressed via the Perfetto C++ SDK
// (perfetto/tracing/tracing.h). Replaces the previous split where
// session lifecycle went through the C SDK (perfetto_shim.c) but
// CloneTrace went through the C++ SDK (perfetto_clone.cc) — the
// recorder's "consumer" role now has one consistent backing.
//
// Producer-side (data source registration via the captures' C
// trampolines) still lives in perfetto_shim.c and uses the C SDK's
// PerfettoDsRegister machinery — that's where our trampoline-based
// callback design fits naturally.
//
// The C surface here is what cmd_record.zig and cmd_snapshot.zig
// call into:
//   - session_create / setup / start_blocking / stop_blocking / destroy
//     drive the recorder's tracing session.
//   - clone_to_file is used by `sismo snapshot` (and in principle the
//     recorder, though we no longer auto-flush at session end —
//     snapshotting is exclusively user-driven via `sismo snapshot`).

#include "perfetto_shim.h"

// tracing.h only forward-declares TraceConfig; the .gen.h has the
// full proto-generated class needed for ParseFromArray + Setup().
#include "perfetto/tracing/core/trace_config.h"
#include "perfetto/tracing/tracing.h"

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <vector>

namespace {

// Idempotent — the C++ Tracing::Initialize must be called before any
// NewTrace(). Both the recorder (long-lived process) and the snapshot
// subcommand (short-lived) end up here on first session_create or
// clone_to_file call.
void EnsureInitialized() {
    if (perfetto::Tracing::IsInitialized()) return;
    perfetto::TracingInitArgs args;
    args.backends = perfetto::kSystemBackend;
    perfetto::Tracing::Initialize(args);
}

}  // namespace

struct SismoConsumerSession {
    std::unique_ptr<perfetto::TracingSession> session;
};

extern "C" SismoConsumerSession* sismo_consumer_session_create(void) {
    EnsureInitialized();
    auto* s = new SismoConsumerSession();
    s->session = perfetto::Tracing::NewTrace(perfetto::kSystemBackend);
    if (!s->session) {
        delete s;
        return nullptr;
    }
    return s;
}

extern "C" int sismo_consumer_session_setup(SismoConsumerSession* s,
                                            const void* cfg_bytes,
                                            size_t cfg_len) {
    if (!s || !s->session || !cfg_bytes) return 1;
    perfetto::TraceConfig cfg;
    if (!cfg.ParseFromArray(cfg_bytes, static_cast<int>(cfg_len))) return 2;
    s->session->Setup(cfg);
    return 0;
}

extern "C" void sismo_consumer_session_start_blocking(SismoConsumerSession* s) {
    if (!s || !s->session) return;
    s->session->StartBlocking();
}

extern "C" void sismo_consumer_session_stop_blocking(SismoConsumerSession* s) {
    if (!s || !s->session) return;
    s->session->StopBlocking();
}

extern "C" void sismo_consumer_session_destroy(SismoConsumerSession* s) {
    delete s;  // unique_ptr cleans up the underlying TracingSession.
}

// ---------------------------------------------------------------------------
// Snapshot — clone an existing named session and stream its buffer
// out chunk-by-chunk via the caller's callback.
//
// This is what `sismo snapshot` runs (in its own process, connecting
// to the same in-process service the recorder hosts via
// sismo_traced.cc). The recorder's session is unaffected — clone gives
// us a read-only attached snapshot session; we ReadTrace it
// asynchronously, forwarding each chunk to the C callback. File I/O
// stays on the Zig side: this function never opens, writes, or closes
// a file.
// ---------------------------------------------------------------------------

extern "C" int sismo_consumer_clone_and_stream(const char* source_session_name,
                                               SismoTraceChunkCb cb,
                                               void* user_arg) {
    if (!source_session_name || !cb) return 1;

    EnsureInitialized();

    auto session = perfetto::Tracing::NewTrace(perfetto::kSystemBackend);
    if (!session) return 2;

    // (1) CloneTrace — attach as a read-only clone of the source
    //     session. Async; we wait via condvar with a timeout.
    std::mutex m;
    std::condition_variable cv;
    bool clone_done = false;
    bool clone_ok = false;
    std::string clone_err;

    perfetto::TracingSession::CloneTraceArgs args;
    args.unique_session_name = source_session_name;
    session->CloneTrace(
        args,
        [&](perfetto::TracingSession::CloneTraceCallbackArgs cb_args) {
            std::lock_guard<std::mutex> lk(m);
            clone_done = true;
            clone_ok = cb_args.success;
            if (!cb_args.success) clone_err = cb_args.error;
            cv.notify_one();
        });

    {
        std::unique_lock<std::mutex> lk(m);
        if (!cv.wait_for(lk, std::chrono::seconds(10), [&] { return clone_done; })) {
            std::fprintf(stderr,
                         "sismo: CloneTrace(\"%s\") timed out after 10s "
                         "(is `sismo record --flight-recorder` running?)\n",
                         source_session_name);
            return 7;
        }
    }
    if (!clone_ok) {
        std::fprintf(stderr,
                     "sismo: CloneTrace(\"%s\") failed: %s\n",
                     source_session_name, clone_err.c_str());
        return 3;
    }

    // (2) ReadTrace — async chunk delivery. The callback fires on a
    //     Perfetto-internal thread; we relay each chunk to the
    //     caller's C callback unchanged. Wait until we observe
    //     has_more=false on the final chunk.
    bool read_done = false;
    session->ReadTrace([&](perfetto::TracingSession::ReadTraceCallbackArgs ra) {
        cb(ra.data, ra.size, ra.has_more, user_arg);
        if (!ra.has_more) {
            std::lock_guard<std::mutex> lk(m);
            read_done = true;
            cv.notify_one();
        }
    });

    {
        std::unique_lock<std::mutex> lk(m);
        if (!cv.wait_for(lk, std::chrono::seconds(30), [&] { return read_done; })) {
            std::fprintf(stderr,
                         "sismo: ReadTrace timed out after 30s\n");
            return 8;
        }
    }
    return 0;
}
