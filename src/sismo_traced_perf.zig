// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Zig wrapper for the in-process Perfetto traced_perf producer.
//! Backed by `src/c/sismo_traced_perf.cc`, which links against
//! libperfetto.a and drives PerfProducer on a worker thread inside
//! the orchestrator process. Linux-only — traced_perf uses
//! perf_event_open which is Linux/Android only.

const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .linux) {
        @compileError("sismo_traced_perf is Linux-only; traced_perf's " ++
            "perf_event_open producer doesn't exist on macOS or Windows");
    }
}

pub const c = @cImport({
    @cInclude("src/c/sismo_traced_perf.h");
});

pub const PerfSvc = opaque {};

pub const Error = error{
    StartFailed,
};

/// Spawn the producer worker thread, build the DirectDescriptorGetter,
/// and connect to the producer socket. Blocks until the worker has
/// issued ConnectWithRetries.
pub fn create(producer_socket: [:0]const u8) !*PerfSvc {
    const ptr = c.sismo_traced_perf_create(producer_socket.ptr);
    if (ptr == null) return Error.StartFailed;
    return @ptrCast(ptr.?);
}

/// Signal the TaskRunner to return. Safe from any thread. Idempotent.
pub fn stop(svc: *PerfSvc) void {
    c.sismo_traced_perf_stop(@ptrCast(svc));
}

/// Join the worker and free the handle. Will Quit() the runner first
/// if stop() wasn't called.
pub fn destroy(svc: *PerfSvc) void {
    c.sismo_traced_perf_destroy(@ptrCast(svc));
}
