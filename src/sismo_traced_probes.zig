//! Zig wrapper for the in-process Perfetto traced_probes producer.
//! Backed by `src/c/sismo_traced_probes.cc`, which links against
//! libperfetto.a and drives ProbesProducer on a worker thread inside
//! the orchestrator process. Linux-only — traced_probes itself is
//! Linux/Android only upstream.

const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .linux) {
        @compileError("sismo_traced_probes is Linux-only; traced_probes' " ++
            "ftrace + procfs producer doesn't exist on macOS or Windows");
    }
}

pub const c = @cImport({
    @cInclude("sismo_traced_probes.h");
});

pub const ProbesSvc = opaque {};

pub const Error = error{
    StartFailed,
};

/// Spawn the producer worker thread and connect to the producer
/// socket. Blocks until the worker has issued ConnectWithRetries.
pub fn create(producer_socket: [:0]const u8) !*ProbesSvc {
    const ptr = c.sismo_traced_probes_create(producer_socket.ptr);
    if (ptr == null) return Error.StartFailed;
    return @ptrCast(ptr.?);
}

/// Signal the TaskRunner to return. Safe from any thread. Idempotent.
pub fn stop(svc: *ProbesSvc) void {
    c.sismo_traced_probes_stop(@ptrCast(svc));
}

/// Join the worker and free the handle. Will Quit() the runner first
/// if stop() wasn't called.
pub fn destroy(svc: *ProbesSvc) void {
    c.sismo_traced_probes_destroy(@ptrCast(svc));
}
