//! Zig wrapper for the in-process Perfetto tracing service. Backed by
//! `src/c/sismo_traced.cc`, which links against `libperfetto.a` and
//! drives `ServiceIPCHost`.

const std = @import("std");

pub const c = @cImport({
    @cInclude("sismo_traced.h");
});

pub const TracedSvc = opaque {};

pub const Error = error{
    StartFailed,
};

/// Create the embedded service and bind the per-PID Unix sockets.
/// Returns the opaque handle; caller takes ownership.
pub fn create(producer_socket: [:0]const u8, consumer_socket: [:0]const u8) !*TracedSvc {
    const ptr = c.sismo_traced_create(producer_socket.ptr, consumer_socket.ptr);
    if (ptr == null) return Error.StartFailed;
    return @ptrCast(ptr.?);
}

/// Signal the TaskRunner to return from its internal run loop. Safe
/// from any thread.
pub fn stop(svc: *TracedSvc) void {
    c.sismo_traced_stop(@ptrCast(svc));
}

/// Free the service. Caller must have joined any run-thread first.
pub fn destroy(svc: *TracedSvc) void {
    c.sismo_traced_destroy(@ptrCast(svc));
}
