// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Windows stub for the sismo heap-profiler control channel. Per
//! `plans/05-heap-research.md` the Windows analog of the POSIX
//! Unix-socket + SCM_RIGHTS design is a per-PID named pipe plus
//! `DuplicateHandle` to hand the shm section across processes.
//!
//! Not implemented yet — this file exists so `heap_protocol.zig`'s
//! per-OS dispatch compiles when targeting Windows and so the public
//! API surface (types + function names) is documented in one place
//! both implementations have to honour. The bodies are stubs that
//! return `error.Unimplemented` so any caller paths that get here at
//! runtime fail loudly rather than silently.

const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .windows) {
        @compileError("heap_protocol_windows is Windows-only; import heap_protocol.zig instead");
    }
}

pub const ProtocolError = error{
    Unimplemented,
    PathTooLong,
    OutOfMemory,
};

pub const AttachConfig = extern struct {
    version: u32 align(8),
    ring_size: u32,
    sample_interval: u64,
    _reserved: [16]u8,
};

comptime {
    if (@sizeOf(AttachConfig) != 32) {
        @compileError("AttachConfig must be 32 bytes for ABI stability");
    }
}

pub const Listener = struct {
    pub fn close(self: *Listener) void {
        self.* = undefined;
    }
};

pub const AttachState = struct {
    config: AttachConfig,

    pub fn closeAll(self: *AttachState) void {
        self.* = undefined;
    }
};

pub fn socketPath(pid: i32, buf: []u8) ![:0]u8 {
    _ = pid;
    _ = buf;
    return error.Unimplemented;
}

pub fn listenForAttach(pid: i32) !Listener {
    _ = pid;
    return error.Unimplemented;
}

pub fn acceptAndReceive(listener: *Listener) !AttachState {
    _ = listener;
    return error.Unimplemented;
}

pub fn connectAndAttach(pid: i32, shm_handle: usize, config: AttachConfig) !usize {
    _ = pid;
    _ = shm_handle;
    _ = config;
    return error.Unimplemented;
}
