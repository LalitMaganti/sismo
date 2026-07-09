// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Well-known filesystem paths and binary-relative path resolution for
//! sismo. Centralized here so `cmd_record`, `cmd_prepare`, and any
//! future subcommand agree on the same constants — the whole point of
//! "well-known" is that nothing computes them ad-hoc.
//!
//! Sockets are sismo-owned (not Perfetto's defaults) so they can be
//! renamed or relocated as the project moves toward the wrapped sismo SDK
//! without breaking anything external.

const std = @import("std");
const builtin = @import("builtin");

comptime {
    // /tmp Unix sockets + flock-based session locking are POSIX-only.
    // The Windows analog (`\\.\pipe\sismo-*` named pipes + `LockFileEx`)
    // belongs in a sibling module.
    if (builtin.os.tag == .windows) {
        @compileError("sismo_paths is POSIX-only; Windows analog TBD");
    }
}

/// Embedded `traced` listens here. Workloads with a Perfetto/sismo SDK
/// connect to this path (via PERFETTO_PRODUCER_SOCK_NAME today; via
/// the sismo SDK wrapper baking it in once that lands). One sismo
/// session at a time — see `acquireSessionLock`.
pub const producer_sock: [:0]const u8 = "/tmp/sismo-producer.sock";

/// Sismo's own consumer connects here from inside `sismo record`.
/// Not exposed to anyone outside sismo.
pub const consumer_sock: [:0]const u8 = "/tmp/sismo-consumer.sock";

/// Advisory flock target. Held for the lifetime of `sismo record` to
/// detect a second concurrent recorder. Never unlinked — the file is
/// just a lock anchor; the lock is released when the holding process
/// exits (kernel drops it).
pub const session_lock_path: [:0]const u8 = "/tmp/sismo.lock";

// The session-lock, recorder-pid, and heap-dylib-path LOGIC now lives in Rust
// (rust-bridge/src/sismo_paths.rs); this file is a thin facade so its 5 CLI
// callers keep the same Zig API. The facade collapses as the cmd_* commands
// migrate to Rust (P4). The socket-path constants above stay here (stable
// literals, not logic).
extern fn sismo_acquire_session_lock(pid: c_int) c_int;
extern fn sismo_release_session_lock(fd: c_int) void;
extern fn sismo_read_recorder_pid(out_pid: *c_int) c_int;
extern fn sismo_heap_dylib_path(out: [*]u8, cap: usize) usize;

pub const LockError = error{
    OpenFailed,
    AlreadyHeld,
};

/// Acquire the session lock or fail, and write the recorder's pid to
/// it so `sismo snapshot` (and any other tool) can find the recorder.
/// The returned fd must be held for the lifetime of the recording
/// (kernel drops the lock when the fd is closed or the process exits).
/// Caller closes via `releaseSessionLock`.
pub fn acquireSessionLock(pid: c_int) LockError!c_int {
    const fd = sismo_acquire_session_lock(pid);
    return switch (fd) {
        -1 => error.OpenFailed,
        -2 => error.AlreadyHeld,
        else => fd,
    };
}

pub fn releaseSessionLock(fd: c_int) void {
    sismo_release_session_lock(fd);
}

pub const ReadPidError = error{
    NoLockFile,
    NoRecorder,
    InvalidPid,
};

/// Read the recorder's pid from the session lock file. Used by
/// `sismo snapshot` (and future companion tools) to find a running
/// recorder. Returns an error if the file is absent or empty.
pub fn readRecorderPid() ReadPidError!c_int {
    var pid: c_int = 0;
    return switch (sismo_read_recorder_pid(&pid)) {
        0 => pid,
        -1 => error.NoLockFile,
        -2 => error.NoRecorder,
        else => error.InvalidPid,
    };
}

/// Path to the heap preload dylib, relative to the running sismo binary's
/// directory. Tries the install / cargo-dev / legacy-zig layouts and returns
/// the first that exists, else the cargo-dev candidate as a best-effort. Caller
/// frees the returned slice. (`io` is unused now — the Rust side reads the
/// executable path itself — but kept for call-site stability.)
pub fn heapDylibPath(io: std.Io, allocator: std.mem.Allocator) ![:0]u8 {
    _ = io;
    var buf: [4096]u8 = undefined;
    const n = sismo_heap_dylib_path(&buf, buf.len);
    if (n == 0 or n >= buf.len) return error.NoBinDir;
    return allocator.dupeZ(u8, buf[0..n]);
}
