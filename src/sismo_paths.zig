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
    // std.c.open is declared variadic — Apple ARM64's ABI requires
    // variadic args on the stack; a fixed-arg decl would put mode in
    // x2 and the kernel would read garbage from the stack slot.
    const fd = std.c.open(session_lock_path.ptr, .{ .ACCMODE = .RDWR, .CREAT = true }, @as(c_uint, 0o644));
    if (fd < 0) return error.OpenFailed;
    if (std.c.flock(fd, std.c.LOCK.EX | std.c.LOCK.NB) != 0) {
        _ = std.c.close(fd);
        return error.AlreadyHeld;
    }
    // Replace any prior contents with the pid as ASCII. Truncate first
    // (a previous run could have left a longer pid string), then write
    // at offset 0.
    _ = std.c.ftruncate(fd, 0);
    var pid_buf: [24]u8 = undefined;
    const written = std.fmt.bufPrint(&pid_buf, "{d}\n", .{pid}) catch "";
    _ = std.c.pwrite(fd, written.ptr, written.len, 0);
    return fd;
}

pub fn releaseSessionLock(fd: c_int) void {
    // Closing the fd releases the flock. No need to call LOCK_UN first.
    _ = std.c.close(fd);
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
    const fd = std.c.open(session_lock_path.ptr, .{ .ACCMODE = .RDONLY });
    if (fd < 0) return error.NoLockFile;
    defer _ = std.c.close(fd);
    var buf: [24]u8 = undefined;
    const n = std.c.pread(fd, &buf, buf.len, 0);
    if (n <= 0) return error.NoRecorder;
    const text = std.mem.trim(u8, buf[0..@intCast(n)], &std.ascii.whitespace);
    if (text.len == 0) return error.NoRecorder;
    return std.fmt.parseInt(c_int, text, 10) catch return error.InvalidPid;
}

/// Path to the heap preload dylib, relative to the running sismo
/// binary's directory. Layout assumption matches what `zig build`
/// produces: `zig-out/bin/sismo` + `zig-out/lib/libsismo_heap.dylib`.
/// When sismo ships installed (homebrew libexec layout), this becomes
/// `<bindir>/../libexec/sismo/libsismo_heap.dylib`, tried first with a
/// fall back to the dev-tree layout.
///
/// Caller frees the returned slice.
pub fn heapDylibPath(io: std.Io, allocator: std.mem.Allocator) ![:0]u8 {
    // std.process.executablePath dispatches per-OS: _NSGetExecutablePath
    // on macOS, /proc/self/exe on Linux, ImagePathName on Windows.
    var buf: [4096]u8 = undefined;
    const n = try std.process.executablePath(io, &buf);
    const exe_path = buf[0..n];
    const bin_dir = std.fs.path.dirname(exe_path) orelse return error.NoBinDir;

    // Try installed layout first.
    const installed = try std.fmt.allocPrintSentinel(
        allocator,
        "{s}/../libexec/sismo/libsismo_heap.dylib",
        .{bin_dir},
        0,
    );
    if (fileExists(installed)) return installed;
    allocator.free(installed);

    // Fall back to dev-tree layout.
    return try std.fmt.allocPrintSentinel(
        allocator,
        "{s}/../lib/libsismo_heap.dylib",
        .{bin_dir},
        0,
    );
}

fn fileExists(path_z: [:0]const u8) bool {
    return std.c.access(path_z.ptr, std.c.F_OK) == 0;
}
