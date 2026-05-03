// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! POSIX implementation of the sismo heap-profiler control channel.
//! Per `plans/05-heap-research.md`:
//!
//! - Per-PID well-known Unix socket at `$TMPDIR/sismo-heap-{pid}.sock`
//! - Client (in target) `accept()`s in a background thread spawned at
//!   preload time; shm fd transferred via `SCM_RIGHTS`.
//! - Sismo (consumer) `connect()`s by PID, creates the shm, sends the
//!   fd + a small `AttachConfig` header.
//! - Detach: sismo closes the socket; client sees EOF and goes back
//!   to dormant.
//!
//! The Windows analog (named pipe + DuplicateHandle cross-process)
//! lives in `heap_protocol_windows.zig`; consumers should import
//! `heap_protocol.zig` (the OS dispatcher) so they get the right one.

const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag == .windows) {
        @compileError("heap_protocol_posix is POSIX-only; import heap_protocol.zig instead");
    }
}

const SockaddrUn = std.c.sockaddr.un;

// cmsghdr is followed by data, alignment varies. Use raw bytes.
fn cmsgAlign(n: usize) usize {
    const a: usize = @sizeOf(usize);
    return (n + a - 1) & ~(a - 1);
}
const CMSGHDR_BYTES: usize = 12; // sizeof(struct cmsghdr) on Darwin (u32 len + 2 × c_int)
const CMSG_DATA_OFFSET: usize = cmsgAlign(CMSGHDR_BYTES);

pub const ProtocolError = error{
    SocketCreate,
    SocketBind,
    SocketListen,
    SocketAccept,
    SocketConnect,
    SendFailed,
    RecvFailed,
    NoFdReceived,
    PathTooLong,
    OutOfMemory,
};

/// Shape of the first message sismo sends to the dormant client.
/// Fixed-size; no length-prefixing. Future expansion: reserve some
/// bytes or version-tag.
pub const AttachConfig = extern struct {
    /// Wire-format version. Bump if the layout changes.
    version: u32 align(8),
    /// Size of the shm ring's data region in bytes. Power of two.
    ring_size: u32,
    /// Sampling interval (bytes between samples). Currently informational;
    /// the client doesn't sample yet.
    sample_interval: u64,
    /// Reserved.
    _reserved: [16]u8,
};

comptime {
    if (@sizeOf(AttachConfig) != 32) {
        @compileError("AttachConfig must be 32 bytes for ABI stability");
    }
}

// sun_path capacity differs across BSDs (104 on Darwin) and Linux (108).
// Use the std.c struct's actual field length so socketPath rejects
// over-long paths consistently on both.
const SUN_PATH_MAX: usize = @typeInfo(@FieldType(SockaddrUn, "path")).array.len;

/// Build the per-PID well-known socket path: `/tmp/sismo-heap-{pid}.sock`.
/// Hardcoded `/tmp` (not `$TMPDIR`) so the orchestrator can find the
/// socket even when run with sudo — sudo gets root's TMPDIR (something
/// like `/var/folders/zz/...`) which differs from the launching user's
/// TMPDIR. /tmp is shared. A future hardening pass could put per-user
/// sockets under the user's runtime dir.
pub fn socketPath(pid: i32, buf: []u8) ![:0]u8 {
    const path = std.fmt.bufPrintZ(buf, "/tmp/sismo-heap-{d}.sock", .{pid}) catch
        return error.PathTooLong;
    if (path.len >= SUN_PATH_MAX) return error.PathTooLong;
    return path;
}

fn fillSockaddr(addr: *SockaddrUn, path: [:0]const u8) void {
    addr.* = std.mem.zeroes(SockaddrUn);
    addr.family = std.c.AF.UNIX;
    @memcpy(addr.path[0..path.len], path);
    addr.path[path.len] = 0;
    // Darwin/BSD's sockaddr_un has a leading sun_len byte the kernel
    // reads to size the address; Linux/glibc has no such field and
    // takes the size from the addrlen arg of bind/connect.
    if (@hasField(SockaddrUn, "len")) {
        addr.len = @intCast(2 + path.len + 1);
    }
}

// ---- Client side (the dormant in-process side, in the target) ------------

pub const Listener = struct {
    fd: c_int,
    path_buf: [128]u8,
    path_len: usize,

    pub fn close(self: *Listener) void {
        _ = std.c.unlink(@ptrCast(self.path_buf[0..self.path_len :0].ptr));
        _ = std.c.close(self.fd);
        self.* = undefined;
    }
};

/// Bind and listen on the well-known per-PID socket. The target's
/// preload calls this once at load time, then loops on `accept`.
pub fn listenForAttach(pid: i32) !Listener {
    var listener: Listener = undefined;
    const path = try socketPath(pid, &listener.path_buf);
    listener.path_len = path.len;
    // Pre-clean any stale socket left from a prior run.
    _ = std.c.unlink(path.ptr);

    const fd = std.c.socket(std.c.AF.UNIX, std.c.SOCK.STREAM, 0);
    if (fd < 0) return error.SocketCreate;
    errdefer _ = std.c.close(fd);

    var sa: SockaddrUn = undefined;
    fillSockaddr(&sa, path);
    if (std.c.bind(fd, @ptrCast(&sa), @sizeOf(SockaddrUn)) != 0) return error.SocketBind;
    if (std.c.listen(fd, 1) != 0) return error.SocketListen;

    listener.fd = fd;
    return listener;
}

/// Block until sismo connects + sends the attach handshake. Returns
/// the AttachConfig + the received shm fd (caller takes ownership).
/// On EOF or error, returns null (client should go back to dormant).
pub fn acceptAndReceive(listener: *Listener) !AttachState {
    const conn = std.c.accept(listener.fd, null, null);
    if (conn < 0) return error.SocketAccept;
    errdefer _ = std.c.close(conn);

    var config: AttachConfig = undefined;
    var iov = std.posix.iovec{
        .base = @ptrCast(&config),
        .len = @sizeOf(AttachConfig),
    };

    // Control buffer big enough for one fd (cmsghdr + sizeof(int)).
    var cbuf: [CMSG_DATA_OFFSET + @sizeOf(c_int)]u8 align(@sizeOf(usize)) = undefined;
    var msg = std.c.msghdr{
        .name = null,
        .namelen = 0,
        .iov = @ptrCast(&iov),
        .iovlen = 1,
        .control = &cbuf,
        .controllen = cbuf.len,
        .flags = 0,
    };

    const n = std.c.recvmsg(conn, &msg, 0);
    if (n != @as(isize, @intCast(@sizeOf(AttachConfig)))) return error.RecvFailed;
    if (msg.controllen < CMSG_DATA_OFFSET + @sizeOf(c_int)) return error.NoFdReceived;

    // Pull the fd out of cbuf (just past the cmsghdr header).
    const fd_ptr: *const c_int = @ptrCast(@alignCast(&cbuf[CMSG_DATA_OFFSET]));
    const shm_fd = fd_ptr.*;
    if (shm_fd < 0) return error.NoFdReceived;

    return .{ .conn_fd = conn, .shm_fd = shm_fd, .config = config };
}

pub const AttachState = struct {
    /// Control connection — when sismo closes it, we detach.
    conn_fd: c_int,
    /// shm fd received via SCM_RIGHTS. Caller owns; pass to
    /// `RingBuffer.attach`.
    shm_fd: c_int,
    config: AttachConfig,

    pub fn closeAll(self: *AttachState) void {
        _ = std.c.close(self.conn_fd);
        _ = std.c.close(self.shm_fd);
        self.* = undefined;
    }
};

// ---- Consumer side (sismo orchestrator) ----------------------------------

/// Connect to a target by PID and send the attach handshake.
/// Returns the control connection fd (caller closes to detach).
pub fn connectAndAttach(pid: i32, shm_fd: c_int, config: AttachConfig) !c_int {
    var path_buf: [128]u8 = undefined;
    const path = try socketPath(pid, &path_buf);

    const fd = std.c.socket(std.c.AF.UNIX, std.c.SOCK.STREAM, 0);
    if (fd < 0) return error.SocketCreate;
    errdefer _ = std.c.close(fd);

    var sa: SockaddrUn = undefined;
    fillSockaddr(&sa, path);
    if (std.c.connect(fd, @ptrCast(&sa), @sizeOf(SockaddrUn)) != 0) return error.SocketConnect;

    var cfg_local = config;
    var iov = std.posix.iovec_const{
        .base = @ptrCast(&cfg_local),
        .len = @sizeOf(AttachConfig),
    };

    // Build SCM_RIGHTS control buffer carrying shm_fd.
    var cbuf: [CMSG_DATA_OFFSET + @sizeOf(c_int)]u8 align(@sizeOf(usize)) = undefined;
    @memset(&cbuf, 0);
    // cmsghdr layout (Darwin): u32 cmsg_len, c_int cmsg_level, c_int cmsg_type
    const cmsg_len_ptr: *u32 = @ptrCast(@alignCast(&cbuf[0]));
    cmsg_len_ptr.* = @intCast(CMSG_DATA_OFFSET + @sizeOf(c_int));
    const cmsg_level_ptr: *c_int = @ptrCast(@alignCast(&cbuf[4]));
    cmsg_level_ptr.* = std.c.SOL.SOCKET;
    const cmsg_type_ptr: *c_int = @ptrCast(@alignCast(&cbuf[8]));
    cmsg_type_ptr.* = std.c.SCM.RIGHTS;
    const fd_ptr: *c_int = @ptrCast(@alignCast(&cbuf[CMSG_DATA_OFFSET]));
    fd_ptr.* = shm_fd;

    var msg = std.c.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = @ptrCast(&iov),
        .iovlen = 1,
        .control = &cbuf,
        .controllen = cbuf.len,
        .flags = 0,
    };

    const n = std.c.sendmsg(fd, &msg, 0);
    if (n != @as(isize, @intCast(@sizeOf(AttachConfig)))) return error.SendFailed;
    return fd;
}
