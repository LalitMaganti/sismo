// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Thin typed facade over the macOS libproc bindings, which now live in Rust
//! (rust-bridge/src/proc_info.rs). Used by the sched producer to attach
//! friendly process / thread names to scheduler events. The wire-safe struct
//! layouts + proc_pidinfo/proc_pidpath calls are all on the Rust side; this
//! keeps the small typed API the producer uses.

const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .macos) @compileError("process_tree is macOS-only");
}

pub const MAXTHREADNAMESIZE: usize = 64;
pub const MAXPATHLEN: usize = 1024;

extern fn sismo_proc_parent_pid(pid: c_int, out_ppid: *u32) bool;
extern fn sismo_proc_thread_name(pid: c_int, tid: u64, out: [*]u8, cap: usize) usize;
extern fn sismo_proc_pid_path(pid: c_int, out: [*]u8, cap: usize) usize;

/// Parent pid of `pid`. Null on any lookup failure (pid gone, etc.).
pub fn parentPid(pid: c_int) ?u32 {
    var ppid: u32 = 0;
    if (!sismo_proc_parent_pid(pid, &ppid)) return null;
    return ppid;
}

/// A thread's `pth_name`. `tid` is the xnu thread-id (the value
/// `KdThreadMap.thread` carries). Writes into `out_buf` and returns the
/// sub-slice, or null if the lookup fails or the thread is unnamed.
pub fn threadName(pid: c_int, tid: u64, out_buf: *[MAXTHREADNAMESIZE]u8) ?[]const u8 {
    const n = sismo_proc_thread_name(pid, tid, out_buf, out_buf.len);
    if (n == 0) return null;
    return out_buf[0..n];
}

/// proc_pidpath: full executable path for a pid (used as the cmdline in
/// `GenericKernelProcessTree.Process`). Returns the written sub-slice (which
/// still trails a NUL the caller strips), or null on failure.
pub fn pidPath(pid: c_int, out_buf: *[MAXPATHLEN]u8) ?[]const u8 {
    const n = sismo_proc_pid_path(pid, out_buf, out_buf.len);
    if (n == 0) return null;
    return out_buf[0..n];
}
