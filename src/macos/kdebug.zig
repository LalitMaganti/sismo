// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Thin typed facade over the kdebug ring control, whose `KERN_KDEBUG` sysctl
//! calls now live in Rust (rust-bridge/src/kdebug.rs). This file keeps the
//! wire struct layouts (KdBuf, KdThreadMap) and the sched-event decoders the
//! sched worker's hot loop uses; every sysctl call is on the Rust side.
//!
//! Captures `DBG_MACH_SCHED` events — the channel Apple's `trace(1)` and
//! Instruments use. Requires root: KERN_KDEBUG sysctls return EPERM otherwise.
//! See plans/01-kdebug-research.md for the API survey + permission model.

const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .macos) @compileError("kdebug reader is macOS-only");
}

// kd_buf event record — 64 bytes on arm64 (LP64). Layout from xnu's
// bsd/sys/kdebug_private.h; wire-stable per Apple's own comment.
pub const KdBuf = extern struct {
    timestamp: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64, // thread ID
    debugid: u32,
    cpuid: u32,
    unused: u64,
};

comptime {
    std.debug.assert(@sizeOf(KdBuf) == 64);
}

/// Thread map entry — maps `kd_buf.arg5` (thread ID) to (pid, comm). Layout
/// from xnu's `bsd/sys/kdebug_private.h`.
pub const KdThreadMap = extern struct {
    thread: u64,
    pid: c_int,
    command: [20]u8,
};

comptime {
    std.debug.assert(@sizeOf(KdThreadMap) == 32);
}

/// MACH_SCHED / MACH_STACK_HANDOFF event arguments. Source: xnu
/// `osfmk/kern/sched_prim.c`, `thread_invoke` (fires BEFORE the register
/// switch, so `kd_buf.arg5` is still the OUTGOING thread).
pub const MachSchedArgs = struct {
    outgoing_tid: u64,
    incoming_tid: u64,
    outgoing_pri: u32,
    incoming_pri: u32,
    reason: u32,

    pub fn fromBuf(e: *const KdBuf) MachSchedArgs {
        return .{
            .outgoing_tid = e.arg5,
            .incoming_tid = e.arg2,
            .outgoing_pri = @truncate(e.arg3),
            .incoming_pri = @truncate(e.arg4),
            .reason = @truncate(e.arg1),
        };
    }
};

/// MACH_DISPATCH event arguments. Source: xnu `osfmk/kern/sched_prim.c`,
/// `thread_dispatch` (fires AFTER the switch, so `kd_buf.arg5` is the INCOMING
/// thread; the outgoing thread's finalized state is `arg3`).
pub const MachDispatchArgs = struct {
    outgoing_tid: u64,
    outgoing_state: u32,
    incoming_tid: u64,

    pub fn fromBuf(e: *const KdBuf) MachDispatchArgs {
        return .{
            .outgoing_tid = e.arg1,
            .outgoing_state = @truncate(e.arg3),
            .incoming_tid = e.arg5,
        };
    }
};

pub const KdebugError = error{
    NotPermitted,
    SetupFailed,
    SetRegFailed,
    EnableFailed,
    ReadFailed,
};

// rust-bridge/src/kdebug.rs — KERN_KDEBUG sysctl calls.
extern fn sismo_kdebug_start(buffer_events: c_int) c_int;
extern fn sismo_kdebug_drain(out: [*]u8, cap_events: usize, out_count: *usize) bool;
extern fn sismo_kdebug_read_thread_map(out: [*]u8, cap_bytes: usize, out_entries: *usize) bool;
extern fn sismo_kdebug_teardown() void;

pub const Capture = struct {
    /// Tear down any prior session, configure buffers + the DBG_MACH_SCHED
    /// filter, and start recording. Caller must invoke `tearDown` when done.
    pub fn start(buffer_events: c_int) KdebugError!void {
        return switch (sismo_kdebug_start(buffer_events)) {
            0 => {},
            2 => error.SetRegFailed,
            3 => error.EnableFailed,
            else => error.SetupFailed,
        };
    }

    /// Drain the kernel ring WITHOUT stopping capture. Returns the number of
    /// events read (≤ `events.len`).
    pub fn drain(events: []KdBuf) KdebugError!usize {
        var count: usize = 0;
        if (!sismo_kdebug_drain(@ptrCast(events.ptr), events.len, &count)) return error.ReadFailed;
        return count;
    }

    /// Read a fresh thread map (KERN_KDREADCURTHRMAP — repeatable, picks up
    /// new threads). Returns the number of entries written.
    pub fn readThreadMap(out_threads: []KdThreadMap) KdebugError!usize {
        const bytes = std.mem.sliceAsBytes(out_threads);
        var entries: usize = 0;
        if (!sismo_kdebug_read_thread_map(bytes.ptr, bytes.len, &entries)) return error.ReadFailed;
        return entries;
    }

    /// Tear down the kdebug session (frees the kernel buffers).
    pub fn tearDown() void {
        sismo_kdebug_teardown();
    }
};

/// Extract the event code from a kd_buf `debugid`. KDBG_CODE_MASK/OFFSET are
/// from sys/kdebug.h (0x0000fffc, 2).
pub fn extractCode(debugid: u32) u32 {
    return (debugid & 0x0000fffc) >> 2;
}
