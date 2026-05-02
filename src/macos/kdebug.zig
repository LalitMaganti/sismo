//! macOS kdebug reader (sequencing item #3 in the master plan).
//!
//! Captures `DBG_MACH_SCHED` events via the `KERN_KDEBUG` sysctl path,
//! the same channel Apple's `trace(1)` and Instruments use under the hood.
//!
//! IMPORTANT: requires root. KERN_KDEBUG sysctls return EPERM for unprivileged
//! callers (confirmed on Darwin 25.4.0). The
//! `com.apple.private.kernel.tracing` entitlement is Apple-only — third-party
//! binaries cannot get it.
//!
//! See plans/01-kdebug-research.md for the API survey + permission model.

const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .macos) @compileError("kdebug reader is macOS-only");
}

const c = @cImport({
    @cInclude("sys/sysctl.h");
    @cInclude("sys/kdebug.h");
});

// kd_buf event record. Layout copied from
//   MacOSX26.4.sdk/.../Kernel.framework/Headers/sys/kdebug_private.h
// (a private header we don't include from user space — pulls in
// kext-side declarations). The struct is wire-stable across LP32/LP64
// per Apple's own comment in that header.
//
// 64 bytes on arm64 macOS (LP64 + the trailing `unused` field that's only
// present on LP64/arm64 to keep wire compatibility with LP32).
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

pub const KBufInfo = extern struct {
    nkdbufs: c_int,
    nolog: c_int,
    flags: c_uint,
    nkdthreads: c_int,
    bufid: c_int,
};

pub const KdRegType = extern struct {
    type: c_uint,
    value1: c_uint,
    value2: c_uint,
    value3: c_uint,
    value4: c_uint,
};

/// Thread map entry — maps `kd_buf.arg5` (thread ID) to (pid, comm).
/// Layout from xnu's `bsd/sys/kdebug_private.h`. `valid` is misnamed in the
/// kernel header but actually carries the PID.
pub const KdThreadMap = extern struct {
    thread: u64,
    pid: c_int,
    command: [20]u8,
};

/// Extended CPU map entry — maps `kd_buf.cpuid` to a stable CPU name.
/// Preceded in the buffer by `KdCpuMapHeader`.
pub const KdCpuMapExt = extern struct {
    cpu_id: u32,
    flags: u32,
    name: [32]u8,
};

pub const KdCpuMapHeader = extern struct {
    version_no: u32,
    cpu_count: u32,
};

pub const KDBG_CPUMAP_IS_IOP: u32 = 0x1;

/// MACH_SCHED event arguments.
/// Source: xnu `osfmk/kern/sched_prim.c`, function `thread_dispatch`.
/// Argument order has been stable since the arm64 transition; verify against
/// `xnu-*/osfmk/kern/sched_prim.c` for the macOS version you ship against.
///   - arg1 = AST reason the outgoing thread is leaving (`AST_PREEMPT`,
///     `AST_QUANTUM`, etc. — see `osfmk/kern/ast.h`).
///   - arg2 = TID of the **incoming** thread (the one coming on-CPU).
///   - arg3 = sched_pri of the **outgoing** thread.
///   - arg4 = state bits of the outgoing thread (TH_RUN/TH_WAIT/...).
///   - arg5 = TID of the **outgoing** thread (`kd_buf.arg5`, generic field).
pub const MachSchedArgs = struct {
    outgoing_tid: u64,
    incoming_tid: u64,
    outgoing_pri: u32,
    outgoing_state: u32,
    reason: u32,

    pub fn fromBuf(e: *const KdBuf) MachSchedArgs {
        return .{
            .outgoing_tid = e.arg5,
            .incoming_tid = e.arg2,
            .outgoing_pri = @truncate(e.arg3),
            .outgoing_state = @truncate(e.arg4),
            .reason = @truncate(e.arg1),
        };
    }
};

// kd_regtype.type values (from xnu's bsd/sys/kdebug_private.h).
pub const KDBG_TYPENONE: c_uint = 0x80000000;
pub const KDBG_RANGETYPE: c_uint = 0x00000100;
pub const KDBG_VALCHECK: c_uint = 0x00000200;
pub const KDBG_CLASSTYPE: c_uint = 0x00010000;
pub const KDBG_SUBCLSTYPE: c_uint = 0x00020000;

fn errno() c_int {
    return std.c._errno().*;
}

pub const KdebugError = error{
    NotPermitted,
    SetupFailed,
    SetRegFailed,
    EnableFailed,
    ReadFailed,
};

fn sysctlVoid(cmd: c_int) c_int {
    var mib = [_]c_int{ c.CTL_KERN, c.KERN_KDEBUG, cmd };
    return std.c.sysctl(&mib, mib.len, null, null, null, 0);
}

fn sysctlSetInt(cmd: c_int, value: c_int) c_int {
    var mib = [_]c_int{ c.CTL_KERN, c.KERN_KDEBUG, cmd, value };
    return std.c.sysctl(&mib, mib.len, null, null, null, 0);
}

fn sysctlSetReg(reg: *KdRegType) c_int {
    var mib = [_]c_int{ c.CTL_KERN, c.KERN_KDEBUG, c.KERN_KDSETREG };
    var len: usize = @sizeOf(KdRegType);
    return std.c.sysctl(&mib, mib.len, @ptrCast(reg), &len, null, 0);
}

fn sysctlReadTr(out: []KdBuf) !usize {
    var mib = [_]c_int{ c.CTL_KERN, c.KERN_KDEBUG, c.KERN_KDREADTR };
    var len: usize = out.len * @sizeOf(KdBuf);
    if (std.c.sysctl(&mib, mib.len, @ptrCast(out.ptr), &len, null, 0) < 0) {
        return error.ReadFailed;
    }
    // KDREADTR overwrites len with the *event count*, not the byte count
    // (verified: sysctl populates oldlenp with the number of records).
    return len;
}

fn sysctlReadBuf(cmd: c_int, out: []u8) !usize {
    var mib = [_]c_int{ c.CTL_KERN, c.KERN_KDEBUG, cmd };
    var len: usize = out.len;
    if (std.c.sysctl(&mib, mib.len, out.ptr, &len, null, 0) < 0) {
        return error.ReadFailed;
    }
    return len;
}

pub const Capture = struct {
    /// Tear down any prior session, configure buffers + filter, start
    /// recording. Caller must invoke `stop` to disable + drain.
    pub fn start(buffer_events: c_int) KdebugError!void {
        // Idempotent teardown.
        _ = sysctlVoid(c.KERN_KDREMOVE);

        if (sysctlSetInt(c.KERN_KDSETBUF, buffer_events) < 0) {
            return error.SetupFailed;
        }
        if (sysctlVoid(c.KERN_KDSETUP) < 0) {
            return error.SetupFailed;
        }

        var reg = KdRegType{
            .type = KDBG_SUBCLSTYPE,
            .value1 = c.DBG_MACH,
            .value2 = c.DBG_MACH_SCHED,
            .value3 = 0,
            .value4 = 0,
        };
        if (sysctlSetReg(&reg) < 0) {
            _ = sysctlVoid(c.KERN_KDREMOVE);
            return error.SetRegFailed;
        }

        if (sysctlSetInt(c.KERN_KDENABLE, 1) < 0) {
            _ = sysctlVoid(c.KERN_KDREMOVE);
            return error.EnableFailed;
        }
    }

    /// Disable tracing and drain the kernel buffer into `events`. Returns
    /// the number of events read (capped at events.len). Caller can still
    /// pull the thread/cpu maps after this; call `tearDown` when done.
    pub fn stopAndDrain(events: []KdBuf) !usize {
        _ = sysctlSetInt(c.KERN_KDENABLE, 0);
        return try sysctlReadTr(events);
    }

    /// Drain the kernel ring buffer WITHOUT stopping capture. Returns
    /// the number of events read (capped at events.len). Intended for
    /// the streaming model: a polling loop drains every ~100 ms and
    /// emits to a Perfetto session, so the kernel ring never fills up
    /// regardless of capture duration. Same primitive (`KERN_KDREADTR`)
    /// as `stopAndDrain`; this one just doesn't disable first.
    pub fn drain(events: []KdBuf) !usize {
        return try sysctlReadTr(events);
    }

    /// Query the kdebug session metadata (sized buffers, thread count, …).
    /// Call before `tearDown`; the values come from kdebug session state.
    pub fn bufInfo() !KBufInfo {
        var info: KBufInfo = std.mem.zeroes(KBufInfo);
        var mib = [_]c_int{ c.CTL_KERN, c.KERN_KDEBUG, c.KERN_KDGETBUF };
        var len: usize = @sizeOf(KBufInfo);
        if (std.c.sysctl(&mib, mib.len, &info, &len, null, 0) < 0) {
            return error.ReadFailed;
        }
        return info;
    }

    /// Read a fresh thread map by walking the kernel's live proc/uthread
    /// lists.
    ///
    /// We use `KERN_KDREADCURTHRMAP` (sysctl 21), NOT the older
    /// `KERN_KDTHRMAP` (12). KDTHRMAP returns the snapshot taken at
    /// `KERN_KDENABLE` time and — critically — `kdbg_copyout_thread_map`
    /// calls `_clear_thread_map()` after a successful copyout. So the
    /// snapshot is single-shot: the second call (and every subsequent
    /// `bufInfo().nkdthreads`) sees zero entries, all comm lookups fall
    /// back to "?", and threads spawned after `KDENABLE` are absent
    /// regardless. KDREADCURTHRMAP is repeatable, picks up new threads,
    /// and only needs `ktrace_read_check` (not configure-owner perms),
    /// so it survives a `tailspind`/Instruments ownership flip.
    ///
    /// `oldlenp` is bytes (input = capacity, output = bytes written).
    /// Returns the number of entries written.
    pub fn readThreadMap(out_threads: []KdThreadMap) !usize {
        const bytes = std.mem.sliceAsBytes(out_threads);
        var mib = [_]c_int{ c.CTL_KERN, c.KERN_KDEBUG, c.KERN_KDREADCURTHRMAP };
        var len: usize = bytes.len;
        if (std.c.sysctl(&mib, mib.len, bytes.ptr, &len, null, 0) < 0) {
            return error.ReadFailed;
        }
        return len / @sizeOf(KdThreadMap);
    }

    /// Retrieve the extended CPU map. The buffer must be large enough for
    /// `KdCpuMapHeader` + N × `KdCpuMapExt`. Returns the bytes written
    /// (caller parses header + entries from the start).
    pub fn readCpuMap(out: []u8) !usize {
        return try sysctlReadBuf(c.KERN_KDCPUMAP_EXT, out);
    }

    /// Tear down the kdebug session (frees the kernel buffers).
    pub fn tearDown() void {
        _ = sysctlVoid(c.KERN_KDREMOVE);
    }
};

pub fn isRoot() bool {
    return std.c.geteuid() == 0;
}

/// Human-readable name for a `DBG_MACH_SCHED` event code. Driven by the
/// constants in `<sys/kdebug.h>` so it stays in sync with the SDK; we only
/// list the events most relevant to Perfetto-style sched analysis. `null`
/// for unrecognized codes (rare boundary events like `MACH_AMP_DEBUG`).
pub fn schedCodeName(code: u32) ?[]const u8 {
    return switch (code) {
        c.MACH_SCHED => "MACH_SCHED",                       // context switch
        c.MACH_STACK_HANDOFF => "MACH_STACK_HANDOFF",       // direct handoff
        c.MACH_MAKE_RUNNABLE => "MACH_MAKE_RUNNABLE",       // wakeup
        c.MACH_IDLE => "MACH_IDLE",
        c.MACH_BLOCK => "MACH_BLOCK",                       // off-CPU
        c.MACH_WAIT => "MACH_WAIT",                         // wait assertion
        c.MACH_DISPATCH => "MACH_DISPATCH",                 // ctx switch done
        c.MACH_MOVED => "MACH_MOVED",
        c.MACH_GET_URGENCY => "MACH_GET_URGENCY",
        c.MACH_URGENCY => "MACH_URGENCY",
        c.MACH_REDISPATCH => "MACH_REDISPATCH",
        c.MACH_QUANTUM_HANDOFF => "MACH_QUANTUM_HANDOFF",
        c.MACH_SCHED_THREAD_SWITCH => "MACH_SCHED_THREAD_SWITCH",
        c.MACH_SCHED_CHANGE_PRIORITY => "MACH_SCHED_CHANGE_PRIORITY",
        c.MACH_SCHED_QUANTUM_EXPIRED => "MACH_SCHED_QUANTUM_EXPIRED",
        c.MACH_SCHED_THREAD_SELECT => "MACH_SCHED_THREAD_SELECT",
        c.MACH_SCHED_LOAD => "MACH_SCHED_LOAD",
        c.MACH_SCHED_LOAD_EFFECTIVE => "MACH_SCHED_LOAD_EFFECTIVE",
        c.MACH_SCHED_AST_CHECK => "MACH_SCHED_AST_CHECK",
        c.MACH_SCHED_MODE_CHANGE => "MACH_SCHED_MODE_CHANGE",
        c.MACH_SCHED_PREEMPT_TIMER_ACTIVE => "MACH_SCHED_PREEMPT_TIMER_ACTIVE",
        c.MACH_PSET_AVG_EXEC_TIME => "MACH_PSET_AVG_EXEC_TIME",
        c.MACH_TURNSTILE_KERNEL_CHANGE => "MACH_TURNSTILE_KERNEL_CHANGE",
        c.MACH_TURNSTILE_USER_CHANGE => "MACH_TURNSTILE_USER_CHANGE",
        else => null,
    };
}

pub fn extractCode(debugid: u32) u32 {
    return (debugid & c.KDBG_CODE_MASK) >> c.KDBG_CODE_OFFSET;
}

/// The low two bits of `debugid` carry the event semantic:
///   0 = single instantaneous event
///   1 = nested-region START
///   2 = nested-region END
///   3 = unused / reserved
pub const Func = enum(u2) { instant = 0, start = 1, end = 2, none = 3 };

pub fn extractFunc(debugid: u32) Func {
    return @enumFromInt(@as(u2, @intCast(debugid & c.KDBG_FUNC_MASK)));
}

/// Sleep helper; lets the standalone spike pull in this module without
/// dragging std.time.
pub fn sleepMs(ms: c_uint) void {
    const ts: std.c.timespec = .{
        .sec = @intCast(ms / std.time.ms_per_s),
        .nsec = @intCast((ms % std.time.ms_per_s) * std.time.ns_per_ms),
    };
    _ = std.c.nanosleep(&ts, null);
}
