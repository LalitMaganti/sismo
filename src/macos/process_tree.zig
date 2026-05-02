//! Thin Zig bindings over `<libproc.h>` proc_pidinfo flavors used by
//! the macOS sched producer to attach friendly process / thread names
//! to scheduler events.
//!
//! Two flavors today:
//!   - `PROC_PIDTBSDINFO`     → ppid + 16-char `pbi_comm` for a pid.
//!   - `PROC_PIDTHREADID64INFO` → 64-char `pth_name` for a thread by
//!                                its xnu thread-id (matches the
//!                                `kd_buf.arg5` value the sched producer
//!                                already keys on).
//!
//! The kdebug threadmap (`KdThreadMap.command`) carries the same 16-char
//! comm but truncates beyond that and is empty for threads spawned
//! before kdebug enable — proc_pidinfo plugs both holes. See
//! `plans/09-cxx-sdk-direct-and-protovm.md` Phase 3 for the design.

const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .macos) @compileError("process_tree is macOS-only");
}

// Layouts copied from `<sys/proc_info.h>` (Darwin 25.4 SDK):
//   struct proc_bsdinfo (PROC_PIDTBSDINFO_SIZE = sizeof)
//   struct proc_threadinfo (PROC_PIDTHREADID64INFO_SIZE = sizeof)
//
// We only read a handful of fields — but the buffer size handed to
// `proc_pidinfo` MUST equal the declared SIZE of the flavor or the
// kernel returns ENOMEM, so the structs need to mirror the kernel
// layout byte-for-byte. Verified at comptime via @sizeOf assertions
// below.

const MAXCOMLEN: usize = 16;
const MAXTHREADNAMESIZE: usize = 64;

pub const ProcBsdinfo = extern struct {
    pbi_flags: u32,
    pbi_status: u32,
    pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: u32,
    pbi_gid: u32,
    pbi_ruid: u32,
    pbi_rgid: u32,
    pbi_svuid: u32,
    pbi_svgid: u32,
    rfu_1: u32,
    pbi_comm: [MAXCOMLEN]u8,
    pbi_name: [MAXCOMLEN * 2]u8,
    pbi_nfiles: u32,
    pbi_pgid: u32,
    pbi_pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    pbi_nice: i32,
    pbi_start_tvsec: u64,
    pbi_start_tvusec: u64,
};

pub const ProcThreadinfo = extern struct {
    pth_user_time: u64,
    pth_system_time: u64,
    pth_cpu_usage: i32,
    pth_policy: i32,
    pth_run_state: i32,
    pth_flags: i32,
    pth_sleep_time: i32,
    pth_curpri: i32,
    pth_priority: i32,
    pth_maxpriority: i32,
    pth_name: [MAXTHREADNAMESIZE]u8,
};

comptime {
    // From `<sys/proc_info.h>` on Darwin 25.4 (verified via cc -E):
    //   PROC_PIDTBSDINFO_SIZE       = sizeof(struct proc_bsdinfo)    = 136
    //   PROC_PIDTHREADID64INFO_SIZE = sizeof(struct proc_threadinfo) = 112
    // proc_pidinfo enforces the size match, so a layout drift would
    // be caught at runtime — but failing fast at comptime saves an
    // afternoon of "why is this returning ENOMEM" debugging.
    std.debug.assert(@sizeOf(ProcBsdinfo) == 136);
    std.debug.assert(@sizeOf(ProcThreadinfo) == 112);
}

pub const PROC_PIDTBSDINFO: c_int = 3;
pub const PROC_PIDTHREADID64INFO: c_int = 15;

extern "c" fn proc_pidinfo(
    pid: c_int,
    flavor: c_int,
    arg: u64,
    buffer: ?*anyopaque,
    buffersize: c_int,
) c_int;

/// Fetch BSDINFO for a pid. Returns null on ESRCH (pid gone) or any
/// other proc_pidinfo failure — callers treat null as "not in our
/// process universe right now" rather than distinguishing transient
/// vs. permanent errors.
pub fn bsdinfo(pid: c_int) ?ProcBsdinfo {
    var info: ProcBsdinfo = std.mem.zeroes(ProcBsdinfo);
    const rc = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, @sizeOf(ProcBsdinfo));
    if (rc != @sizeOf(ProcBsdinfo)) return null;
    return info;
}

/// Fetch a thread's pth_name. `tid` is the xnu thread-id (the same
/// value `KdThreadMap.thread` carries — Darwin's `thread_t.thread_id`,
/// not the pthread `mach_port_t`). Returns null if the lookup fails or
/// the thread has no name (kernel zero-fills `pth_name` for unnamed
/// threads — we treat that as "no useful name" too).
pub fn threadName(pid: c_int, tid: u64, out_buf: *[MAXTHREADNAMESIZE]u8) ?[]const u8 {
    var info: ProcThreadinfo = std.mem.zeroes(ProcThreadinfo);
    const rc = proc_pidinfo(pid, PROC_PIDTHREADID64INFO, tid, &info, @sizeOf(ProcThreadinfo));
    if (rc != @sizeOf(ProcThreadinfo)) return null;
    @memcpy(out_buf, &info.pth_name);
    const name = std.mem.sliceTo(out_buf, 0);
    if (name.len == 0) return null;
    return name;
}

/// proc_pidpath: full executable path for a pid. Used as the cmdline
/// in `GenericKernelProcessTree.Process`. Returns null on failure.
extern "c" fn proc_pidpath(pid: c_int, buffer: ?*anyopaque, buffersize: u32) c_int;

pub const MAXPATHLEN: usize = 1024;

pub fn pidPath(pid: c_int, out_buf: *[MAXPATHLEN]u8) ?[]const u8 {
    @memset(out_buf, 0);
    const n = proc_pidpath(pid, out_buf, @intCast(MAXPATHLEN));
    if (n <= 0) return null;
    return out_buf[0..@intCast(n)];
}
