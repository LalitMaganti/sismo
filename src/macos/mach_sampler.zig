// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! macOS Mach thread enumeration + identity/CPU-time queries.
//!
//! `task_threads` to enumerate a task's threads, `thread_info` for each
//! thread's kernel TID and accumulated CPU time. `task_for_pid()` requires
//! root or the `com.apple.security.cs.debugger` entitlement for a sibling
//! process (self-profiling needs no permissions).
//!
//! The per-sample hot path — thread suspend/resume, arm64 register read, stack
//! reads, and unwinding — lives in Rust (rust-bridge/src/mach_sampler.rs).
//!
//! cImport is deliberately avoided for `mach/mach.h` / `mach/mach_port.h`
//! — translate-c trips on `mach_msg_mac_trailer_t`'s static_asserts. The
//! Mach API surface used here is small enough to declare by hand.

const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .macos) @compileError("Mach sampler is macOS-only");
    if (builtin.cpu.arch != .aarch64) @compileError("only arm64 wired up so far");
}

// -- Mach types -------------------------------------------------------------
pub const mach_port_t = u32;
pub const task_t = mach_port_t;
pub const thread_t = mach_port_t;
pub const kern_return_t = c_int;
pub const mach_msg_type_number_t = u32;
pub const mach_vm_address_t = u64;
pub const mach_vm_size_t = u64;
pub const thread_state_flavor_t = c_int;

pub const KERN_SUCCESS: kern_return_t = 0;

// -- Mach extern functions --------------------------------------------------
// std.c covers task_threads, thread_info, mach_port_deallocate, task_for_pid.
// mach_vm_deallocate (to free the thread-port array) and mach_task_self_
// aren't exposed publicly by std.c, so they stay declared here.
extern "c" var mach_task_self_: mach_port_t;

extern "c" fn mach_vm_deallocate(
    target: task_t,
    address: mach_vm_address_t,
    size: mach_vm_size_t,
) kern_return_t;

/// Look up the task port for `pid`. Caller is responsible for
/// `mach_port_deallocate`-ing the returned port when done.
pub fn taskForPid(pid: c_int) SamplerError!task_t {
    var t: task_t = 0;
    if (std.c.task_for_pid(mach_task_self_, pid, &t) != KERN_SUCCESS) {
        return error.TaskForPidFailed;
    }
    return t;
}

// thread_info flavor for THREAD_BASIC_INFO.
pub const THREAD_BASIC_INFO: c_int = 3;
pub const THREAD_IDENTIFIER_INFO: c_int = 4;

/// `time_value_t` from mach/time_value.h.
pub const TimeValue = extern struct {
    seconds: c_int,
    microseconds: c_int,

    pub inline fn toMicros(self: TimeValue) u64 {
        return @as(u64, @intCast(self.seconds)) * 1_000_000 + @as(u64, @intCast(self.microseconds));
    }
};

/// `thread_basic_info_data_t` from mach/thread_info.h.
pub const ThreadBasicInfo = extern struct {
    user_time: TimeValue,
    system_time: TimeValue,
    cpu_usage: c_int,
    policy: c_int,
    run_state: c_int,
    flags: c_int,
    suspend_count: c_int,
    sleep_time: c_int,
};

pub const THREAD_BASIC_INFO_COUNT: mach_msg_type_number_t =
    @sizeOf(ThreadBasicInfo) / @sizeOf(u32);

/// `thread_identifier_info_data_t` from mach/thread_info.h. Gives the
/// kernel thread ID (matches `kd_buf.arg5` from kdebug events).
pub const ThreadIdentifierInfo = extern struct {
    thread_id: u64,
    thread_handle: u64,
    dispatch_qaddr: u64,
};

pub const THREAD_IDENTIFIER_INFO_COUNT: mach_msg_type_number_t =
    @sizeOf(ThreadIdentifierInfo) / @sizeOf(u32);

/// Total user+system CPU time accumulated by `thread`, in microseconds.
/// Cheap (no suspend needed); the kernel updates this counter independently.
/// samply's "skip walking the stack if cpu delta is zero" optimization
/// hinges on this.
pub fn threadCpuTimeUs(thread: thread_t) SamplerError!u64 {
    var info: ThreadBasicInfo = undefined;
    var count: mach_msg_type_number_t = THREAD_BASIC_INFO_COUNT;
    if (std.c.thread_info(thread, THREAD_BASIC_INFO, @ptrCast(&info), &count) != KERN_SUCCESS) {
        return error.ThreadGetStateFailed;
    }
    return info.user_time.toMicros() + info.system_time.toMicros();
}

/// Get the kernel TID for `thread` (matches kdebug's `arg5` field).
pub fn threadId(thread: thread_t) SamplerError!u64 {
    var info: ThreadIdentifierInfo = undefined;
    var count: mach_msg_type_number_t = THREAD_IDENTIFIER_INFO_COUNT;
    if (std.c.thread_info(thread, THREAD_IDENTIFIER_INFO, @ptrCast(&info), &count) != KERN_SUCCESS) {
        return error.ThreadGetStateFailed;
    }
    return info.thread_id;
}

// -- Public API -------------------------------------------------------------
pub const SamplerError = error{
    TaskThreadsFailed,
    ThreadGetStateFailed,
    TaskForPidFailed,
    VmReadFailed,
};

/// Enumerate the threads of `task`. Caller frees with `freeThreadList`.
pub fn threadList(task: task_t) SamplerError![]thread_t {
    var list: [*]thread_t = undefined;
    var count: mach_msg_type_number_t = 0;
    if (std.c.task_threads(task, &list, &count) != KERN_SUCCESS) {
        return error.TaskThreadsFailed;
    }
    return list[0..count];
}

/// Free the thread-port array returned by `threadList`. Mach allocates it
/// out-of-line via vm_allocate; deallocates that and drops the ref on each
/// thread port.
pub fn freeThreadList(task: task_t, threads: []thread_t) void {
    for (threads) |t| {
        _ = std.c.mach_port_deallocate(task, t);
    }
    _ = mach_vm_deallocate(
        task,
        @intFromPtr(threads.ptr),
        threads.len * @sizeOf(thread_t),
    );
}

