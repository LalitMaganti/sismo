// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! macOS Mach-based sampler.
//!
//! Wraps `task_threads` + `thread_get_state` to enumerate threads and read
//! their register state. For self-profiling (target = own process) no
//! permissions are needed — `mach_task_self()` returns a usable task port.
//! For sibling-process profiling, `task_for_pid()` requires either root or
//! the `com.apple.security.cs.debugger` entitlement (Apple-restricted).
//!
//! Stack unwinding is not done here — that's framehop's job (via rust-bridge).
//! This layer surfaces (PC, FP, LR, SP) so the unwinder can walk back.
//!
//! NOTE on cImport: we deliberately do NOT `@cImport` `mach/mach.h` or even
//! `mach/mach_port.h` — translate-c trips on `mach_msg_mac_trailer_t`'s
//! static_asserts. The Mach API surface we touch is small enough to declare
//! by hand.

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

// arm/thread_status.h: ARM_THREAD_STATE64 = 6.
pub const ARM_THREAD_STATE64: thread_state_flavor_t = 6;

// arm64 thread register state. Layout matches the non-opaque
// `_STRUCT_ARM_THREAD_STATE64` form (plain u64 fields). Wire format is
// identical to the OPAQUE variant the kernel actually fills — it's all
// 8-byte fields either way.
//
// On arm64 macOS, `pc/lr/fp/sp` carry PAC (Pointer Authentication Code)
// bits in the high address bits when ptrauth is enabled. Use `cleanPC` /
// `cleanFP` etc. to strip the auth bits before passing to an unwinder.
pub const ArmThreadState64 = extern struct {
    x: [29]u64,
    fp: u64,
    lr: u64,
    sp: u64,
    pc: u64,
    cpsr: u32,
    flags: u32,

    pub inline fn stripPAC(v: u64) u64 {
        return v & 0x0000_00FF_FFFF_FFFF; // 40-bit mask, conservative
    }

    pub inline fn cleanPC(self: ArmThreadState64) u64 {
        return stripPAC(self.pc);
    }
    pub inline fn cleanLR(self: ArmThreadState64) u64 {
        return stripPAC(self.lr);
    }
    pub inline fn cleanFP(self: ArmThreadState64) u64 {
        return stripPAC(self.fp);
    }
    pub inline fn cleanSP(self: ArmThreadState64) u64 {
        return stripPAC(self.sp);
    }
};

// ARM_THREAD_STATE64_COUNT = sizeof(arm_thread_state64_t) / sizeof(uint32_t).
pub const ARM_THREAD_STATE64_COUNT: mach_msg_type_number_t =
    @sizeOf(ArmThreadState64) / @sizeOf(u32);

// -- Mach extern functions --------------------------------------------------
// std.c covers task_threads, thread_get_state, thread_resume, thread_info,
// mach_port_deallocate, task_for_pid. The two cross-task VM ops
// (mach_vm_deallocate, mach_vm_read_overwrite), thread_suspend, and
// mach_task_self_ aren't exposed publicly by std.c, so they stay
// declared here.
extern "c" var mach_task_self_: mach_port_t;

extern "c" fn mach_vm_deallocate(
    target: task_t,
    address: mach_vm_address_t,
    size: mach_vm_size_t,
) kern_return_t;

/// Cross-task memory read. Copies `size` bytes from address `address` in
/// `target_task`'s address space into `data` in our address space, writing
/// the actual transferred byte count to `out_size`. Used for stack walking
/// and dyld image enumeration on a sibling process.
extern "c" fn mach_vm_read_overwrite(
    target_task: task_t,
    address: mach_vm_address_t,
    size: mach_vm_size_t,
    data: mach_vm_address_t,
    out_size: *mach_vm_size_t,
) kern_return_t;

extern "c" fn thread_suspend(target: thread_t) kern_return_t;

/// Look up the task port for `pid`. Caller is responsible for
/// `mach_port_deallocate`-ing the returned port when done.
pub fn taskForPid(pid: c_int) SamplerError!task_t {
    var t: task_t = 0;
    if (std.c.task_for_pid(mach_task_self_, pid, &t) != KERN_SUCCESS) {
        return error.TaskForPidFailed;
    }
    return t;
}

/// Read `out.len` bytes from `target`'s address space starting at
/// `address` into `out`. Short reads (transferred < requested) are
/// reported as success with the actual byte count returned; the caller
/// inspects `out` only up to that count.
pub fn vmReadInto(target: task_t, address: u64, out: []u8) SamplerError!usize {
    var got: mach_vm_size_t = 0;
    const rc = mach_vm_read_overwrite(
        target,
        address,
        out.len,
        @intFromPtr(out.ptr),
        &got,
    );
    if (rc != KERN_SUCCESS) return error.VmReadFailed;
    return @intCast(got);
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

/// Suspend a thread — must be paired with `threadResume`. Don't call on the
/// calling thread (deadlock). Suspend count is per-thread; nested suspends
/// require matched resumes.
pub fn threadSuspend(thread: thread_t) SamplerError!void {
    if (thread_suspend(thread) != KERN_SUCCESS) return error.ThreadGetStateFailed;
}

pub fn threadResume(thread: thread_t) SamplerError!void {
    if (std.c.thread_resume(thread) != KERN_SUCCESS) return error.ThreadGetStateFailed;
}

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

/// In-process FP-chain stack walker. ARM64 ABI: at each non-leaf frame, the
/// frame pointer (x29) points to a (saved_fp, saved_lr) pair on the stack.
/// We follow saved_fp upward and emit each saved_lr as a return address.
///
/// Limitations vs. real unwinders (framehop / compact unwind):
///   - Misses **leaf functions** that don't establish a frame.
///   - Walks past tail-call bounces silently.
///   - Trips on functions compiled without `-fno-omit-frame-pointer` (rare
///     on macOS — Apple ABI requires FP).
///
/// Sufficient for "good enough" sampling on macOS, where the system ABI
/// keeps frame pointers. framehop (via rust-bridge) is the higher-fidelity
/// option once we wire it in here.
///
/// Returns the number of frames written to `out_pcs`. The current PC is
/// always the first entry; saved LRs follow.
pub fn walkFpChainSelf(
    state: ArmThreadState64,
    out_pcs: []u64,
) usize {
    if (out_pcs.len == 0) return 0;
    out_pcs[0] = state.cleanPC();
    var n: usize = 1;

    var fp = state.cleanFP();
    while (n < out_pcs.len and fp != 0) {
        // Each frame: [saved_fp, saved_lr] at *fp. Validate alignment.
        if (fp & 0x7 != 0) break;
        const frame: *const [2]u64 = @ptrFromInt(fp);
        const saved_fp = ArmThreadState64.stripPAC(frame[0]);
        const saved_lr = ArmThreadState64.stripPAC(frame[1]);
        if (saved_lr == 0) break;
        out_pcs[n] = saved_lr;
        n += 1;
        if (saved_fp <= fp) break; // stacks grow down; FP must increase
        fp = saved_fp;
    }
    return n;
}

/// Cross-task FP-chain walker. Same shape as `walkFpChainSelf`, but each
/// `(saved_fp, saved_lr)` pair lives in `task`'s address space, so we read
/// the frames via `mach_vm_read_overwrite` instead of dereferencing
/// in-process. A failed/short read terminates the walk silently — same
/// outcome as walking off the bottom of the stack.
///
/// Caller still owns suspending the thread before calling: `state` must be
/// a coherent snapshot, and the stack must not shift mid-walk.
pub fn walkFpChainForeign(
    task: task_t,
    state: ArmThreadState64,
    out_pcs: []u64,
) usize {
    if (out_pcs.len == 0) return 0;
    out_pcs[0] = state.cleanPC();
    var n: usize = 1;

    var fp = state.cleanFP();
    while (n < out_pcs.len and fp != 0) {
        if (fp & 0x7 != 0) break;
        var frame: [2]u64 = undefined;
        const got = vmReadInto(task, fp, std.mem.asBytes(&frame)) catch break;
        if (got < @sizeOf(@TypeOf(frame))) break;
        const saved_fp = ArmThreadState64.stripPAC(frame[0]);
        const saved_lr = ArmThreadState64.stripPAC(frame[1]);
        if (saved_lr == 0) break;
        out_pcs[n] = saved_lr;
        n += 1;
        if (saved_fp <= fp) break;
        fp = saved_fp;
    }
    return n;
}


// -- Public API -------------------------------------------------------------
pub const SamplerError = error{
    TaskThreadsFailed,
    ThreadGetStateFailed,
    TaskForPidFailed,
    VmReadFailed,
};

pub fn taskSelf() task_t {
    return mach_task_self_;
}

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
/// out-of-line via vm_allocate; we deallocate it and also drop our refs on
/// each thread port.
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

/// Read arm64 register state for a thread.
pub fn threadStateArm64(thread: thread_t) SamplerError!ArmThreadState64 {
    var state: ArmThreadState64 = undefined;
    var count: mach_msg_type_number_t = ARM_THREAD_STATE64_COUNT;
    const rc = std.c.thread_get_state(
        thread,
        ARM_THREAD_STATE64,
        @ptrCast(&state),
        &count,
    );
    if (rc != KERN_SUCCESS) return error.ThreadGetStateFailed;
    return state;
}
