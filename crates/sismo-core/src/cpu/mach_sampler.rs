// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! macOS per-sample CPU capture. Given a thread, this reads its accumulated CPU
//! time (to skip idle threads), and for an active thread suspends it, reads its
//! arm64 register state, unwinds via the Rust unwinder (reading the target's
//! stack directly through `mach_vm_read`), resumes it, and encodes a PerfSample
//! wrapped in a TracePacket body.
//!
//! It builds the packet bytes rather than emitting — the caller emits via the
//! C++ SDK shim — so this module keeps no dependency on `sismo_ds_emit` and
//! `cargo test` still links. macOS/arm64 only; gated in lib.rs.

use crate::proto::ProtoWriter;
use crate::symbolize::unwinder::{StackRegs, Unwinder};

type MachPort = u32;
const KERN_SUCCESS: i32 = 0;

// Mach flavors / counts.
const THREAD_BASIC_INFO: i32 = 3;
const THREAD_BASIC_INFO_COUNT: u32 = 10; // sizeof(thread_basic_info_data_t)/4 = 40/4
const ARM_THREAD_STATE64: i32 = 6;
const ARM_THREAD_STATE64_COUNT: u32 = 68; // sizeof(arm_thread_state64_t)/4 = 272/4
const ARM_THREAD_STATE64_SIZE: usize = 272;

// arm_thread_state64_t field byte offsets: x[29] occupies 0..232.
const OFF_FP: usize = 232;
const OFF_LR: usize = 240;
const OFF_SP: usize = 248;
const OFF_PC: usize = 256;

// thread_basic_info: user_time (time_value_t @0), system_time (@8); each is
// { int32 seconds; int32 microseconds }.
const OFF_USER_SEC: usize = 0;
const OFF_USER_USEC: usize = 4;
const OFF_SYS_SEC: usize = 8;
const OFF_SYS_USEC: usize = 12;

const CLOCK_MONOTONIC: i32 = 6; // <time.h> on Darwin
const TP_FIELD_PERF_SAMPLE: u32 = 66;
const MAX_FRAMES: usize = 32;

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

extern "C" {
    fn thread_info(target: MachPort, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
    fn thread_suspend(target: MachPort) -> i32;
    fn thread_resume(target: MachPort) -> i32;
    fn thread_get_state(target: MachPort, flavor: i32, state: *mut i32, count: *mut u32) -> i32;
    fn mach_vm_read_overwrite(
        target: MachPort,
        address: u64,
        size: u64,
        data: u64,
        out_size: *mut u64,
    ) -> i32;
    fn clock_gettime(clk_id: i32, tp: *mut Timespec) -> i32;
}

fn read_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}
fn read_i32(b: &[u8], off: usize) -> i32 {
    i32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

/// Strip arm64 PAC bits (conservative 40-bit mask) before handing an address to
/// the unwinder.
fn strip_pac(v: u64) -> u64 {
    v & 0x0000_00FF_FFFF_FFFF
}

fn now_monotonic_ns() -> u64 {
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Total user+system CPU time for `thread`, in microseconds, or None on failure.
unsafe fn thread_cpu_time_us(thread: MachPort) -> Option<u64> {
    let mut buf = [0u8; 40];
    let mut count = THREAD_BASIC_INFO_COUNT;
    let rc = unsafe { thread_info(thread, THREAD_BASIC_INFO, buf.as_mut_ptr() as *mut i32, &mut count) };
    if rc != KERN_SUCCESS {
        return None;
    }
    let us = |sec_off: usize, usec_off: usize| {
        read_i32(&buf, sec_off) as u64 * 1_000_000 + read_i32(&buf, usec_off) as u64
    };
    Some(us(OFF_USER_SEC, OFF_USER_USEC) + us(OFF_SYS_SEC, OFF_SYS_USEC))
}

/// The outcome of sampling one thread.
pub struct ThreadSample {
    /// The thread's current CPU-time (µs); the caller tracks the per-thread
    /// delta from it. Falls back to `last_cpu_us` when the read fails.
    pub new_cpu_us: u64,
    /// True iff the thread ran since `last_cpu_us`.
    pub active: bool,
    /// The PerfSample TracePacket body, present only for an active thread that
    /// suspended and unwound cleanly.
    pub packet: Option<Vec<u8>>,
}

/// Sample one thread: read its CPU-time, and for a thread that ran since
/// `last_cpu_us`, suspend it, unwind its stack, and build a PerfSample
/// TracePacket body.
pub fn sample_thread(
    task: MachPort,
    thread: MachPort,
    unwinder: &mut Unwinder,
    pid: u32,
    tid: u64,
    last_cpu_us: u64,
) -> ThreadSample {
    let cpu_now = match unsafe { thread_cpu_time_us(thread) } {
        Some(c) => c,
        None => return ThreadSample { new_cpu_us: last_cpu_us, active: false, packet: None },
    };
    if cpu_now == last_cpu_us {
        // idle — no point unwinding the same stack
        return ThreadSample { new_cpu_us: cpu_now, active: false, packet: None };
    }

    let active = |packet| ThreadSample { new_cpu_us: cpu_now, active: true, packet };

    if unsafe { thread_suspend(thread) } != KERN_SUCCESS {
        return active(None);
    }

    let mut state = [0u8; ARM_THREAD_STATE64_SIZE];
    let mut count = ARM_THREAD_STATE64_COUNT;
    let rc = unsafe {
        thread_get_state(thread, ARM_THREAD_STATE64, state.as_mut_ptr() as *mut i32, &mut count)
    };
    if rc != KERN_SUCCESS {
        unsafe { thread_resume(thread) };
        return active(None);
    }

    let pc = strip_pac(read_u64(&state, OFF_PC));
    let fp = strip_pac(read_u64(&state, OFF_FP));
    let lr = strip_pac(read_u64(&state, OFF_LR));
    let sp = strip_pac(read_u64(&state, OFF_SP));

    // Walk the stack (reading target memory via mach_vm_read). The result isn't
    // interned into a callstack yet — leaf-only samples for now — but the walk
    // is kept so the hot path matches production and is ready for interning.
    let _pcs = unwinder.walk(
        StackRegs { pc, fp, lr, sp },
        |addr| {
            let mut val: u64 = 0;
            let mut got: u64 = 0;
            let rc = unsafe {
                mach_vm_read_overwrite(task, addr, 8, &mut val as *mut u64 as u64, &mut got)
            };
            if rc != KERN_SUCCESS || got < 8 {
                Err(())
            } else {
                Ok(val)
            }
        },
        MAX_FRAMES,
    );

    unsafe { thread_resume(thread) };

    // TracePacket body: timestamp + PerfSample (leaf-only: callstack_iid = 0).
    let mut w = ProtoWriter::new();
    w.write_uint64(8, now_monotonic_ns());
    w.write_perf_sample(
        TP_FIELD_PERF_SAMPLE,
        0,        // cpu — core not tracked
        pid,
        tid as u32,
        0,        // callstack_iid — interning is a follow-up
        0,        // timebase_count
        &[],      // followers
        0,        // data_address
        None,     // data_symbol
    );
    active(Some(w.bytes().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_time_of_own_thread_is_readable() {
        // pthread_mach_thread_np(pthread_self()) would give our port; simpler:
        // mach_thread_self() returns the calling thread's port.
        extern "C" {
            fn mach_thread_self() -> MachPort;
        }
        let t = unsafe { mach_thread_self() };
        let cpu = unsafe { thread_cpu_time_us(t) };
        assert!(cpu.is_some(), "own thread CPU time should be readable");
    }

    #[test]
    fn monotonic_clock_advances() {
        let a = now_monotonic_ns();
        let b = now_monotonic_ns();
        assert!(b >= a && a > 0);
    }
}
