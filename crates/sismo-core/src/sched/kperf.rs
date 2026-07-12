// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! macOS kperf control plane. kperf is a private, system-global singleton — one
//! action/timer table shared across the whole machine. This module owns driving
//! it (via the `kperf.*` sysctls) so the features that use it (off-CPU lazy.wait
//! today; on-CPU timer sampling + PMU counters next) configure it through one
//! place instead of each poking sysctls.
//!
//! All constants here are cross-checked against xnu source by
//! `tools/verify_kperf_constants.py` — run it when bumping macOS.
//!
//! macOS-only; gated in sched/mod.rs.

use crate::mach::{mach_timebase_info, TimebaseInfo};
use std::ffi::c_void;

// kperf samplers bitmask (osfmk/kperf/action.h).
pub(crate) const SAMPLER_TH_INFO: u32 = 1 << 0;
#[allow(dead_code)] // used by the Stage-2 on-CPU consumer
pub(crate) const SAMPLER_KSTACK: u32 = 1 << 2;
pub(crate) const SAMPLER_USTACK: u32 = 1 << 3;

// Action ids are 1-based (0 = "no action").
const OFFCPU_ACTION_ID: u64 = 1;
const UCALLSTACK_DEPTH: u64 = 128;

// ---- sysctl helpers --------------------------------------------------------

fn errno() -> i32 {
    unsafe { *libc::__error() }
}

fn set_u32(name: &[u8], value: u32) -> Result<(), i32> {
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr() as *const libc::c_char,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &value as *const u32 as *mut c_void,
            std::mem::size_of::<u32>(),
        )
    };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

fn set_u64(name: &[u8], value: u64) -> Result<(), i32> {
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr() as *const libc::c_char,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &value as *const u64 as *mut c_void,
            std::mem::size_of::<u64>(),
        )
    };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

/// Indexed kperf knob: the kernel reads `[id, value]` as two u64s.
fn set_indexed(name: &[u8], id: u64, value: u64) -> Result<(), i32> {
    let inputs: [u64; 2] = [id, value];
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr() as *const libc::c_char,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            inputs.as_ptr() as *mut c_void,
            std::mem::size_of::<[u64; 2]>(),
        )
    };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

// ---- mach timebase ---------------------------------------------------------

pub(crate) fn timebase() -> (u64, u64) {
    let mut tb = TimebaseInfo { numer: 1, denom: 1 };
    unsafe { mach_timebase_info(&mut tb) };
    (tb.numer as u64, tb.denom as u64)
}

pub(crate) fn ns_to_ticks(ns: u64) -> u64 {
    let (n, d) = timebase();
    (ns as u128 * d as u128 / n as u128) as u64
}

pub(crate) fn ticks_to_ns(ticks: u64) -> u64 {
    let (n, d) = timebase();
    (ticks as u128 * n as u128 / d as u128) as u64
}

// ---- feature arming --------------------------------------------------------

/// Arm the lazy.wait off-CPU sampler for `pid`, sampling waits longer than
/// `threshold_ns`. No timer/PET — the scheduler triggers it on wakeup. Assumes
/// the kdebug ring is already up and keeps DBG_PERF. (When on-CPU sampling lands
/// this grows into a shared multi-action configure step; today off-CPU is the
/// only kperf user, so it owns action 1.)
pub(crate) fn arm_lazy_wait(pid: i32, threshold_ns: u64) -> Result<(), String> {
    let step = |r: Result<(), i32>, what: &str| r.map_err(|e| format!("{what} failed (errno {e})"));
    step(set_u32(b"kperf.reset\0", 1), "kperf.reset")?;
    step(set_u32(b"kperf.action.count\0", 1), "kperf.action.count")?;
    step(
        set_indexed(b"kperf.action.samplers\0", OFFCPU_ACTION_ID, (SAMPLER_USTACK | SAMPLER_TH_INFO) as u64),
        "kperf.action.samplers",
    )?;
    step(
        set_indexed(b"kperf.action.ucallstack_depth\0", OFFCPU_ACTION_ID, UCALLSTACK_DEPTH),
        "kperf.action.ucallstack_depth",
    )?;
    step(
        set_indexed(b"kperf.action.filter_by_pid\0", OFFCPU_ACTION_ID, pid as u64),
        "kperf.action.filter_by_pid",
    )?;
    step(
        set_u64(b"kperf.lazy.wait_time_threshold\0", ns_to_ticks(threshold_ns)),
        "kperf.lazy.wait_time_threshold",
    )?;
    step(set_u32(b"kperf.lazy.wait_action\0", OFFCPU_ACTION_ID as u32), "kperf.lazy.wait_action")?;
    step(set_u32(b"kperf.sampling\0", 1), "kperf.sampling")?;
    Ok(())
}

/// Stop kperf sampling and clear its state (idempotent; ignores errors).
pub(crate) fn disarm() {
    let _ = set_u32(b"kperf.sampling\0", 0);
    let _ = set_u32(b"kperf.reset\0", 1);
}
