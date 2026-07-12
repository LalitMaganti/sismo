// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! macOS kperf control plane. kperf is a private, system-global singleton — one
//! action/timer table shared across the whole machine. This module owns driving
//! it (via the `kperf.*` sysctls) so the features that use it (off-CPU lazy.wait
//! and on-CPU timer sampling today; PMU counters next) configure it through one
//! place instead of each poking sysctls.
//!
//! Both samplers ride ONE kperf configuration: [`arm`] takes a [`KperfConfig`]
//! and sets up whichever actions are requested (off-CPU lazy.wait, on-CPU
//! timer), each pid-filtered, in a single `sampling=1` transaction. This is why
//! it's a shared control plane and not two independent arm calls — kperf has one
//! action table, so the ring host configures both together.
//!
//! All constants here are cross-checked against xnu source by
//! `tools/verify_kperf_constants.py` — run it when bumping macOS.
//!
//! macOS-only; gated in sched/mod.rs.

use crate::mach::{mach_timebase_info, TimebaseInfo};
use std::ffi::c_void;

// kperf samplers bitmask (osfmk/kperf/action.h).
pub(crate) const SAMPLER_TH_INFO: u32 = 1 << 0;
pub(crate) const SAMPLER_KSTACK: u32 = 1 << 2;
pub(crate) const SAMPLER_USTACK: u32 = 1 << 3;

// Callstack depths requested per action.
const UCALLSTACK_DEPTH: u64 = 128;
const KCALLSTACK_DEPTH: u64 = 128;

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

/// What to arm on the shared kperf singleton. Both samplers are pid-filtered to
/// `pid` (this restricts the kernel `kperf_sample` entry — the check PET bypasses
/// but the on-core timer and lazy.wait paths honor). Each `Some` enables one
/// action; the actions get sequential 1-based ids.
pub(crate) struct KperfConfig {
    pub pid: i32,
    /// Off-CPU: sample a thread's blocking stack when it wakes from a wait
    /// longer than this many ns. Scheduler-triggered (no timer).
    pub offcpu_threshold_ns: Option<u64>,
    /// On-CPU: sample the running thread on each CPU every this many ns via a
    /// kperf timer (per-CPU on-core sampling, NOT PET — so pid_filter applies).
    pub oncpu_period_ns: Option<u64>,
}

/// Configure kperf for `cfg` and start sampling. Assumes the kdebug ring is
/// already up and keeps DBG_PERF (the sample events land there). Sets every
/// requested action, the lazy/timer triggers, then flips `sampling=1` as the
/// final step. Idempotent-ish: callers pair this with [`disarm`].
pub(crate) fn arm(cfg: &KperfConfig) -> Result<(), String> {
    let step = |r: Result<(), i32>, what: &str| r.map_err(|e| format!("{what} failed (errno {e})"));

    // One action per enabled sampler, ids 1-based in declaration order.
    let mut next_id = 1u64;
    let offcpu_id = cfg.offcpu_threshold_ns.map(|_| {
        let id = next_id;
        next_id += 1;
        id
    });
    let oncpu_id = cfg.oncpu_period_ns.map(|_| {
        let id = next_id;
        next_id += 1;
        id
    });
    let action_count = next_id - 1;
    if action_count == 0 {
        return Err("kperf arm called with no samplers enabled".into());
    }

    step(set_u32(b"kperf.reset\0", 1), "kperf.reset")?;
    step(set_u32(b"kperf.action.count\0", action_count as u32), "kperf.action.count")?;

    // Off-CPU samples the blocking user stack only (lazy.wait fires in the
    // scheduler, where the kernel stack is just the scheduler). On-CPU also takes
    // the kernel stack (KSTACK) so a timer-interrupted syscall shows kernel time,
    // matching the Linux CPU-samples timeline. TH_INFO carries the pid on both.
    let configure = |id: u64, kernel: bool| -> Result<(), String> {
        let mut samplers = SAMPLER_USTACK | SAMPLER_TH_INFO;
        if kernel {
            samplers |= SAMPLER_KSTACK;
        }
        step(set_indexed(b"kperf.action.samplers\0", id, samplers as u64), "kperf.action.samplers")?;
        step(set_indexed(b"kperf.action.ucallstack_depth\0", id, UCALLSTACK_DEPTH), "kperf.action.ucallstack_depth")?;
        if kernel {
            step(set_indexed(b"kperf.action.kcallstack_depth\0", id, KCALLSTACK_DEPTH), "kperf.action.kcallstack_depth")?;
        }
        step(set_indexed(b"kperf.action.filter_by_pid\0", id, cfg.pid as u64), "kperf.action.filter_by_pid")?;
        Ok(())
    };
    if let Some(id) = offcpu_id {
        configure(id, false)?;
    }
    if let Some(id) = oncpu_id {
        configure(id, true)?;
    }

    if let (Some(id), Some(threshold_ns)) = (offcpu_id, cfg.offcpu_threshold_ns) {
        step(set_u64(b"kperf.lazy.wait_time_threshold\0", ns_to_ticks(threshold_ns)), "kperf.lazy.wait_time_threshold")?;
        step(set_u32(b"kperf.lazy.wait_action\0", id as u32), "kperf.lazy.wait_action")?;
    }
    if let (Some(id), Some(period_ns)) = (oncpu_id, cfg.oncpu_period_ns) {
        // One timer (id 0), firing every period, driving the on-CPU action. A
        // plain kperf timer is per-CPU on-core — it samples whatever runs on each
        // CPU when it fires — so it stays inside the pid_filter (unlike PET).
        step(set_u32(b"kperf.timer.count\0", 1), "kperf.timer.count")?;
        step(set_indexed(b"kperf.timer.period\0", 0, ns_to_ticks(period_ns)), "kperf.timer.period")?;
        step(set_indexed(b"kperf.timer.action\0", 0, id), "kperf.timer.action")?;
    }

    step(set_u32(b"kperf.sampling\0", 1), "kperf.sampling")?;
    Ok(())
}

/// Stop kperf sampling and clear its state (idempotent; ignores errors).
pub(crate) fn disarm() {
    let _ = set_u32(b"kperf.sampling\0", 0);
    let _ = set_u32(b"kperf.reset\0", 1);
}
