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
pub(crate) const SAMPLER_PMC_CPU: u32 = 1 << 5; // per-sample PMU counters (on-core)

// kpc counter classes (osfmk/kern/kpc.h): FIXED = cycles + instructions (no
// event selection needed); CONFIGURABLE = programmable counters whose event is
// chosen via a per-microarchitecture selector word.
const KPC_CLASS_FIXED_MASK: u32 = 1 << 0;
const KPC_CLASS_CONFIGURABLE_MASK: u32 = 1 << 1;

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

// ---- kpc (PMU counter) config plane ----------------------------------------
//
// kpc is driven through the `kpc.*` sysctls (bsd/kern/kern_kpc.c). The array
// sysctls (kpc.config) use a "bigarray" convention: the class-mask u64 is read
// first, then the register array (config_count(classes) u64s) contiguously after
// it. kpc.counting takes an int class-mask. config_count / counter_count are
// in/out ints (class-mask in, count out).

/// PMU config for on-CPU samples: raw configurable-counter event selectors
/// (per-microarchitecture event numbers). Fixed counters (cycles + instructions)
/// are enabled alongside; an empty `events` means fixed-only.
pub(crate) struct KpcConfig {
    pub events: Vec<u64>,
}

/// Read a kpc in/out `int` sysctl (kpc.config_count / kpc.counter_count): the
/// class mask goes in, the count comes back.
fn kpc_query_count(name: &[u8], classes: u32) -> u32 {
    let class_in: i32 = classes as i32;
    let mut count_out: i32 = 0;
    let mut oldlen = std::mem::size_of::<i32>();
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr() as *const libc::c_char,
            &mut count_out as *mut i32 as *mut c_void,
            &mut oldlen,
            &class_in as *const i32 as *mut c_void,
            std::mem::size_of::<i32>(),
        )
    };
    if rc == 0 { count_out.max(0) as u32 } else { 0 }
}

/// Write kpc.config: the u64 class mask followed by one config word per
/// configurable counter (the bigarray convention).
fn kpc_set_config(classes: u32, configs: &[u64]) -> Result<(), i32> {
    let mut buf: Vec<u8> = Vec::with_capacity(8 + configs.len() * 8);
    buf.extend_from_slice(&(classes as u64).to_ne_bytes());
    for c in configs {
        buf.extend_from_slice(&c.to_ne_bytes());
    }
    let rc = unsafe {
        libc::sysctlbyname(
            b"kpc.config\0".as_ptr() as *const libc::c_char,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            buf.as_ptr() as *mut c_void,
            buf.len(),
        )
    };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

/// Write kpc.counting: an int class mask that starts those counter classes.
fn kpc_set_counting(classes: u32) -> Result<(), i32> {
    let v: i32 = classes as i32;
    let rc = unsafe {
        libc::sysctlbyname(
            b"kpc.counting\0".as_ptr() as *const libc::c_char,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &v as *const i32 as *mut c_void,
            std::mem::size_of::<i32>(),
        )
    };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

/// Build the kpc config-word array for `events`, sized to the hardware's
/// configurable-counter count: extra events are dropped (logged), fewer are
/// zero-padded (leaving those counters disabled). Public for testing the layout.
pub(crate) fn kpc_config_words(events: &[u64], n_config: u32) -> Vec<u64> {
    let mut configs = vec![0u64; n_config as usize];
    if events.len() > n_config as usize {
        eprintln!(
            "kperf: {} PMU events requested but only {} configurable counters — dropping the rest",
            events.len(),
            n_config
        );
    }
    for (slot, ev) in configs.iter_mut().zip(events.iter()) {
        *slot = *ev;
    }
    configs
}

/// Program kpc for `cfg` and start counting. Returns the number of counters that
/// will appear on each on-CPU sample (fixed + configurable), which the decoder
/// needs to size each PERF_KPC_DATA batch.
fn configure_kpc(cfg: &KpcConfig) -> Result<u32, String> {
    let mut classes = KPC_CLASS_FIXED_MASK;
    if !cfg.events.is_empty() {
        let n_config = kpc_query_count(b"kpc.config_count\0", KPC_CLASS_CONFIGURABLE_MASK);
        if n_config == 0 {
            return Err("kpc reports no configurable counters".into());
        }
        let configs = kpc_config_words(&cfg.events, n_config);
        kpc_set_config(KPC_CLASS_CONFIGURABLE_MASK, &configs).map_err(|e| format!("kpc.config failed (errno {e})"))?;
        classes |= KPC_CLASS_CONFIGURABLE_MASK;
    }
    kpc_set_counting(classes).map_err(|e| format!("kpc.counting failed (errno {e})"))?;
    Ok(kpc_query_count(b"kpc.counter_count\0", classes))
}

/// Stop kpc counting (idempotent; ignores errors). Paired with [`disarm`].
fn kpc_disarm() {
    let _ = kpc_set_counting(0);
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
    /// On-CPU PMU counters to attach to each timer sample (requires on-CPU).
    pub pmu: Option<KpcConfig>,
}

/// Configure kperf for `cfg` and start sampling. Assumes the kdebug ring is
/// already up and keeps DBG_PERF (the sample events land there). Sets every
/// requested action, the lazy/timer triggers, programs kpc if PMU counters are
/// requested, then flips `sampling=1` as the final step. Returns the number of
/// PMU counters that will ride each on-CPU sample (0 if no PMU). Callers pair
/// this with [`disarm`].
pub(crate) fn arm(cfg: &KperfConfig) -> Result<u32, String> {
    let step = |r: Result<(), i32>, what: &str| r.map_err(|e| format!("{what} failed (errno {e})"));
    // PMU rides the on-CPU timer action; ignore it if on-CPU isn't enabled.
    let pmu = cfg.oncpu_period_ns.and(cfg.pmu.as_ref());

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
    let configure = |id: u64, kernel: bool, pmc: bool| -> Result<(), String> {
        let mut samplers = SAMPLER_USTACK | SAMPLER_TH_INFO;
        if kernel {
            samplers |= SAMPLER_KSTACK;
        }
        if pmc {
            samplers |= SAMPLER_PMC_CPU;
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
        configure(id, false, false)?;
    }
    if let Some(id) = oncpu_id {
        configure(id, true, pmu.is_some())?;
    }

    // Program kpc before starting sampling; capture the per-sample counter count.
    let counter_count = match pmu {
        Some(kpc) => configure_kpc(kpc)?,
        None => 0,
    };

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
    Ok(counter_count)
}

/// Stop kperf sampling + kpc counting and clear state (idempotent; ignores errors).
pub(crate) fn disarm() {
    let _ = set_u32(b"kperf.sampling\0", 0);
    let _ = set_u32(b"kperf.reset\0", 1);
    kpc_disarm();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_words_pad_and_truncate() {
        // Fewer events than counters -> zero-padded (unused counters disabled).
        assert_eq!(kpc_config_words(&[0x02], 3), vec![0x02, 0, 0]);
        // Exactly filled.
        assert_eq!(kpc_config_words(&[0x02, 0x8c], 2), vec![0x02, 0x8c]);
        // More events than counters -> extras dropped.
        assert_eq!(kpc_config_words(&[1, 2, 3], 2), vec![1, 2]);
        // No configurable counters -> empty array.
        assert!(kpc_config_words(&[1, 2], 0).is_empty());
    }
}
