// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! kperf off-CPU-stack spike.
//!
//! Configures Apple's private kperf sampling engine in **PET** mode (Profile
//! Every Thread — the kernel walks every thread each tick, blocked ones
//! included) filtered to one pid, then drains the resulting samples from the
//! SAME `KERN_KDEBUG` ring sismo's sched capture already reads, and reassembles
//! per-thread user call stacks. It prints raw frame PCs — symbolization and
//! folding into `macos_sched_capture` come later.
//!
//! Every constant below is taken from published xnu sources (osfmk/kperf/*),
//! cited inline. The only "private" part is the userspace CoreProfile wrapper,
//! which we bypass by driving the `kperf.*` sysctls directly.
//!
//! Must run as root (the kperf + kdebug sysctls return EPERM otherwise).

#![cfg(target_os = "macos")]

use std::ffi::c_void;
use std::time::{Duration, Instant};

// ---- KERN_KDEBUG sysctl (numeric MIB) — same interface as sismo's kdebug.rs --

const CTL_KERN: i32 = 1;
const KERN_KDEBUG: i32 = 24;
const KERN_KDENABLE: i32 = 3;
const KERN_KDSETBUF: i32 = 4;
const KERN_KDSETUP: i32 = 6;
const KERN_KDREMOVE: i32 = 7;
const KERN_KDSETREG: i32 = 8;
const KERN_KDREADTR: i32 = 10;

// KDBG_CLASSTYPE keeps a whole debug CLASS (vs sismo's KDBG_SUBCLSTYPE). We keep
// the DBG_PERF class so only kperf's sample events land in the ring.
const KDBG_CLASSTYPE: u32 = 0x0001_0000;

// ---- kperf sample events in the kdebug stream (osfmk/kperf/buffer.h) --------

// Debug class kperf emits under: PERF_CODE(sc, c) = KDBG_CODE(DBG_PERF, sc, c).
const DBG_PERF: u32 = 0x25;
// Subclass we decode (PERF_THREADINFO=1 is emitted too, but each kd_buf's arg5
// already carries the sampled tid, so the spike keys on that).
const PERF_CALLSTACK: u32 = 2;
// PERF_CALLSTACK codes (user stacks; kernel KHDR=5/KDATA=3 are ignored here).
const PERF_CS_UDATA: u32 = 4;
const PERF_CS_UHDR: u32 = 6;

// ---- kperf samplers bitmask (osfmk/kperf/action.h) -------------------------

const SAMPLER_TH_INFO: u32 = 1 << 0; // 0x1
const SAMPLER_KSTACK: u32 = 1 << 2; // 0x4
const SAMPLER_USTACK: u32 = 1 << 3; // 0x8

// One action, 1-based (action id 0 means "no action").
const ACTION_ID: u64 = 1;
// One timer, id 0.
const TIMER_ID: u64 = 0;
const UCALLSTACK_DEPTH: u64 = 128;

// The 64-byte kd_buf KERN_KDREADTR returns (osfmk/../kdebug.h, LP64). arg5 is
// the emitting thread's tid.
#[repr(C)]
#[derive(Clone, Copy)]
struct KdBuf {
    timestamp: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64, // thread id
    debugid: u32,
    cpuid: u32,
    unused: u64,
}

extern "C" {
    fn mach_timebase_info(info: *mut MachTimebase) -> libc::c_int;
}

#[repr(C)]
struct MachTimebase {
    numer: u32,
    denom: u32,
}

// ---- kperf sysctl helpers --------------------------------------------------

/// Set a scalar `kperf.*` knob (CTLTYPE_INT — a single u32). `name` NUL-terminated.
fn kperf_set_u32(name: &[u8], value: u32) -> Result<(), i32> {
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr() as *const libc::c_char,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &value as *const u32 as *mut c_void,
            std::mem::size_of::<u32>(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

/// Set an indexed `kperf.*` knob. The kernel reads two u64s: `[id, value]`
/// (osfmk/kperf/kperfbsd.c: kperf_sysctl_get_set_unsigned_uint32 /
/// sysctl_timer_period).
fn kperf_set_indexed(name: &[u8], id: u64, value: u64) -> Result<(), i32> {
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
    if rc == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

fn errno() -> i32 {
    unsafe { *libc::__error() }
}

fn ns_to_ticks(ns: u64) -> u64 {
    let mut tb = MachTimebase { numer: 1, denom: 1 };
    unsafe { mach_timebase_info(&mut tb) };
    // ns = ticks * numer / denom  ->  ticks = ns * denom / numer.
    (ns as u128 * tb.denom as u128 / tb.numer as u128) as u64
}

// ---- kdebug ring (KERN_KDEBUG) ---------------------------------------------

unsafe fn kd_void(cmd: i32) -> i32 {
    let mut mib = [CTL_KERN, KERN_KDEBUG, cmd];
    libc::sysctl(mib.as_mut_ptr(), mib.len() as u32, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), 0)
}

unsafe fn kd_set_int(cmd: i32, value: i32) -> i32 {
    let mut mib = [CTL_KERN, KERN_KDEBUG, cmd, value];
    libc::sysctl(mib.as_mut_ptr(), mib.len() as u32, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), 0)
}

#[repr(C)]
struct KdRegType {
    reg_type: u32,
    value1: u32,
    value2: u32,
    value3: u32,
    value4: u32,
}

/// Size the kdebug buffer and keep only the DBG_PERF class, then enable.
fn kdebug_start(buffer_events: i32) -> Result<(), String> {
    unsafe {
        let _ = kd_void(KERN_KDREMOVE);
        if kd_set_int(KERN_KDSETBUF, buffer_events) < 0 {
            return Err(format!("KDSETBUF failed (errno {})", errno()));
        }
        if kd_void(KERN_KDSETUP) < 0 {
            return Err(format!("KDSETUP failed (errno {})", errno()));
        }
        let mut reg = KdRegType { reg_type: KDBG_CLASSTYPE, value1: DBG_PERF, value2: 0, value3: 0, value4: 0 };
        let mut mib = [CTL_KERN, KERN_KDEBUG, KERN_KDSETREG];
        let mut len = std::mem::size_of::<KdRegType>();
        if libc::sysctl(mib.as_mut_ptr(), mib.len() as u32, &mut reg as *mut KdRegType as *mut c_void, &mut len, std::ptr::null_mut(), 0) < 0 {
            let _ = kd_void(KERN_KDREMOVE);
            return Err(format!("KDSETREG(DBG_PERF) failed (errno {})", errno()));
        }
        if kd_set_int(KERN_KDENABLE, 1) < 0 {
            let _ = kd_void(KERN_KDREMOVE);
            return Err(format!("KDENABLE failed (errno {})", errno()));
        }
    }
    Ok(())
}

fn kdebug_drain(out: &mut [KdBuf]) -> Option<usize> {
    let mut mib = [CTL_KERN, KERN_KDEBUG, KERN_KDREADTR];
    let mut len = std::mem::size_of_val(out);
    let rc = unsafe {
        libc::sysctl(mib.as_mut_ptr(), mib.len() as u32, out.as_mut_ptr() as *mut c_void, &mut len, std::ptr::null_mut(), 0)
    };
    if rc < 0 {
        return None;
    }
    // KDREADTR overwrites len with the event *count*.
    Some(len)
}

fn kdebug_teardown() {
    unsafe {
        let _ = kd_void(KERN_KDREMOVE);
    }
}

// ---- kperf PET setup / teardown --------------------------------------------

fn kperf_pet_start(pid: i32, period_ns: u64) -> Result<(), String> {
    let step = |r: Result<(), i32>, what: &str| -> Result<(), String> {
        r.map_err(|e| format!("{what} failed (errno {e})"))
    };
    // Clean slate.
    step(kperf_set_u32(b"kperf.reset\0", 1), "kperf.reset")?;
    // One action capturing user + kernel stacks + thread info.
    step(kperf_set_u32(b"kperf.action.count\0", 1), "kperf.action.count")?;
    step(
        kperf_set_indexed(b"kperf.action.samplers\0", ACTION_ID, (SAMPLER_USTACK | SAMPLER_KSTACK | SAMPLER_TH_INFO) as u64),
        "kperf.action.samplers",
    )?;
    step(kperf_set_indexed(b"kperf.action.ucallstack_depth\0", ACTION_ID, UCALLSTACK_DEPTH), "kperf.action.ucallstack_depth")?;
    // Only the target process.
    step(kperf_set_indexed(b"kperf.action.filter_by_pid\0", ACTION_ID, pid as u64), "kperf.action.filter_by_pid")?;
    // One timer firing the action; period is in mach ticks.
    step(kperf_set_u32(b"kperf.timer.count\0", 1), "kperf.timer.count")?;
    step(kperf_set_indexed(b"kperf.timer.period\0", TIMER_ID, ns_to_ticks(period_ns)), "kperf.timer.period")?;
    step(kperf_set_indexed(b"kperf.timer.action\0", TIMER_ID, ACTION_ID), "kperf.timer.action")?;
    // Make it the PET timer: sample EVERY thread each tick, blocked included.
    step(kperf_set_u32(b"kperf.timer.pet_timer\0", TIMER_ID as u32), "kperf.timer.pet_timer")?;
    // Go.
    step(kperf_set_u32(b"kperf.sampling\0", 1), "kperf.sampling")?;
    Ok(())
}

fn kperf_stop() {
    let _ = kperf_set_u32(b"kperf.sampling\0", 0);
    let _ = kperf_set_u32(b"kperf.reset\0", 1);
}

// ---- decode ----------------------------------------------------------------

/// A user stack being reassembled for one thread across UHDR + UDATA events.
struct Pending {
    want: usize,
    frames: Vec<u64>,
}

/// A completed user-stack sample.
pub struct StackSample {
    pub tid: u64,
    pub frames: Vec<u64>,
}

fn class_of(debugid: u32) -> u32 {
    (debugid >> 24) & 0xff
}
fn subclass_of(debugid: u32) -> u32 {
    (debugid >> 16) & 0xff
}
fn code_of(debugid: u32) -> u32 {
    (debugid >> 2) & 0x3fff
}

/// Feed one drained kd_buf; returns a completed sample when a user stack closes.
fn on_event(pending: &mut std::collections::HashMap<u64, Pending>, e: &KdBuf) -> Option<StackSample> {
    if class_of(e.debugid) != DBG_PERF || subclass_of(e.debugid) != PERF_CALLSTACK {
        return None;
    }
    let tid = e.arg5;
    match code_of(e.debugid) {
        PERF_CS_UHDR => {
            // BUF_DATA(hdrid, flags, nframes, ...): arg2 = nframes.
            let want = e.arg2 as usize;
            pending.insert(tid, Pending { want, frames: Vec::with_capacity(want) });
            None
        }
        PERF_CS_UDATA => {
            let p = pending.get_mut(&tid)?;
            for pc in [e.arg1, e.arg2, e.arg3, e.arg4] {
                if p.frames.len() < p.want {
                    p.frames.push(pc);
                }
            }
            if p.frames.len() >= p.want {
                let done = pending.remove(&tid).unwrap();
                return Some(StackSample { tid, frames: done.frames });
            }
            None
        }
        // Kernel frames (PERF_CS_KHDR / PERF_CS_KDATA) are captured too but the
        // spike prints user stacks only.
        _ => None,
    }
}

/// Run the spike: sample `pid` for `secs` seconds and print reassembled user
/// stacks. Returns the number of completed samples.
pub fn run(pid: i32, secs: u64, period_ns: u64) -> Result<usize, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("must run as root (kperf/kdebug sysctls need it)".into());
    }
    // ~500k events of ring headroom.
    kdebug_start(500_000)?;
    if let Err(e) = kperf_pet_start(pid, period_ns) {
        kdebug_teardown();
        return Err(e);
    }
    eprintln!("kperf-spike: sampling pid {pid} every {period_ns}ns via PET for {secs}s…");

    let mut pending = std::collections::HashMap::new();
    let mut buf = vec![
        KdBuf { timestamp: 0, arg1: 0, arg2: 0, arg3: 0, arg4: 0, arg5: 0, debugid: 0, cpuid: 0, unused: 0 };
        100_000
    ];
    let mut total = 0usize;
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
        let n = match kdebug_drain(&mut buf) {
            Some(n) => n,
            None => {
                eprintln!("kperf-spike: KDREADTR failed (errno {})", errno());
                break;
            }
        };
        for e in &buf[..n] {
            if let Some(s) = on_event(&mut pending, e) {
                total += 1;
                print_sample(&s);
            }
        }
    }

    kperf_stop();
    kdebug_teardown();
    Ok(total)
}

fn print_sample(s: &StackSample) {
    print!("tid {:>8}  {} frames:", s.tid, s.frames.len());
    for (i, pc) in s.frames.iter().enumerate().take(12) {
        print!(" {i}=0x{pc:x}");
    }
    if s.frames.len() > 12 {
        print!(" …");
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debugid_fields_decode() {
        // PERF_CS_UHDR = KDBG_CODE(DBG_PERF, PERF_CALLSTACK, 6).
        let id = (DBG_PERF << 24) | (PERF_CALLSTACK << 16) | (PERF_CS_UHDR << 2);
        assert_eq!(class_of(id), DBG_PERF);
        assert_eq!(subclass_of(id), PERF_CALLSTACK);
        assert_eq!(code_of(id), PERF_CS_UHDR);
    }

    #[test]
    fn reassembles_a_user_stack() {
        let mut pending = std::collections::HashMap::new();
        let mk = |code: u32, a1: u64, a2: u64, a3: u64, a4: u64| KdBuf {
            timestamp: 0,
            arg1: a1,
            arg2: a2,
            arg3: a3,
            arg4: a4,
            arg5: 42, // tid
            debugid: (DBG_PERF << 24) | (PERF_CALLSTACK << 16) | (code << 2),
            cpuid: 0,
            unused: 0,
        };
        // UHDR: flags=0, nframes=5.
        assert!(on_event(&mut pending, &mk(PERF_CS_UHDR, 0, 5, 0, 0)).is_none());
        // UDATA: 4 frames.
        assert!(on_event(&mut pending, &mk(PERF_CS_UDATA, 0x1000, 0x2000, 0x3000, 0x4000)).is_none());
        // UDATA: 1 more (of a batch of 4) completes 5.
        let s = on_event(&mut pending, &mk(PERF_CS_UDATA, 0x5000, 0xdead, 0xdead, 0xdead)).unwrap();
        assert_eq!(s.tid, 42);
        assert_eq!(s.frames, vec![0x1000, 0x2000, 0x3000, 0x4000, 0x5000]);
    }
}
