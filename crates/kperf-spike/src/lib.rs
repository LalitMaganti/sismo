// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! kperf off-CPU-stack spike.
//!
//! Configures Apple's private kperf sampling engine in **PET** mode (Profile
//! Every Thread — the kernel walks every thread each tick, blocked ones
//! included) filtered to one pid, then drains the resulting samples from the
//! SAME `KERN_KDEBUG` ring sismo's sched capture already reads, and reassembles
//! per-thread user call stacks. For the target pid it symbolizes the captured
//! stacks with `atos` (a spike convenience); folding into `macos_sched_capture`
//! and offline symbolization come later.
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
const KERN_KDREADTR: i32 = 10;
// Modern per-(class,subclass) bitmap filter. Command number + bitmap size taken
// from the macOS 26.2 SDK (sys/sysctl.h: KERN_KDSET_TYPEFILTER=22; sys/
// kdebug_private.h: KDBG_TYPEFILTER_BITMAP_SIZE=(256*256)/8). This is what this
// xnu actually honors — the old KDSETREG class-range empties the ring.
const KERN_KDSET_TYPEFILTER: i32 = 22;
const TYPEFILTER_BITMAP_SIZE: usize = (256 * 256) / 8; // 8192

// ---- kperf sample events in the kdebug stream (osfmk/kperf/buffer.h) --------

// Debug class kperf emits under: PERF_CODE(sc, c) = KDBG_CODE(DBG_PERF, sc, c).
const DBG_PERF: u32 = 0x25;
// PERF_THREADINFO (subclass 1) carries the *sampled* thread's pid+tid. Under PET
// every event is emitted by the single PET sampler thread, so the kd_buf's own
// thread-id field (arg5) is that sampler, NOT the sampled thread — we must demux
// callstacks by the tid reported in the preceding THREADINFO event instead.
const PERF_THREADINFO: u32 = 1;
// THREADINFO codes: PERF_TI_SAMPLE=0 (start marker), PERF_TI_DATA=1 (payload:
// pid, tid, dq_addr, runmode). The DATA event is the one carrying the ids.
const PERF_TI_DATA: u32 = 1;
// Subclass we decode.
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

/// Read back a scalar `kperf.*` knob (u32) for diagnostics. Returns None on error.
fn kperf_get_u32(name: &[u8]) -> Option<u32> {
    let mut val: u32 = 0;
    let mut len = std::mem::size_of::<u32>();
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr() as *const libc::c_char,
            &mut val as *mut u32 as *mut c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc == 0 { Some(val) } else { None }
}

/// Read back a `kperf.*` knob as u64 for diagnostics. Returns None on error.
fn kperf_get_u64(name: &[u8]) -> Option<u64> {
    let mut val: u64 = 0;
    let mut len = std::mem::size_of::<u64>();
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr() as *const libc::c_char,
            &mut val as *mut u64 as *mut c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc == 0 { Some(val) } else { None }
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

/// Install a typefilter bitmap that keeps only class `class_id` (all subclasses).
/// The bitmap is indexed by csc = (class<<8)|subclass (SDK: KDBG_CSC_*); we set
/// the 256 contiguous bits for the class. Passed via oldp+oldlenp like the other
/// kdebug write commands. Setting a typefilter enables KDBG_TYPEFILTER_CHECK, so
/// only matching (class,subclass) events land in the ring.
fn kdebug_set_class_typefilter(class_id: u32) -> Result<(), i32> {
    let mut bitmap = vec![0u8; TYPEFILTER_BITMAP_SIZE];
    let base = (class_id as usize) << 8; // csc of subclass 0
    for csc in base..base + 256 {
        bitmap[csc >> 3] |= 1 << (csc & 7);
    }
    let mut mib = [CTL_KERN, KERN_KDEBUG, KERN_KDSET_TYPEFILTER];
    let mut len = bitmap.len();
    let rc = unsafe {
        libc::sysctl(mib.as_mut_ptr(), mib.len() as u32, bitmap.as_mut_ptr() as *mut c_void, &mut len, std::ptr::null_mut(), 0)
    };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

/// Size the kdebug buffer and (optionally) keep only the DBG_PERF class via a
/// typefilter, then enable. When `filter` is false we capture *all* classes —
/// used for diagnosis, to see what kperf emits into the ring and under what class.
fn kdebug_start(buffer_events: i32, filter: bool) -> Result<(), String> {
    unsafe {
        let _ = kd_void(KERN_KDREMOVE);
        if kd_set_int(KERN_KDSETBUF, buffer_events) < 0 {
            return Err(format!("KDSETBUF failed (errno {})", errno()));
        }
        if kd_void(KERN_KDSETUP) < 0 {
            return Err(format!("KDSETUP failed (errno {})", errno()));
        }
        if filter {
            // The old KDSETREG class-range empties the ring on this xnu; the
            // per-(class,subclass) typefilter is what it honors. Keep DBG_PERF.
            if let Err(e) = kdebug_set_class_typefilter(DBG_PERF) {
                let _ = kd_void(KERN_KDREMOVE);
                return Err(format!("KDSET_TYPEFILTER(DBG_PERF) failed (errno {e})"));
            }
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
    pub pid: u64,
    pub tid: u64,
    pub frames: Vec<u64>,
}

/// Decoder state for one kperf/kdebug stream. Because PET serializes all events
/// through one sampler thread, we track the "current" sampled thread from the
/// latest THREADINFO event and attribute the callstack that follows to it.
#[derive(Default)]
struct Decoder {
    /// Callstack being reassembled for the current thread.
    pending: Option<Pending>,
    /// pid + tid from the most recent THREADINFO DATA event.
    cur_pid: u64,
    cur_tid: u64,
    /// Bounded dump of raw THREADINFO events (for empirical arg-layout checking).
    ti_dump_left: u32,
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

impl Decoder {
    /// Feed one drained kd_buf; returns a completed sample when a user stack closes.
    fn on_event(&mut self, e: &KdBuf) -> Option<StackSample> {
        if class_of(e.debugid) != DBG_PERF {
            return None;
        }
        match (subclass_of(e.debugid), code_of(e.debugid)) {
            // THREADINFO DATA: BUF_DATA(PERF_TI_DATA, pid, tid, dq_addr, runmode).
            // Marks which thread the *following* callstack events belong to.
            (PERF_THREADINFO, PERF_TI_DATA) => {
                if self.ti_dump_left > 0 {
                    self.ti_dump_left -= 1;
                    eprintln!(
                        "kperf-spike:   TI_DATA arg1(pid?)={} arg2(tid?)={} arg3=0x{:x} arg4=0x{:x}  kd_arg5(sampler_tid)={}",
                        e.arg1, e.arg2, e.arg3, e.arg4, e.arg5
                    );
                }
                // arg1 = pid, arg2 = sampled tid (confirmed empirically via dump).
                self.cur_pid = e.arg1;
                self.cur_tid = e.arg2;
                None
            }
            (PERF_CALLSTACK, PERF_CS_UHDR) => {
                // BUF_DATA(UHDR, flags, nframes, ...): arg2 = nframes.
                let want = e.arg2 as usize;
                self.pending = Some(Pending { want, frames: Vec::with_capacity(want) });
                None
            }
            (PERF_CALLSTACK, PERF_CS_UDATA) => {
                let (pid, tid) = (self.cur_pid, self.cur_tid);
                let p = self.pending.as_mut()?;
                for pc in [e.arg1, e.arg2, e.arg3, e.arg4] {
                    if p.frames.len() < p.want {
                        p.frames.push(pc);
                    }
                }
                if p.frames.len() >= p.want {
                    let done = self.pending.take().unwrap();
                    return Some(StackSample { pid, tid, frames: done.frames });
                }
                None
            }
            // Kernel frames (PERF_CS_KHDR / PERF_CS_KDATA) are captured too but the
            // spike prints user stacks only.
            _ => None,
        }
    }
}

/// Run the spike: sample `pid` for `secs` seconds and print reassembled user
/// stacks. Returns the number of completed samples.
pub fn run(pid: i32, secs: u64, period_ns: u64) -> Result<usize, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("must run as root (kperf/kdebug sysctls need it)".into());
    }
    // In-kernel DBG_PERF class filter is ON by default via a kdebug typefilter
    // (KERN_KDSET_TYPEFILTER) — the old KDSETREG class-range empties the ring on
    // this xnu, so we use the per-(class,subclass) bitmap the kernel honors. This
    // is what lets kperf coexist with DBG_MACH_SCHED on the one unified ring.
    // Set KPERF_SPIKE_CAPTURE_ALL=1 to disable it and histogram every class.
    let use_kernel_filter = std::env::var("KPERF_SPIKE_CAPTURE_ALL").is_err();

    // ~500k events of ring headroom.
    kdebug_start(500_000, use_kernel_filter)?;
    eprintln!(
        "kperf-spike: kernel class typefilter (DBG_PERF only): {}",
        if use_kernel_filter { "ON" } else { "OFF (capture all)" }
    );
    if let Err(e) = kperf_pet_start(pid, period_ns) {
        kdebug_teardown();
        return Err(e);
    }
    eprintln!("kperf-spike: sampling pid {pid} every {period_ns}ns via PET for {secs}s…");

    // Read the knobs back to confirm they actually took effect.
    eprintln!(
        "kperf-spike: readback sampling={:?} timer.count={:?} action.count={:?} pet_timer={:?} timer.period_min_pet_ns={:?}",
        kperf_get_u32(b"kperf.sampling\0"),
        kperf_get_u32(b"kperf.timer.count\0"),
        kperf_get_u32(b"kperf.action.count\0"),
        kperf_get_u32(b"kperf.timer.pet_timer\0"),
        kperf_get_u64(b"kperf.limits.timer_min_pet_period_ns\0"),
    );
    eprintln!(
        "kperf-spike: ns_to_ticks({period_ns})={} mach ticks",
        ns_to_ticks(period_ns)
    );

    // Ring-content histograms: which classes/codes actually land in the ring —
    // motivates the Phase-B kernel-side filter (DBG_PERF is ~half the traffic).
    let mut class_hist: std::collections::HashMap<u32, u64> = std::collections::HashMap::new();
    let mut perf_hist: std::collections::HashMap<(u32, u32), u64> = std::collections::HashMap::new();
    let mut total_events: u64 = 0;

    // TI arg layout (arg1=pid, arg2=tid) is confirmed; set >0 to re-dump.
    let mut decoder = Decoder { ti_dump_left: 0, ..Default::default() };
    let mut buf = vec![
        KdBuf { timestamp: 0, arg1: 0, arg2: 0, arg3: 0, arg4: 0, arg5: 0, debugid: 0, cpuid: 0, unused: 0 };
        100_000
    ];
    let mut total = 0usize;
    // The kernel filter_by_pid knob is currently ineffective on this xnu (we get
    // system-wide PET samples), so filter to the target pid in userspace using
    // the pid reported in each THREADINFO event. Count distinct pids/tids seen
    // for context, but the per-thread summary is TARGET-ONLY.
    let target_pid = pid as u64;
    let mut distinct_pids: std::collections::HashSet<u64> = std::collections::HashSet::new();
    // Per (target) tid: (sample count, most recent stack).
    let mut per_tid: std::collections::HashMap<u64, (u64, Vec<u64>)> = std::collections::HashMap::new();
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
            total_events += 1;
            *class_hist.entry(class_of(e.debugid)).or_default() += 1;
            if class_of(e.debugid) == DBG_PERF {
                *perf_hist.entry((subclass_of(e.debugid), code_of(e.debugid))).or_default() += 1;
            }
            if let Some(s) = decoder.on_event(e) {
                total += 1;
                distinct_pids.insert(s.pid);
                if s.pid != target_pid {
                    continue;
                }
                let entry = per_tid.entry(s.tid).or_insert((0, Vec::new()));
                entry.0 += 1;
                entry.1 = s.frames;
            }
        }
    }

    kperf_stop();
    kdebug_teardown();

    eprintln!("kperf-spike: drained {total_events} total kdebug events");
    let mut classes: Vec<_> = class_hist.into_iter().collect();
    classes.sort_by_key(|&(_, c)| std::cmp::Reverse(c));
    for (cls, cnt) in classes.iter().take(20) {
        eprintln!("kperf-spike:   class 0x{cls:02x}: {cnt}");
    }
    if !perf_hist.is_empty() {
        let mut perfs: Vec<_> = perf_hist.into_iter().collect();
        perfs.sort_by_key(|&(_, c)| std::cmp::Reverse(c));
        for ((sub, code), cnt) in perfs.iter() {
            eprintln!("kperf-spike:   DBG_PERF subclass={sub} code={code}: {cnt}");
        }
    }
    eprintln!(
        "kperf-spike: {} distinct pid(s) sampled system-wide (kernel filter_by_pid ineffective)",
        distinct_pids.len()
    );
    // Per-thread summary for the TARGET pid only (userspace-filtered). The
    // target is still alive here (the caller kills it afterwards), so symbolize
    // each representative stack with atos to name the block site.
    eprintln!("kperf-spike: target pid {target_pid}: {} distinct tid(s):", per_tid.len());
    let mut tids: Vec<_> = per_tid.into_iter().collect();
    tids.sort_by_key(|&(_, (c, _))| std::cmp::Reverse(c));
    for (tid, (count, frames)) in tids.iter() {
        let repr: Vec<String> = frames.iter().take(16).map(|pc| format!("0x{pc:x}")).collect();
        eprintln!("kperf-spike:   tid {tid} x{count}  {} frames: {}", frames.len(), repr.join(" "));
        for (i, line) in symbolize(pid, frames).iter().enumerate() {
            eprintln!("kperf-spike:       {i:>2}  {line}");
        }
    }
    Ok(total)
}

/// Symbolize a user stack against a still-live target via `atos -p <pid>`.
/// Returns one line per frame (falls back to raw hex on any failure). This is a
/// spike convenience — the real path will symbolize offline from the dyld
/// shared cache + on-disk binaries, not by shelling out.
fn symbolize(pid: i32, frames: &[u64]) -> Vec<String> {
    let frames: Vec<&u64> = frames.iter().filter(|&&pc| pc != 0).collect();
    if frames.is_empty() {
        return Vec::new();
    }
    let mut cmd = std::process::Command::new("/usr/bin/atos");
    cmd.arg("-p").arg(pid.to_string());
    for pc in &frames {
        cmd.arg(format!("0x{pc:x}"));
    }
    match cmd.output() {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.to_string())
            .collect(),
        _ => frames.iter().map(|pc| format!("0x{pc:x} (atos failed)")).collect(),
    }
}

#[allow(dead_code)]
fn print_sample(s: &StackSample) {
    print!("pid {} tid {:>8}  {} frames:", s.pid, s.tid, s.frames.len());
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

    fn mk(sub: u32, code: u32, a1: u64, a2: u64, a3: u64, a4: u64) -> KdBuf {
        KdBuf {
            timestamp: 0,
            arg1: a1,
            arg2: a2,
            arg3: a3,
            arg4: a4,
            arg5: 999, // sampler tid — deliberately NOT the sampled tid under PET
            debugid: (DBG_PERF << 24) | (sub << 16) | (code << 2),
            cpuid: 0,
            unused: 0,
        }
    }

    #[test]
    fn reassembles_a_user_stack_keyed_on_threadinfo() {
        let mut d = Decoder::default();
        // THREADINFO DATA: pid=1234, tid=42 — sets the sampled thread.
        assert!(d.on_event(&mk(PERF_THREADINFO, PERF_TI_DATA, 1234, 42, 0, 0)).is_none());
        // UHDR: flags=0, nframes=5.
        assert!(d.on_event(&mk(PERF_CALLSTACK, PERF_CS_UHDR, 0, 5, 0, 0)).is_none());
        // UDATA: 4 frames.
        assert!(d.on_event(&mk(PERF_CALLSTACK, PERF_CS_UDATA, 0x1000, 0x2000, 0x3000, 0x4000)).is_none());
        // UDATA: 1 more (of a batch of 4) completes 5.
        let s = d.on_event(&mk(PERF_CALLSTACK, PERF_CS_UDATA, 0x5000, 0xdead, 0xdead, 0xdead)).unwrap();
        // tid comes from THREADINFO, not the kd_buf's arg5 (999).
        assert_eq!(s.tid, 42);
        assert_eq!(s.frames, vec![0x1000, 0x2000, 0x3000, 0x4000, 0x5000]);
    }

    #[test]
    fn two_threads_do_not_bleed_into_one_stack() {
        let mut d = Decoder::default();
        // Thread A.
        d.on_event(&mk(PERF_THREADINFO, PERF_TI_DATA, 1, 10, 0, 0));
        d.on_event(&mk(PERF_CALLSTACK, PERF_CS_UHDR, 0, 2, 0, 0));
        let a = d.on_event(&mk(PERF_CALLSTACK, PERF_CS_UDATA, 0xa0, 0xa1, 0, 0)).unwrap();
        assert_eq!((a.tid, a.frames), (10, vec![0xa0, 0xa1]));
        // Thread B, right after — must not inherit A's frames.
        d.on_event(&mk(PERF_THREADINFO, PERF_TI_DATA, 1, 20, 0, 0));
        d.on_event(&mk(PERF_CALLSTACK, PERF_CS_UHDR, 0, 1, 0, 0));
        let b = d.on_event(&mk(PERF_CALLSTACK, PERF_CS_UDATA, 0xb0, 0, 0, 0)).unwrap();
        assert_eq!((b.tid, b.frames), (20, vec![0xb0]));
    }
}
