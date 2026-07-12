// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! macOS kdebug ring control: the `KERN_KDEBUG` sysctl calls that configure,
//! drain, and tear down the kernel's `DBG_MACH_SCHED` trace stream. Requires
//! root (the sysctls return EPERM otherwise).
//!
//! Only the sysctl syscalls live here; the wire struct layouts (KdBuf,
//! KdThreadMap) and sched-event decoding live in the sched capture worker —
//! this module reads raw bytes into caller buffers.
//!
//! Constants are taken from the macOS SDK headers (sys/sysctl.h, sys/kdebug.h)
//! — stable kernel ABI. macOS-only; gated in lib.rs.

use libc::c_void;

// sys/sysctl.h
const CTL_KERN: i32 = 1;
const KERN_KDEBUG: i32 = 24;
// sys/kdebug.h KERN_KD* subcommands
const KERN_KDENABLE: i32 = 3;
const KERN_KDSETBUF: i32 = 4;
const KERN_KDSETUP: i32 = 6;
const KERN_KDREMOVE: i32 = 7;
const KERN_KDREADTR: i32 = 10;
const KERN_KDREADCURTHRMAP: i32 = 21;
// KERN_KDSET_TYPEFILTER (=22, macOS SDK sys/sysctl.h): install a per-(class,
// subclass) bitmap filter. The old KDSETREG class/subclass-range reg empties the
// ring on xnu-12377 for a *class* range; the typefilter is what this kernel
// honors and it lets us keep DBG_MACH_SCHED and DBG_PERF at once (one ring for
// both sched events and kperf off-CPU samples).
const KERN_KDSET_TYPEFILTER: i32 = 22;
const TYPEFILTER_BITMAP_SIZE: usize = (256 * 256) / 8; // 8192; indexed by csc=(class<<8)|subclass

const KD_THREADMAP_ENTRY_SIZE: usize = 32; // sizeof(kd_threadmap): u64 + i32 + [20]u8, 8-aligned

/// Why [`KdebugRing::open`] failed.
pub enum StartError {
    /// KDSETBUF or KDSETUP failed.
    Setup,
    /// KDSET_TYPEFILTER (the class/subclass filter) failed.
    SetReg,
    /// KDENABLE failed.
    Enable,
}

/// Install a typefilter keeping exactly the given inclusive `csc` ranges, where
/// `csc = (class << 8) | subclass`. Each feature that consumes the ring
/// contributes its own range(s); the union is what lands in the ring. Returns
/// false on sysctl failure. The 8192-byte bitmap is passed via oldp+oldlenp,
/// like the other kdebug write commands.
fn install_typefilter(csc_ranges: &[(u16, u16)]) -> bool {
    let mut bitmap = vec![0u8; TYPEFILTER_BITMAP_SIZE];
    for &(lo, hi) in csc_ranges {
        for csc in lo..=hi {
            let i = csc as usize;
            bitmap[i >> 3] |= 1 << (i & 7);
        }
    }
    let mut mib = [CTL_KERN, KERN_KDEBUG, KERN_KDSET_TYPEFILTER];
    let mut len = bitmap.len();
    unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            bitmap.as_mut_ptr() as *mut c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        ) == 0
    }
}

unsafe fn sysctl_void(cmd: i32) -> i32 {
    let mut mib = [CTL_KERN, KERN_KDEBUG, cmd];
    unsafe {
        libc::sysctl(mib.as_mut_ptr(), mib.len() as u32, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), 0)
    }
}

unsafe fn sysctl_set_int(cmd: i32, value: i32) -> i32 {
    let mut mib = [CTL_KERN, KERN_KDEBUG, cmd, value];
    unsafe {
        libc::sysctl(mib.as_mut_ptr(), mib.len() as u32, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), 0)
    }
}

/// A handle to the single kdebug ring session. `open` installs a typefilter (the
/// union of the callers' csc ranges) and enables capture; dropping it tears the
/// session down. The ring is a machine-global singleton — one owner at a time —
/// so features that want kdebug events don't each own it; they share this one
/// facility and contribute their csc range to its filter.
pub struct KdebugRing {
    _private: (),
}

impl KdebugRing {
    /// Tear down any prior session, size the buffer, install the typefilter for
    /// `csc_ranges` (inclusive (class<<8)|subclass values — each consumer's
    /// contribution; the union is captured), and enable. Calls the KERN_KDEBUG
    /// sysctls, which need root (EPERM otherwise).
    pub fn open(buffer_events: i32, csc_ranges: &[(u16, u16)]) -> Result<KdebugRing, StartError> {
        unsafe {
            let _ = sysctl_void(KERN_KDREMOVE); // idempotent teardown of any prior session
            if sysctl_set_int(KERN_KDSETBUF, buffer_events) < 0 {
                return Err(StartError::Setup);
            }
            if sysctl_void(KERN_KDSETUP) < 0 {
                return Err(StartError::Setup);
            }
            if !install_typefilter(csc_ranges) {
                let _ = sysctl_void(KERN_KDREMOVE);
                return Err(StartError::SetReg);
            }
            if sysctl_set_int(KERN_KDENABLE, 1) < 0 {
                let _ = sysctl_void(KERN_KDREMOVE);
                return Err(StartError::Enable);
            }
        }
        Ok(KdebugRing { _private: () })
    }

    /// Drain the ring into `out` (a buffer of 64-byte kd_bufs) WITHOUT stopping
    /// capture. Returns the event count, or `None` on sysctl failure.
    pub fn drain(&self, out: &mut [u8]) -> Option<usize> {
        let mut mib = [CTL_KERN, KERN_KDEBUG, KERN_KDREADTR];
        let mut len = out.len();
        let rc = unsafe {
            libc::sysctl(mib.as_mut_ptr(), mib.len() as u32, out.as_mut_ptr() as *mut c_void, &mut len, std::ptr::null_mut(), 0)
        };
        if rc < 0 {
            return None;
        }
        // KDREADTR overwrites len with the event *count*, not the byte count.
        Some(len)
    }

    /// Read the current thread map (KERN_KDREADCURTHRMAP) into `out`. Returns the
    /// entry count, or `None` on sysctl failure.
    pub fn read_thread_map(&self, out: &mut [u8]) -> Option<usize> {
        let mut mib = [CTL_KERN, KERN_KDEBUG, KERN_KDREADCURTHRMAP];
        let mut len = out.len();
        let rc = unsafe {
            libc::sysctl(mib.as_mut_ptr(), mib.len() as u32, out.as_mut_ptr() as *mut c_void, &mut len, std::ptr::null_mut(), 0)
        };
        if rc < 0 {
            return None;
        }
        Some(len / KD_THREADMAP_ENTRY_SIZE)
    }
}

impl Drop for KdebugRing {
    /// Tear down the kdebug session (frees the kernel buffers).
    fn drop(&mut self) {
        unsafe {
            let _ = sysctl_void(KERN_KDREMOVE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_without_root_fails_cleanly() {
        // cargo test runs unprivileged, so the KERN_KDEBUG sysctls return EPERM.
        // The call path must not crash and must report failure (no ring handed back).
        assert!(
            KdebugRing::open(1000, &[(0x0140, 0x0140)]).is_err(),
            "kdebug open should fail without root"
        );
    }
}
