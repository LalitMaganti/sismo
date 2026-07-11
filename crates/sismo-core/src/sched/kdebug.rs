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

use std::os::raw::c_void;

// sys/sysctl.h
const CTL_KERN: i32 = 1;
const KERN_KDEBUG: i32 = 24;
// sys/kdebug.h KERN_KD* subcommands
const KERN_KDENABLE: i32 = 3;
const KERN_KDSETBUF: i32 = 4;
const KERN_KDSETUP: i32 = 6;
const KERN_KDREMOVE: i32 = 7;
const KERN_KDSETREG: i32 = 8;
const KERN_KDREADTR: i32 = 10;
const KERN_KDREADCURTHRMAP: i32 = 21;
// DBG_MACH / DBG_MACH_SCHED class+subclass filter, KDBG_SUBCLSTYPE reg type.
const DBG_MACH: u32 = 1;
const DBG_MACH_SCHED: u32 = 0x40;
const KDBG_SUBCLSTYPE: u32 = 0x0002_0000;

const KD_THREADMAP_ENTRY_SIZE: usize = 32; // sizeof(kd_threadmap): u64 + i32 + [20]u8, 8-aligned

/// Why [`kdebug_start`] failed.
pub enum StartError {
    /// KDSETBUF or KDSETUP failed.
    Setup,
    /// KDSETREG (the DBG_MACH_SCHED filter) failed.
    SetReg,
    /// KDENABLE failed.
    Enable,
}

extern "C" {
    fn sysctl(
        name: *const i32,
        namelen: u32,
        oldp: *mut c_void,
        oldlenp: *mut usize,
        newp: *const c_void,
        newlen: usize,
    ) -> i32;
}

#[repr(C)]
struct KdRegType {
    reg_type: u32,
    value1: u32,
    value2: u32,
    value3: u32,
    value4: u32,
}

unsafe fn sysctl_void(cmd: i32) -> i32 {
    let mib = [CTL_KERN, KERN_KDEBUG, cmd];
    unsafe {
        sysctl(mib.as_ptr(), mib.len() as u32, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null(), 0)
    }
}

unsafe fn sysctl_set_int(cmd: i32, value: i32) -> i32 {
    let mib = [CTL_KERN, KERN_KDEBUG, cmd, value];
    unsafe {
        sysctl(mib.as_ptr(), mib.len() as u32, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null(), 0)
    }
}

/// Tear down any prior session, size the buffer, install the DBG_MACH_SCHED
/// filter, and enable capture. Calls the KERN_KDEBUG sysctls, which need root
/// (they return EPERM otherwise).
pub fn kdebug_start(buffer_events: i32) -> Result<(), StartError> {
    unsafe {
        let _ = sysctl_void(KERN_KDREMOVE); // idempotent teardown
        if sysctl_set_int(KERN_KDSETBUF, buffer_events) < 0 {
            return Err(StartError::Setup);
        }
        if sysctl_void(KERN_KDSETUP) < 0 {
            return Err(StartError::Setup);
        }
        let mut reg = KdRegType {
            reg_type: KDBG_SUBCLSTYPE,
            value1: DBG_MACH,
            value2: DBG_MACH_SCHED,
            value3: 0,
            value4: 0,
        };
        let mib = [CTL_KERN, KERN_KDEBUG, KERN_KDSETREG];
        let mut len = std::mem::size_of::<KdRegType>();
        if sysctl(
            mib.as_ptr(),
            mib.len() as u32,
            &mut reg as *mut KdRegType as *mut c_void,
            &mut len,
            std::ptr::null(),
            0,
        ) < 0
        {
            let _ = sysctl_void(KERN_KDREMOVE);
            return Err(StartError::SetReg);
        }
        if sysctl_set_int(KERN_KDENABLE, 1) < 0 {
            let _ = sysctl_void(KERN_KDREMOVE);
            return Err(StartError::Enable);
        }
        Ok(())
    }
}

/// Drain the kernel ring into `out` (a buffer of 64-byte kd_bufs) WITHOUT
/// stopping capture. Returns the event count, or `None` on sysctl failure.
pub fn kdebug_drain(out: &mut [u8]) -> Option<usize> {
    let mib = [CTL_KERN, KERN_KDEBUG, KERN_KDREADTR];
    let mut len = out.len();
    let rc = unsafe {
        sysctl(mib.as_ptr(), mib.len() as u32, out.as_mut_ptr() as *mut c_void, &mut len, std::ptr::null(), 0)
    };
    if rc < 0 {
        return None;
    }
    // KDREADTR overwrites len with the event *count*, not the byte count.
    Some(len)
}

/// Read the current thread map (KERN_KDREADCURTHRMAP) into `out`. Returns the
/// entry count, or `None` on sysctl failure.
pub fn kdebug_read_thread_map(out: &mut [u8]) -> Option<usize> {
    let mib = [CTL_KERN, KERN_KDEBUG, KERN_KDREADCURTHRMAP];
    let mut len = out.len();
    let rc = unsafe {
        sysctl(mib.as_ptr(), mib.len() as u32, out.as_mut_ptr() as *mut c_void, &mut len, std::ptr::null(), 0)
    };
    if rc < 0 {
        return None;
    }
    Some(len / KD_THREADMAP_ENTRY_SIZE)
}

/// Tear down the kdebug session (frees the kernel buffers).
pub fn kdebug_teardown() {
    unsafe {
        let _ = sysctl_void(KERN_KDREMOVE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_without_root_fails_cleanly() {
        // cargo test runs unprivileged, so the KERN_KDEBUG sysctls return EPERM.
        // We just need the call path to not crash and to report failure.
        assert!(kdebug_start(1000).is_err(), "kdebug start should fail without root");
        kdebug_teardown(); // must be a harmless no-op
    }

    #[test]
    fn drain_without_session_reports_cleanly() {
        let mut buf = [0u8; 4 * 64]; // room for 4 kd_bufs
        // No active session (and unprivileged) → sysctl fails → None; must not crash.
        let n = kdebug_drain(&mut buf);
        assert!(n.is_none() || n.unwrap() <= 4);
    }
}
