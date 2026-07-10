// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! macOS libproc bindings (migrated from src/macos/process_tree.zig), used by
//! the sched producer to attach process / thread names to scheduler events.
//!
//! `proc_pidinfo` / `proc_pidpath` are libSystem symbols, so this links in the
//! final binary and in standalone `cargo test` — the tests below exercise the
//! bindings against the test process itself, no root required.
//!
//! macOS-only: gated in lib.rs (`proc_pidinfo` is a Darwin symbol).

use std::os::raw::c_void;

// proc_pidinfo flavors + their kernel-enforced buffer sizes (from
// <sys/proc_info.h>; proc_pidinfo returns the size on success, ENOMEM if the
// buffer size doesn't match the flavor's struct exactly).
const PROC_PIDTBSDINFO: i32 = 3;
const PROC_PIDTHREADID64INFO: i32 = 15;
const PROC_PIDTBSDINFO_SIZE: i32 = 136; // sizeof(struct proc_bsdinfo)
const PROC_PIDTHREADID64INFO_SIZE: i32 = 112; // sizeof(struct proc_threadinfo)

// Field offsets within those structs (only these are read).
const PBI_PPID_OFFSET: usize = 16; // proc_bsdinfo.pbi_ppid (u32)
const PTH_NAME_OFFSET: usize = 48; // proc_threadinfo.pth_name
const PTH_NAME_LEN: usize = 64; // MAXTHREADNAMESIZE

use libc::{proc_pidinfo, proc_pidpath};

/// Parent pid of `pid` via PROC_PIDTBSDINFO. Writes `*out_ppid` and returns
/// true on success; false on any proc_pidinfo failure (pid gone, etc.).
///
/// # Safety
/// `out_ppid` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_proc_parent_pid(pid: i32, out_ppid: *mut u32) -> bool {
    let mut buf = [0u8; PROC_PIDTBSDINFO_SIZE as usize];
    let rc = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            buf.as_mut_ptr() as *mut c_void,
            PROC_PIDTBSDINFO_SIZE,
        )
    };
    if rc != PROC_PIDTBSDINFO_SIZE {
        return false;
    }
    let ppid = u32::from_ne_bytes(buf[PBI_PPID_OFFSET..PBI_PPID_OFFSET + 4].try_into().unwrap());
    unsafe {
        *out_ppid = ppid;
    }
    true
}

/// Thread name (proc_threadinfo.pth_name) for xnu thread-id `tid` under `pid`.
/// Writes up to `cap` bytes into `out` (no NUL) and returns the length, or 0 if
/// the lookup fails or the thread is unnamed (kernel zero-fills pth_name).
///
/// # Safety
/// `out` must be writable for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_proc_thread_name(pid: i32, tid: u64, out: *mut u8, cap: usize) -> usize {
    let mut buf = [0u8; PROC_PIDTHREADID64INFO_SIZE as usize];
    let rc = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTHREADID64INFO,
            tid,
            buf.as_mut_ptr() as *mut c_void,
            PROC_PIDTHREADID64INFO_SIZE,
        )
    };
    if rc != PROC_PIDTHREADID64INFO_SIZE {
        return 0;
    }
    let name = &buf[PTH_NAME_OFFSET..PTH_NAME_OFFSET + PTH_NAME_LEN];
    let len = name.iter().position(|&b| b == 0).unwrap_or(PTH_NAME_LEN);
    let n = len.min(cap);
    if n > 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(name.as_ptr(), out, n);
        }
    }
    n
}

/// Executable path of `pid` via proc_pidpath, written directly into `out`
/// (up to `cap` bytes). Returns proc_pidpath's byte count (which trails a NUL
/// the caller strips), or 0 on failure.
///
/// # Safety
/// `out` must be writable for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_proc_pid_path(pid: i32, out: *mut u8, cap: usize) -> usize {
    let rc = unsafe { proc_pidpath(pid, out as *mut c_void, cap as u32) };
    if rc <= 0 {
        return 0;
    }
    (rc as usize).min(cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn own_pid() -> i32 {
        std::process::id() as i32
    }

    #[test]
    fn pid_path_of_self_is_nonempty_and_exists() {
        let mut buf = [0u8; 1024];
        let n = unsafe { sismo_proc_pid_path(own_pid(), buf.as_mut_ptr(), buf.len()) };
        assert!(n > 0, "proc_pidpath should resolve our own path");
        // Strip trailing NUL(s), like the sched caller does.
        let path = &buf[..n];
        let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
        let s = std::str::from_utf8(&path[..end]).unwrap();
        assert!(std::path::Path::new(s).exists(), "resolved path {s:?} should exist");
    }

    #[test]
    fn parent_pid_of_self_is_positive() {
        let mut ppid = 0u32;
        assert!(unsafe { sismo_proc_parent_pid(own_pid(), &mut ppid) });
        assert!(ppid > 0, "we always have a parent");
    }

    #[test]
    fn bogus_pid_fails_cleanly() {
        // A pid that (essentially) never exists — expect clean failure, not UB.
        let mut ppid = 0u32;
        assert!(!unsafe { sismo_proc_parent_pid(0x7FFF_FFFE, &mut ppid) });
        let mut buf = [0u8; 64];
        assert_eq!(unsafe { sismo_proc_thread_name(0x7FFF_FFFE, 1, buf.as_mut_ptr(), buf.len()) }, 0);
        assert_eq!(unsafe { sismo_proc_pid_path(0x7FFF_FFFE, buf.as_mut_ptr(), buf.len()) }, 0);
    }

    #[test]
    fn thread_name_respects_cap() {
        // Even if unnamed (n=0), must never exceed cap. Exercise a tiny cap.
        let mut buf = [0xFFu8; 8];
        let n = unsafe { sismo_proc_thread_name(own_pid(), 1, buf.as_mut_ptr(), 4) };
        assert!(n <= 4);
        assert_eq!(buf.len(), 8); // buffer untouched beyond cap is fine
    }
}
