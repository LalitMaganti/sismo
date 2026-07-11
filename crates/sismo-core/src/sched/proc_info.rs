// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! macOS libproc bindings, used by the sched producer to attach process /
//! thread names to scheduler events.
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

/// Parent pid of `pid` via PROC_PIDTBSDINFO, or `None` on any proc_pidinfo
/// failure (pid gone, etc.).
pub fn parent_pid(pid: i32) -> Option<u32> {
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
        return None;
    }
    Some(u32::from_ne_bytes(buf[PBI_PPID_OFFSET..PBI_PPID_OFFSET + 4].try_into().unwrap()))
}

/// Thread name (proc_threadinfo.pth_name) for xnu thread-id `tid` under `pid`,
/// or `None` if the lookup fails or the thread is unnamed (kernel zero-fills
/// pth_name).
pub fn thread_name(pid: i32, tid: u64) -> Option<Vec<u8>> {
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
        return None;
    }
    let name = &buf[PTH_NAME_OFFSET..PTH_NAME_OFFSET + PTH_NAME_LEN];
    let len = name.iter().position(|&b| b == 0).unwrap_or(PTH_NAME_LEN);
    if len == 0 {
        return None;
    }
    Some(name[..len].to_vec())
}

/// Executable path of `pid` via proc_pidpath (trailing NUL stripped), or `None`
/// on failure.
pub fn pid_path(pid: i32) -> Option<Vec<u8>> {
    let mut buf = [0u8; 1024];
    let rc = unsafe { proc_pidpath(pid, buf.as_mut_ptr() as *mut c_void, buf.len() as u32) };
    if rc <= 0 {
        return None;
    }
    let s = &buf[..(rc as usize).min(buf.len())];
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    Some(s[..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn own_pid() -> i32 {
        std::process::id() as i32
    }

    #[test]
    fn pid_path_of_self_is_nonempty_and_exists() {
        let path = pid_path(own_pid()).expect("proc_pidpath should resolve our own path");
        let s = std::str::from_utf8(&path).unwrap();
        assert!(std::path::Path::new(s).exists(), "resolved path {s:?} should exist");
    }

    #[test]
    fn parent_pid_of_self_is_positive() {
        let ppid = parent_pid(own_pid()).expect("we always have a parent");
        assert!(ppid > 0);
    }

    #[test]
    fn bogus_pid_fails_cleanly() {
        // A pid that (essentially) never exists — expect clean failure, not UB.
        assert!(parent_pid(0x7FFF_FFFE).is_none());
        assert!(thread_name(0x7FFF_FFFE, 1).is_none());
        assert!(pid_path(0x7FFF_FFFE).is_none());
    }
}
