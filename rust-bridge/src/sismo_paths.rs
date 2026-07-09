// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Well-known filesystem paths + binary-relative resolution (migrated from the
//! logic half of sismo_paths.zig). Session-lock acquire/release (flock), the
//! recorder-pid read, and heap-dylib path resolution. The socket-path string
//! constants stay in the Zig facade for now; those are stable literals, not
//! logic. POSIX-only (flock + /tmp); the module is not built on Windows.
//!
//! Exposed over a small C ABI so the Zig `sismo_paths.zig` facade (which its 5
//! CLI callers still use unchanged) forwards to it; that facade collapses as the
//! cmd_* commands migrate to Rust (P4).

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::raw::c_int;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, IntoRawFd};

const SESSION_LOCK_PATH: &str = "/tmp/sismo.lock";

// BSD flock operations (identical on macOS + Linux).
const LOCK_EX: c_int = 2;
const LOCK_NB: c_int = 4;

extern "C" {
    fn flock(fd: c_int, operation: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
}

/// Acquire the session lock, writing `pid` (ASCII) into the file so `sismo
/// snapshot` can find the recorder. Returns the held fd (>= 0) — the caller must
/// keep it open for the recording's lifetime and close it via
/// `sismo_release_session_lock`. On failure: -1 open failed, -2 already held.
#[unsafe(no_mangle)]
pub extern "C" fn sismo_acquire_session_lock(pid: c_int) -> c_int {
    acquire_at(SESSION_LOCK_PATH, pid)
}

fn acquire_at(path: &str, pid: c_int) -> c_int {
    // std handles the (variadic) open() ABI correctly, sidestepping the ARM64
    // Darwin variadic-mode footgun the Zig version documents.
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o644)
        .open(path)
    {
        Ok(f) => f,
        Err(_) => return -1,
    };
    let fd = file.as_raw_fd();
    if unsafe { flock(fd, LOCK_EX | LOCK_NB) } != 0 {
        return -2; // File drop closes fd, releasing nothing (never locked).
    }
    // Replace any prior contents with the pid as ASCII: truncate then write.
    let _ = file.set_len(0);
    let mut file = file;
    let _ = write!(file, "{pid}\n");
    // Leak the fd so the lock persists past this call; the caller owns it.
    file.into_raw_fd()
}

/// Release the session lock (closing the fd drops the flock).
#[unsafe(no_mangle)]
pub extern "C" fn sismo_release_session_lock(fd: c_int) {
    unsafe { close(fd) };
}

/// Read the recorder pid from the lock file into `*out_pid`. Returns 0 on
/// success; -1 no lock file, -2 empty/no recorder, -3 invalid pid.
///
/// # Safety
/// `out_pid` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_read_recorder_pid(out_pid: *mut c_int) -> c_int {
    read_pid_at(SESSION_LOCK_PATH, out_pid)
}

fn read_pid_at(path: &str, out_pid: *mut c_int) -> c_int {
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return -1,
    };
    let mut buf = [0u8; 24];
    let n = match file.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return -2,
    };
    if n == 0 {
        return -2;
    }
    let text = std::str::from_utf8(&buf[..n]).unwrap_or("").trim();
    if text.is_empty() {
        return -2;
    }
    match text.parse::<c_int>() {
        Ok(pid) => {
            unsafe { *out_pid = pid };
            0
        }
        Err(_) => -3,
    }
}

/// Resolve the heap-preload dylib path relative to the running binary, writing
/// it (no NUL) into `out[..cap]` and returning the length (0 on failure, or if
/// it doesn't fit). Tries the install / cargo-dev / legacy layouts in order,
/// returning the first that exists; falls back to the cargo-dev candidate.
///
/// # Safety
/// `out` must be writable for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_heap_dylib_path(out: *mut u8, cap: usize) -> usize {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let bin_dir = match exe.parent() {
        Some(d) => d,
        None => return 0,
    };

    // Most-specific first; index 1 (cargo dev tree) is the best-effort fallback.
    const LAYOUTS: [&str; 3] = [
        "../libexec/sismo/libsismo_heap.dylib",
        "../../../zig-out/lib/libsismo_heap.dylib",
        "../lib/libsismo_heap.dylib",
    ];
    const FALLBACK_INDEX: usize = 1;

    let mut fallback: Option<String> = None;
    for (i, rel) in LAYOUTS.iter().enumerate() {
        let candidate = bin_dir.join(rel);
        let s = candidate.to_string_lossy().into_owned();
        if candidate.exists() {
            return write_path(&s, out, cap);
        }
        if i == FALLBACK_INDEX {
            fallback = Some(s);
        }
    }
    match fallback {
        Some(s) => write_path(&s, out, cap),
        None => 0,
    }
}

fn write_path(s: &str, out: *mut u8, cap: usize) -> usize {
    let bytes = s.as_bytes();
    if bytes.len() > cap {
        return 0;
    }
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
    bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_write_read_release_roundtrip() {
        // Use a private temp path (not the real /tmp/sismo.lock, which a prior
        // sudo run may have left root-owned): acquire → the pid reads back.
        let path = std::env::temp_dir().join("sismo-paths-selftest.lock");
        let p = path.to_str().unwrap();
        let fd = acquire_at(p, 4242);
        assert!(fd >= 0);
        let mut pid: c_int = 0;
        let rc = read_pid_at(p, &mut pid);
        assert_eq!(rc, 0);
        assert_eq!(pid, 4242);
        sismo_release_session_lock(fd);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn read_pid_absent_file_errors() {
        let path = std::env::temp_dir().join("sismo-paths-nonexistent-xyz.lock");
        let _ = std::fs::remove_file(&path);
        let mut pid: c_int = 0;
        assert_eq!(read_pid_at(path.to_str().unwrap(), &mut pid), -1);
    }

    #[test]
    fn heap_dylib_path_writes_a_nonempty_path() {
        let mut buf = [0u8; 4096];
        let n = unsafe { sismo_heap_dylib_path(buf.as_mut_ptr(), buf.len()) };
        assert!(n > 0);
        let s = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(s.ends_with("libsismo_heap.dylib"));
    }

    #[test]
    fn heap_dylib_path_rejects_too_small_buffer() {
        let mut buf = [0u8; 4];
        let n = unsafe { sismo_heap_dylib_path(buf.as_mut_ptr(), buf.len()) };
        assert_eq!(n, 0);
    }
}
