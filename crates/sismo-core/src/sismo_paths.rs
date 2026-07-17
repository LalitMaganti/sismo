// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Well-known filesystem paths + binary-relative resolution: session-lock
//! acquire/release (flock), the recorder-pid read, and heap-dylib path
//! resolution. POSIX-only (flock + /tmp); the module is not built on Windows.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use libc::{close, flock, LOCK_EX, LOCK_NB};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};

const SESSION_LOCK_PATH: &str = "/tmp/sismo.lock";

// Well-known sockets the embedded `traced` hosts.
pub const PRODUCER_SOCK: &str = "/tmp/sismo-producer.sock";
pub const CONSUMER_SOCK: &str = "/tmp/sismo-consumer.sock";

/// Why acquiring the session lock failed.
#[derive(Debug)]
pub enum LockError {
    /// Couldn't open the lock file.
    Open,
    /// Another session already holds it.
    Held,
}

/// Acquire the session lock, writing `pid` (ASCII) into the file so `sismo
/// snapshot` can find the recorder. On success returns the held fd — the caller
/// must keep it open for the recording's lifetime and close it via
/// [`release_session_lock`].
pub fn acquire_session_lock(pid: i32) -> Result<RawFd, LockError> {
    acquire_at(SESSION_LOCK_PATH, pid)
}

fn acquire_at(path: &str, pid: i32) -> Result<RawFd, LockError> {
    // std handles the (variadic) open() ABI correctly, sidestepping the ARM64
    // Darwin variadic-mode footgun.
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o644)
        .open(path)
        .map_err(|_| LockError::Open)?;
    let fd = file.as_raw_fd();
    if unsafe { flock(fd, LOCK_EX | LOCK_NB) } != 0 {
        return Err(LockError::Held); // File drop closes fd (never locked).
    }
    // Replace any prior contents with the pid as ASCII: truncate then write.
    let _ = file.set_len(0);
    let mut file = file;
    let _ = writeln!(file, "{pid}");
    // Leak the fd so the lock persists past this call; the caller owns it.
    Ok(file.into_raw_fd())
}

/// Release the session lock (closing the fd drops the flock).
pub fn release_session_lock(fd: RawFd) {
    unsafe { close(fd) };
}

/// The recorder pid from the lock file, or `None` if there's no lock file / no
/// recorder / the contents don't parse. `sismo snapshot` uses this to find the
/// running recorder.
pub fn read_recorder_pid() -> Option<i32> {
    read_pid_at(SESSION_LOCK_PATH)
}

fn read_pid_at(path: &str) -> Option<i32> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = [0u8; 24];
    let n = file.read(&mut buf).ok()?;
    std::str::from_utf8(&buf[..n]).ok()?.trim().parse::<i32>().ok()
}

/// Resolve the heap-preload dylib path relative to the running binary. Tries the
/// install / cargo-dev / legacy layouts and returns the first that exists, else
/// the cargo-dev candidate as a best-effort. Shared with `cmd_prepare`.
pub fn resolve_heap_dylib_path() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let bin_dir = exe.parent()?;

    // Most-specific first; index 1 (cargo dev tree) is the best-effort fallback.
    // For a cargo-built binary at `crates/sismo/target/debug/sismo`, the repo
    // root is four levels up from `bin_dir`.
    const LAYOUTS: [&str; 4] = [
        "../libexec/sismo/libsismo_heap.dylib",
        "../../../../dev-install/lib/libsismo_heap.dylib",
        "../../../dev-install/lib/libsismo_heap.dylib",
        "../lib/libsismo_heap.dylib",
    ];
    const FALLBACK_INDEX: usize = 1;

    let mut fallback: Option<String> = None;
    for (i, rel) in LAYOUTS.iter().enumerate() {
        let candidate = bin_dir.join(rel);
        let s = candidate.to_string_lossy().into_owned();
        if candidate.exists() {
            return Some(s);
        }
        if i == FALLBACK_INDEX {
            fallback = Some(s);
        }
    }
    fallback
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
        let fd = acquire_at(p, 4242).expect("acquire");
        assert_eq!(read_pid_at(p), Some(4242));
        release_session_lock(fd);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn read_pid_absent_file_is_none() {
        let path = std::env::temp_dir().join("sismo-paths-nonexistent-xyz.lock");
        let _ = std::fs::remove_file(&path);
        assert_eq!(read_pid_at(path.to_str().unwrap()), None);
    }

    #[test]
    fn heap_dylib_path_resolves_to_a_dylib() {
        let s = resolve_heap_dylib_path().expect("resolve");
        assert!(s.ends_with("libsismo_heap.dylib"));
    }
}
