// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Shared primitives for the in-process capture workers (cpu, sched, heap): the
//! Condvar-backed manual-reset [`Event`], a monotonic clock read, and
//! little-endian field readers for the fixed-layout mach structs they parse.
//! The producer C ABI these workers emit through (`sismo_ds_*`) and its callback
//! types live in [`crate::ffi`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

/// Monotonic clock in nanoseconds. Matches the trace's MONOTONIC domain.
#[cfg(unix)]
pub fn now_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Little-endian u64 at byte offset `off`. Panics if `b` is too short.
pub fn read_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// Little-endian i32 at byte offset `off`. Panics if `b` is too short.
pub fn read_i32(b: &[u8], off: usize) -> i32 {
    i32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

/// Block a capture worker at the top of `run` until on_setup fires (via a
/// `wakeup.set`) or exit is requested. Returns true if setup arrived, false if
/// exit was requested first — in which case the worker should return.
pub fn wait_for_setup(wakeup: &Event, exit_requested: &AtomicBool, setup_received: &AtomicBool) -> bool {
    while !exit_requested.load(Ordering::Acquire) && !setup_received.load(Ordering::Acquire) {
        wakeup.reset();
        if exit_requested.load(Ordering::Acquire) || setup_received.load(Ordering::Acquire) {
            break;
        }
        wakeup.wait();
    }
    !exit_requested.load(Ordering::Acquire)
}

/// Manual-reset event. Trampolines `set` to wake the worker; the worker
/// `reset`s at the top of each loop and `wait`s/`wait_timeout`s at the bottom,
/// so a `set` between reset and wait is not lost.
pub struct Event {
    signaled: Mutex<bool>,
    cv: Condvar,
}

impl Event {
    pub fn new() -> Self {
        Event { signaled: Mutex::new(false), cv: Condvar::new() }
    }
    pub fn set(&self) {
        *self.signaled.lock().unwrap() = true;
        self.cv.notify_all();
    }
    pub fn reset(&self) {
        *self.signaled.lock().unwrap() = false;
    }
    pub fn wait(&self) {
        let mut g = self.signaled.lock().unwrap();
        while !*g {
            g = self.cv.wait(g).unwrap();
        }
    }
    pub fn wait_timeout(&self, dur: Duration) {
        let g = self.signaled.lock().unwrap();
        if !*g {
            let _ = self.cv.wait_timeout(g, dur).unwrap();
        }
    }
}

impl Default for Event {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_before_wait_is_not_lost() {
        let e = Event::new();
        e.set();
        e.wait(); // must return immediately
        e.reset();
    }
}
