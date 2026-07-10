// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! The `Event` primitive the in-process capture workers (cpu, sched, heap) use:
//! a Condvar-backed manual-reset event mirroring Zig's std.Io.Event. The
//! producer C ABI these workers emit through (`sismo_ds_*`) and its callback
//! types live in [`crate::ffi`].

use std::sync::{Condvar, Mutex};
use std::time::Duration;

/// Manual-reset event. Trampolines `set` to wake the worker; the worker
/// `reset`s at the top of each loop and `wait`s/`wait_timeout`s at the bottom,
/// so a `set` between reset and wait is not lost (mirrors std.Io.Event usage).
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
