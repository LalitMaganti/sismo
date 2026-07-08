// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Shared plumbing for the in-process capture workers (cpu, sched, heap):
//! the producer C ABI (`sismo_ds_*`, from the C++ shim in the final binary),
//! the data-source trampoline signatures, and a Condvar-backed manual-reset
//! Event mirroring Zig's std.Io.Event.
//!
//! The `#[cfg(test)]` stubs live here (once) so the standalone `cargo test`
//! lib binary links without the C++ shim; defining them per-worker would
//! clash on the `#[no_mangle]` symbols.

use std::os::raw::c_void;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

/// Data-source lifecycle callbacks (invoked by the SDK on its IO thread).
pub type OnSetup = extern "C" fn(*mut c_void, *const c_void, usize);
pub type OnStart = extern "C" fn(*mut c_void);
pub type OnStop = extern "C" fn(*mut c_void, *mut c_void);
pub type OnFlush = extern "C" fn(*mut c_void, *mut c_void);

#[cfg(not(test))]
extern "C" {
    pub fn sismo_ds_register(
        desc_bytes: *const u8,
        desc_len: usize,
        on_setup: OnSetup,
        on_start: OnStart,
        on_stop: OnStop,
        on_flush: OnFlush,
        user_arg: *mut c_void,
    ) -> u32;
    pub fn sismo_ds_emit(slot: u32, packet_bytes: *const u8, packet_len: usize);
    pub fn sismo_stop_done(handle: *mut c_void);
    pub fn sismo_flush_done(handle: *mut c_void);
}

#[cfg(test)]
mod stubs {
    use super::{OnFlush, OnSetup, OnStart, OnStop};
    use std::os::raw::c_void;
    #[no_mangle]
    pub unsafe extern "C" fn sismo_ds_register(
        _d: *const u8,
        _dl: usize,
        _s: OnSetup,
        _st: OnStart,
        _sp: OnStop,
        _f: OnFlush,
        _u: *mut c_void,
    ) -> u32 {
        u32::MAX
    }
    #[no_mangle]
    pub unsafe extern "C" fn sismo_ds_emit(_slot: u32, _b: *const u8, _l: usize) {}
    #[no_mangle]
    pub unsafe extern "C" fn sismo_stop_done(_h: *mut c_void) {}
    #[no_mangle]
    pub unsafe extern "C" fn sismo_flush_done(_h: *mut c_void) {}
}
#[cfg(test)]
pub use stubs::{sismo_ds_emit, sismo_ds_register, sismo_flush_done, sismo_stop_done};

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
