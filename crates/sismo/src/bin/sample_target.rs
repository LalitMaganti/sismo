// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `sample-target` — workload binary `sismo record` spawns and profiles. Three
//! deliberately distinct threads so the trace is easy to read by eye:
//!   - `busy_worker`   — tight arithmetic loop + periodic malloc; near-100% CPU.
//!   - `sleepy_worker` — short bursts of work between 2 ms sleeps.
//!   - `sdk_worker`    — emits TrackEvent slices via Perfetto's stock SDK so the
//!                       trace exercises `track_event` too.
//!
//! Default duration is 5000 ms — long enough for an interesting profile, short
//! enough that a stray invocation exits on its own.

use std::ffi::{c_char, c_void};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

// Link sismo-sys for its native side effects only: its build script compiles
// and links libsismo_cc_shims.a (which carries this bin's TrackEvent shim) plus
// the Perfetto archive. Without this the rlib — and its native libs — get pruned.
use sismo_sys as _;

// Perfetto C TrackEvent shim (csrc/sample_target_sdk.c, compiled into
// libsismo_cc_shims.a by sismo-sys). All emit calls are no-ops until te_init
// connects.
extern "C" {
    fn sismo_target_te_init();
    fn sismo_target_slice_begin(name: *const c_char);
    fn sismo_target_slice_end();
    fn sismo_target_instant(name: *const c_char);
    fn malloc(size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
    fn getpid() -> i32;
}

fn sdk_worker(stop: &AtomicBool) {
    let mut iter: u32 = 0;
    while !stop.load(Ordering::Relaxed) {
        iter = iter.wrapping_add(1);
        unsafe {
            sismo_target_slice_begin(c"frame".as_ptr());
            sismo_target_slice_begin(c"update".as_ptr());
            thread::sleep(Duration::from_micros(500));
            sismo_target_slice_end();
            sismo_target_slice_begin(c"draw".as_ptr());
            thread::sleep(Duration::from_micros(800));
            sismo_target_slice_end();
            sismo_target_slice_end();
            if iter % 100 == 0 {
                sismo_target_instant(c"milestone".as_ptr());
            }
        }
        thread::sleep(Duration::from_micros(1000));
    }
}

fn busy_worker(stop: &AtomicBool) {
    let mut x: u64 = 0;
    let mut iter: u32 = 0;
    while !stop.load(Ordering::Relaxed) {
        for i in 0..1024u32 {
            x = x.wrapping_mul(2654435761).wrapping_add(i as u64);
        }
        std::hint::black_box(x);
        // Periodic libc malloc so a heap orchestrator that attaches after the
        // startup phase has steady-state captures to consume. Cycle sizes so the
        // Poisson sampler sees both small (high-rate) and large (always-sampled).
        iter = iter.wrapping_add(1);
        if iter % 4 == 0 {
            let sz: usize = match iter % 16 {
                0 => 64,
                4 => 256,
                8 => 1024,
                _ => 8192, // > sampling interval, always recorded
            };
            unsafe {
                let p = malloc(sz);
                if !p.is_null() {
                    free(p);
                }
            }
        }
    }
}

fn sleepy_worker(stop: &AtomicBool) {
    let mut x: u64 = 0;
    while !stop.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_micros(2000));
        for i in 0..64u32 {
            x = x.wrapping_mul(2654435761).wrapping_add(i as u64);
        }
        std::hint::black_box(x);
    }
}

fn main() {
    let duration_ms: u32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5000);

    let pid = unsafe { getpid() };
    println!("sample-target pid={pid} duration_ms={duration_ms}");

    // Connect to the orchestrator's hosted producer socket. SYSTEM backend;
    // `sismo record` owns the session.
    unsafe { sismo_target_te_init() };

    // Deterministic allocation phase: 1000 explicit libc mallocs from a
    // recognizable site, giving heap capture a known-shape count to compare.
    for _ in 0..1000 {
        unsafe {
            let p = malloc(4096);
            if !p.is_null() {
                free(p);
            }
        }
    }
    println!("sample-target: allocation phase done (1000 explicit libc mallocs)");

    let stop = AtomicBool::new(false);
    thread::scope(|s| {
        s.spawn(|| busy_worker(&stop));
        s.spawn(|| sleepy_worker(&stop));
        s.spawn(|| sdk_worker(&stop));
        thread::sleep(Duration::from_millis(duration_ms as u64));
        stop.store(true, Ordering::Relaxed);
    });
}
