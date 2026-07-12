// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `kperf-spike <pid> [secs] [us]` — capture one process's off-CPU stacks via
//! kperf's lazy.wait sampler (blocking user stack + wait duration, pid-filtered
//! in-kernel). macOS only, root only.
//!
//! Default mode is lazy.wait off-CPU; the third arg is the wait threshold in µs
//! (waits shorter than this are ignored). Set KPERF_SPIKE_PET=1 for the legacy
//! PET snapshot mode, where the third arg is the timer period in µs instead.

#[cfg(target_os = "macos")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: {} <pid> [secs=3] [us=1000]", args[0]);
        eprintln!("  default: lazy.wait off-CPU (us = wait threshold)");
        eprintln!("  KPERF_SPIKE_PET=1: PET snapshot (us = timer period)");
        std::process::exit(2);
    }
    let pid: i32 = args[1].parse().unwrap_or_else(|_| {
        eprintln!("bad pid: {}", args[1]);
        std::process::exit(2);
    });
    let secs: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3);
    let us: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1000);

    match kperf_spike::run(pid, secs, us * 1000) {
        Ok(n) => eprintln!("kperf-spike: {n} samples"),
        Err(e) => {
            eprintln!("kperf-spike: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("kperf-spike is macOS-only");
    std::process::exit(1);
}
