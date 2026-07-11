// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `kperf-spike <pid> [secs] [period_us]` — sample one process's threads via
//! kperf PET and print reassembled user stacks. macOS only, root only.

#[cfg(target_os = "macos")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: {} <pid> [secs=3] [period_us=1000]", args[0]);
        std::process::exit(2);
    }
    let pid: i32 = args[1].parse().unwrap_or_else(|_| {
        eprintln!("bad pid: {}", args[1]);
        std::process::exit(2);
    });
    let secs: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3);
    let period_us: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1000);

    match kperf_spike::run(pid, secs, period_us * 1000) {
        Ok(n) => eprintln!("kperf-spike: {n} user-stack samples"),
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
