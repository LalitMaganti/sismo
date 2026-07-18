// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.
//
// Rust port of the canonical matrix workload (see workload.c for the shape).
// Built directly with rustc (no cargo).

use std::time::{Duration, Instant};

#[inline(never)]
fn sismo_wl_leaf(mut x: u64) -> u64 {
    for i in 0..4096u64 {
        x = x.wrapping_mul(2654435761).wrapping_add(i);
    }
    std::hint::black_box(x)
}

#[inline(never)]
fn sismo_wl_mid(mut x: u64) -> u64 {
    for i in 0..8u64 {
        x = sismo_wl_leaf(x ^ i);
    }
    x
}

#[inline(never)]
fn sismo_wl_outer(mut x: u64) -> u64 {
    for i in 0..4u64 {
        x = sismo_wl_mid(x.wrapping_add(i));
    }
    x
}

#[inline(never)]
fn sismo_wl_block() {
    std::thread::sleep(Duration::from_millis(2));
}

fn main() {
    let duration_ms: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);
    let end = Instant::now() + Duration::from_millis(duration_ms);
    let mut x: u64 = 1;
    let mut iters: u64 = 0;
    while Instant::now() < end {
        x = sismo_wl_outer(x);
        iters += 1;
        if iters % 32 == 0 {
            sismo_wl_block();
        }
    }
    std::hint::black_box(x);
    println!("sismo-workload iters={iters}");
}
