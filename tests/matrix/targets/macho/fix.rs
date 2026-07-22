// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.
//
// Rust port of fix.c. Legacy mangling appends ::h<16 hex> hashes; the suite
// normalizes those to h<HASH> in the golden.

#[inline(never)]
fn sismo_fix_leaf(x: i64) -> i64 {
    let mut acc = 0;
    for i in 0..x {
        acc += i * i;
    }
    acc
}

#[inline(never)]
fn sismo_fix_mid(x: i64) -> i64 {
    sismo_fix_leaf(x) + 1
}

fn main() {
    println!("{}", sismo_fix_mid(std::hint::black_box(100)));
}
