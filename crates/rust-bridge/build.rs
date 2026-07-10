// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Compile the kernel-side BPF object (src/c/sismo_bpf/sched.bpf.c) so the
//! Linux CPU collector (src/linux_bpf_capture.rs) can include_bytes! it. Linux
//! only; needs clang with the bpf target (same invocation build.zig used).

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "linux" {
        return;
    }
    // crates/rust-bridge -> repo root is two levels up.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let bpf_dir = root.join("src/c/sismo_bpf");
    let src = bpf_dir.join("sched.bpf.c");
    let obj = out.join("sched.bpf.o");

    let status = Command::new("clang")
        .args(["-target", "bpf", "-D__TARGET_ARCH_x86"])
        .arg("-I")
        .arg(&bpf_dir)
        .args(["-Wno-missing-declarations", "-O2", "-g", "-c"])
        .arg(&src)
        .arg("-o")
        .arg(&obj)
        .status()
        .expect("run clang for sched.bpf.o");
    assert!(status.success(), "compiling sched.bpf.c failed");

    println!("cargo:rerun-if-changed={}", bpf_dir.display());
}
