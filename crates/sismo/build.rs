// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! The Perfetto C++ archive + C/C++ shim compile and link now live in
//! `sismo-sys`'s build script (behind its `perfetto-shim` feature, which this
//! crate enables); its `rustc-link-*` directives propagate here to the final
//! binaries. All that remains here is the macOS heap-preload cdylib install.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os == "macos" {
        // The heap preload is a Rust cdylib (sismo-heap-preload/). Build it and
        // install it where sismo_paths resolves it (dev-install/lib/libsismo_heap.dylib).
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        build_heap_preload(&root);
    }

    println!("cargo:rerun-if-changed=build.rs");
}

/// Build the macOS heap preload cdylib (sismo-heap-preload/) in release (so it gets
/// `panic = "abort"` — never unwind into the injected target) and install it as
/// `dev-install/lib/libsismo_heap.dylib`, where `sismo_paths` resolves it. Nested
/// cargo is isolated: it uses the crate's own `sismo-heap-preload/target`, and we drop
/// the outer build's CARGO env so it doesn't inherit our manifest/target.
fn build_heap_preload(root: &PathBuf) {
    let manifest = root.join("crates/sismo-heap-preload/Cargo.toml");
    let status = Command::new("python3")
        .arg(root.join("tools/cargo"))
        .args(["--hermetic", "build", "--release", "--manifest-path"])
        .arg(&manifest)
        .env_remove("CARGO")
        .env_remove("CARGO_MANIFEST_DIR")
        .env_remove("CARGO_MANIFEST_PATH")
        .status()
        .expect("run cargo build for sismo-heap-preload");
    assert!(status.success(), "sismo-heap-preload cdylib build failed");

    let src = root.join("crates/sismo-heap-preload/target/release/libsismo_heap_preload.dylib");
    let dst_dir = root.join("dev-install/lib");
    std::fs::create_dir_all(&dst_dir).expect("mkdir dev-install/lib");
    std::fs::copy(&src, dst_dir.join("libsismo_heap.dylib")).expect("install libsismo_heap.dylib");

    println!("cargo:rerun-if-changed={}", root.join("crates/sismo-heap-preload/src").display());
    println!("cargo:rerun-if-changed={}", root.join("crates/sismo-heap-preload/Cargo.toml").display());
}
