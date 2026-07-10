// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Link the Zig half (libsismo_zig.a, built by `zig build sismo-staticlib`),
//! the Perfetto C++ archive, and the C++ runtime.
//!
//! The whole C++ world here — perfetto and the Zig staticlib's C/C++ shims —
//! was compiled with Zig's bundled libc++, and there is no system libc++. So
//! rather than guess, we ask `zig c++ -v` which libc++/libc++abi/libunwind
//! archives it links for this target (the correct variant for the mode/target)
//! and hand those exact paths to the linker.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // Drive the Zig build so `cargo build` alone produces everything: the
    // static archive we link (+ its Perfetto dependency) and the auxiliary
    // Zig binaries (sample-target, sismo-run). Zig caches, so this is cheap
    // when nothing changed. Reruns when any Zig source or build.zig changes.
    zig_build(&root, &["sismo-staticlib"]);
    zig_build(&root, &[]);
    println!("cargo:rerun-if-changed={}", root.join("src").display());
    println!("cargo:rerun-if-changed={}", root.join("build.zig").display());

    // libsismo_zig.a (Zig + C/C++ shims + compiler_rt).
    println!("cargo:rustc-link-search=native={}", root.join("zig-out/lib").display());
    println!("cargo:rustc-link-lib=static=sismo_zig");

    // Perfetto C++ SDK archive.
    let pf = root.join("third_party/src/perfetto/out/sismo");
    println!("cargo:rustc-link-search=native={}", pf.display());
    println!("cargo:rustc-link-lib=static=sismo_libperfetto");

    // Target OS drives the link surface. On Linux there is no system libc++,
    // so we hand the linker Zig's static libc++/libc++abi/libunwind. macOS
    // ships a system libc++ that is ABI-compatible with the one Zig used for
    // the C/C++ shims (both are LLVM libc++), so we link that instead.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os == "macos" {
        link_macos();
        // The heap preload is now a Rust cdylib (heap-preload/). Build it and
        // install it where sismo_paths resolves it (zig-out/lib/libsismo_heap.dylib).
        build_heap_preload(&root);
    } else {
        // Zig's C++ runtime archives, discovered from `zig c++ -v`.
        for archive in discover_cxx_runtime(&root, &out) {
            println!("cargo:rustc-link-arg={archive}");
        }

        // System libs the Zig/perfetto code needs.
        for lib in ["bpf", "dl", "pthread", "rt", "m"] {
            println!("cargo:rustc-link-lib=dylib={lib}");
        }
    }

    println!("cargo:rerun-if-changed=build.rs");
}

/// macOS link surface. Mirrors what the deleted Zig `sismo` executable linked:
/// the system libc++ (pthread/m live in libSystem, no separate -lpthread/-lm),
/// libdl (perfetto + wholesym), CoreFoundation (perfetto), and the frameworks
/// wholesym pulls in via core-foundation-rs — Foundation/Security — plus
/// CoreServices (Spotlight, to locate dSYM bundles). No bpf/rt: those are Linux.
fn link_macos() {
    println!("cargo:rustc-link-lib=dylib=c++");
    println!("cargo:rustc-link-lib=dylib=dl");
    for framework in ["CoreFoundation", "Foundation", "Security", "CoreServices"] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
}

/// Build the macOS heap preload cdylib (heap-preload/) in release (so it gets
/// `panic = "abort"` — never unwind into the injected target) and install it as
/// `zig-out/lib/libsismo_heap.dylib`, where `sismo_paths` resolves it. Nested
/// cargo is isolated: it uses the crate's own `heap-preload/target`, and we drop
/// the outer build's CARGO env so it doesn't inherit our manifest/target.
fn build_heap_preload(root: &PathBuf) {
    let manifest = root.join("heap-preload/Cargo.toml");
    let status = Command::new("python3")
        .arg(root.join("tools/cargo"))
        .args(["--hermetic", "build", "--release", "--manifest-path"])
        .arg(&manifest)
        .env_remove("CARGO")
        .env_remove("CARGO_MANIFEST_DIR")
        .env_remove("CARGO_MANIFEST_PATH")
        .status()
        .expect("run cargo build for heap-preload");
    assert!(status.success(), "heap-preload cdylib build failed");

    let src = root.join("heap-preload/target/release/libsismo_heap_preload.dylib");
    let dst_dir = root.join("zig-out/lib");
    std::fs::create_dir_all(&dst_dir).expect("mkdir zig-out/lib");
    std::fs::copy(&src, dst_dir.join("libsismo_heap.dylib")).expect("install libsismo_heap.dylib");

    println!("cargo:rerun-if-changed={}", root.join("heap-preload/src").display());
    println!("cargo:rerun-if-changed={}", root.join("heap-preload/Cargo.toml").display());
}

/// Run `zig build <steps>` via the pinned hermetic toolchain.
fn zig_build(root: &PathBuf, steps: &[&str]) {
    let mut cmd = Command::new("python3");
    cmd.current_dir(root) // build.zig lives at the repo root
        .arg(root.join("tools/zig"))
        .arg("--hermetic")
        .arg("build");
    cmd.args(steps);
    let status = cmd.status().expect("run zig build");
    assert!(status.success(), "zig build {steps:?} failed");
}

/// Compile+link a tiny libc++-using program with `zig c++ -v` and scrape the
/// libc++/libc++abi/libunwind archive paths it links.
fn discover_cxx_runtime(root: &PathBuf, out: &PathBuf) -> Vec<String> {
    let probe = out.join("cxx_probe.cpp");
    std::fs::write(
        &probe,
        "#include <string>\nint main(){std::string s;s.push_back('x');return (int)s.size();}\n",
    )
    .expect("write cxx probe");

    let zig = root.join("tools/zig");
    let output = Command::new("python3")
        .arg(&zig)
        .arg("--hermetic")
        .arg("c++")
        .arg("-target")
        .arg("x86_64-linux-gnu")
        .arg(&probe)
        .arg("-o")
        .arg(out.join("cxx_probe.out"))
        .arg("-v")
        .output()
        .expect("run zig c++ for libc++ discovery");

    let log = String::from_utf8_lossy(&output.stderr);
    let mut found = Vec::new();
    for tok in log.split_whitespace() {
        if (tok.ends_with("/libc++.a")
            || tok.ends_with("/libc++abi.a")
            || tok.ends_with("/libunwind.a"))
            && !found.contains(&tok.to_string())
        {
            found.push(tok.to_string());
        }
    }
    assert!(
        found.len() >= 3,
        "could not discover Zig C++ runtime archives from `zig c++ -v`; found {found:?}\nstderr:\n{log}"
    );
    found
}
