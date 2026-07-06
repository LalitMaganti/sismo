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

    // libsismo_zig.a (Zig + C/C++ shims + compiler_rt).
    println!("cargo:rustc-link-search=native={}", root.join("zig-out/lib").display());
    println!("cargo:rustc-link-lib=static=sismo_zig");

    // Perfetto C++ SDK archive.
    let pf = root.join("third_party/src/perfetto/out/sismo");
    println!("cargo:rustc-link-search=native={}", pf.display());
    println!("cargo:rustc-link-lib=static=sismo_libperfetto");

    // Zig's C++ runtime archives, discovered from `zig c++ -v`.
    for archive in discover_cxx_runtime(&root, &out) {
        println!("cargo:rustc-link-arg={archive}");
    }

    // System libs the Zig/perfetto code needs.
    for lib in ["bpf", "dl", "pthread", "rt", "m"] {
        println!("cargo:rustc-link-lib=dylib={lib}");
    }

    println!("cargo:rerun-if-changed=build.rs");
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
