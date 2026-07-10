// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Build + link the C/C++ half of `sismo`: the Perfetto C++ archive and the
//! C/C++ shims, plus the C++ runtime.
//!
//! The whole C++ world here — perfetto and its C/C++ shims — is compiled with
//! Zig's bundled libc++ (`zig c++`), and there is no system libc++. So rather
//! than guess, we ask `zig c++ -v` which libc++/libc++abi/libunwind archives it
//! links for this target and hand those exact paths to the linker. Those Zig
//! runtime archives also carry the compiler_rt builtins the shims need, so no
//! separate Zig staticlib is required.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    // crates/rust-host -> repo root is two levels up.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    println!("cargo:rerun-if-changed={}", root.join("crates/sismo-sys/csrc").display());

    // Perfetto's C++ SDK archive + generated headers. Built directly (ninja is
    // incremental, so this is cheap once built). compile_cc_shims + the final
    // link both need it.
    build_perfetto(&root);

    // The Perfetto C/C++ glue (producer/consumer/traced shims + the sample-
    // target TrackEvent shim). Compiled with `zig c++`, matching the libc++
    // Perfetto was built with.
    compile_cc_shims(&root, &out);

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
        // The heap preload is now a Rust cdylib (sismo-heap-preload/). Build it and
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

/// Build the macOS heap preload cdylib (sismo-heap-preload/) in release (so it gets
/// `panic = "abort"` — never unwind into the injected target) and install it as
/// `zig-out/lib/libsismo_heap.dylib`, where `sismo_paths` resolves it. Nested
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
    let dst_dir = root.join("zig-out/lib");
    std::fs::create_dir_all(&dst_dir).expect("mkdir zig-out/lib");
    std::fs::copy(&src, dst_dir.join("libsismo_heap.dylib")).expect("install libsismo_heap.dylib");

    println!("cargo:rerun-if-changed={}", root.join("crates/sismo-heap-preload/src").display());
    println!("cargo:rerun-if-changed={}", root.join("crates/sismo-heap-preload/Cargo.toml").display());
}

/// Compile the Perfetto C/C++ glue shims with `zig c++` and archive them into
/// libsismo_cc_shims.a. Uses Zig's libc++ (what Perfetto was built with); its
/// runtime archives (linked via discover_cxx_runtime) carry the compiler_rt
/// builtins. ubsan is off so there's no __ubsan_handle_* runtime dep.
fn compile_cc_shims(root: &PathBuf, out: &PathBuf) {
    let target = std::env::var("TARGET").unwrap();
    let is_macos = target.contains("apple-darwin");
    let zig_target = rust_to_zig_target(&target);

    let pf = root.join("third_party/src/perfetto");
    let pf_out = pf.join("out/sismo");
    let csrc = root.join("crates/sismo-sys/csrc");
    let includes = [
        csrc.clone(), // the C shim sources + headers
        pf.join("include"),
        pf.clone(),
        pf.join("buildtools/android-unwinding/libunwindstack/include"),
        pf_out.join("gen"),
        pf_out.join("gen/build_config"),
    ];

    let mut files = vec![
        "sismo_traced.cc",
        "sismo_consumer.cc",
        "sismo_trace_query.cc",
        "perfetto_ds.cc",
    ];
    if !is_macos {
        files.push("sismo_traced_probes.cc"); // Linux traced_probes (ftrace + procfs)
    }

    let mut objs = Vec::new();
    for f in &files {
        let src = csrc.join(f);
        let obj = out.join(format!("{f}.o"));
        let mut cmd = zig_cmd(root, "c++");
        cmd.args(["-target", &zig_target, "-c"]).arg(&src).arg("-o").arg(&obj);
        cmd.args(["-std=c++17", "-fno-exceptions", "-fno-rtti", "-DNDEBUG",
                  "-fno-omit-frame-pointer", "-fno-sanitize=undefined"]);
        if !is_macos {
            cmd.arg("-D_GNU_SOURCE");
        }
        for inc in &includes {
            cmd.arg("-I").arg(inc);
        }
        assert!(cmd.status().expect("run zig c++").success(), "compile {f} failed");
        objs.push(obj);
        println!("cargo:rerun-if-changed={}", src.display());
    }

    // The sample-target TrackEvent shim is C (C11 atomics), so compile it with
    // `zig cc`; it lands in the same archive and links into the sample-target bin.
    {
        let src = csrc.join("sample_target_sdk.c");
        let obj = out.join("sample_target_sdk.c.o");
        let mut cmd = zig_cmd(root, "cc");
        cmd.args(["-target", &zig_target, "-c"]).arg(&src).arg("-o").arg(&obj);
        cmd.args(["-std=c11", "-DNDEBUG", "-fno-omit-frame-pointer", "-fno-sanitize=undefined"]);
        if !is_macos {
            cmd.arg("-D_GNU_SOURCE");
        }
        for inc in &includes {
            cmd.arg("-I").arg(inc);
        }
        assert!(cmd.status().expect("run zig cc").success(), "compile sample_target_sdk.c failed");
        objs.push(obj);
        println!("cargo:rerun-if-changed={}", src.display());
    }

    let lib = out.join("libsismo_cc_shims.a");
    let _ = std::fs::remove_file(&lib);
    let mut ar = zig_cmd(root, "ar");
    ar.arg("rcs").arg(&lib).args(&objs);
    assert!(ar.status().expect("run zig ar").success(), "archive cc shims failed");

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=sismo_cc_shims");
}

/// Map a rustc target triple to the Zig target the pinned toolchain expects.
fn rust_to_zig_target(target: &str) -> String {
    let arch = if target.starts_with("aarch64") { "aarch64" } else { "x86_64" };
    if target.contains("apple-darwin") {
        format!("{arch}-macos")
    } else {
        format!("{arch}-linux-gnu")
    }
}

/// A `python3 tools/zig --hermetic <sub>` command (e.g. sub = "c++" or "ar").
fn zig_cmd(root: &PathBuf, sub: &str) -> Command {
    let mut cmd = Command::new("python3");
    cmd.arg(root.join("tools/zig")).arg("--hermetic").arg(sub);
    cmd
}

/// Build Perfetto's C++ SDK archive + generated headers via tools/build-perfetto.
fn build_perfetto(root: &PathBuf) {
    let status = Command::new("python3")
        .arg(root.join("tools/build-perfetto"))
        .current_dir(root)
        .status()
        .expect("run tools/build-perfetto");
    assert!(status.success(), "perfetto build failed");
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
