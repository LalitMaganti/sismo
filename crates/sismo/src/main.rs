// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Host entry: Rust owns `main`, routing, and every subcommand. `main` collects
//! argv and hands it to [`sismo_core::command::cli::run`], which dispatches to the
//! matching Rust command.

// Link sismo-sys for its native side effects: its build script compiles + links
// the Perfetto archive and the C/C++ shims this binary calls through the FFI in
// sismo-core. On Linux this rlib also arrives via sismo-core, but sismo-core has
// no sismo-sys dep on macOS, so this direct link is what keeps the shim on the
// link line there.
use sismo_sys as _;

fn main() {
    // args_os + lossy so a non-UTF-8 argument mangles rather than panics.
    let args: Vec<String> = std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    std::process::exit(sismo_core::command::cli::run(&args));
}
