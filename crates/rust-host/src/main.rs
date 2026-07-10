// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Host entry: Rust owns `main`, routing, and every subcommand. `main` collects
//! argv and hands it to [`rust_bridge::cli::run`], which dispatches to the
//! matching Rust command.

fn main() {
    // args_os + lossy so a non-UTF-8 argument mangles rather than panics.
    let args: Vec<String> = std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    std::process::exit(rust_bridge::cli::run(&args));
}
