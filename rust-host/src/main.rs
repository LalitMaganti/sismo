// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Host entry: Rust owns `main`, routing, AND every subcommand. `main`
//! extracts the subcommand token, routes it via
//! `rust_bridge::cli::sismo_cli_dispatch`, and invokes the matching Rust
//! subcommand (`sismo_cmd_snapshot` / `_prepare` / `_datasource` /
//! `sismo_run_record_{macos,linux}`) directly with argv — no Zig hop. The Zig
//! staticlib is still linked (the Linux record runner drives the BPF collector
//! over a C ABI), but the process no longer enters through Zig.

// Force rust-bridge to link so its #[no_mangle] exports (dispatch, captures,
// symbolizer, …) satisfy both the direct calls here and the Zig staticlib.
use rust_bridge as _;

use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::os::unix::ffi::OsStringExt;

fn main() {
    let args: Vec<CString> = std::env::args_os()
        .map(|a| CString::new(a.into_vec()).expect("nul byte in argv"))
        .collect();
    let mut argv: Vec<*const c_char> = args.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());

    std::process::exit(dispatch(&args, &argv));
}

/// Route the subcommand (via cli.rs) and invoke the matching Rust command with
/// the full argv. `argv` includes the trailing null; `args.len()` is argc.
fn dispatch(args: &[CString], argv: &[*const c_char]) -> c_int {
    use rust_bridge::cli::{
        sismo_cli_dispatch, SISMO_CLI_DATASOURCE, SISMO_CLI_HANDLED, SISMO_CLI_PREPARE,
        SISMO_CLI_RECORD, SISMO_CLI_SNAPSHOT,
    };

    let argc = args.len();
    let argv_ptr = argv.as_ptr();

    // argv[1] is the subcommand token (or absent).
    let (cmd_ptr, cmd_len) = match args.get(1) {
        Some(c) => {
            let b = c.as_bytes();
            (b.as_ptr(), b.len())
        }
        None => (std::ptr::null(), 0),
    };
    let mut exit_code: i32 = 0;
    let decision = unsafe { sismo_cli_dispatch(cmd_ptr, cmd_len, &mut exit_code) };

    match decision {
        SISMO_CLI_HANDLED => exit_code, // help / unknown-subcommand already printed
        SISMO_CLI_SNAPSHOT => unsafe { rust_bridge::cmd_snapshot::sismo_cmd_snapshot(argc, argv_ptr) },
        SISMO_CLI_PREPARE => unsafe { rust_bridge::cmd_prepare::sismo_cmd_prepare(argc, argv_ptr) },
        SISMO_CLI_DATASOURCE => unsafe { rust_bridge::cmd_datasource::sismo_cmd_datasource(argc, argv_ptr) },
        #[cfg(target_os = "macos")]
        SISMO_CLI_RECORD => unsafe { rust_bridge::cmd_record::sismo_run_record_macos(argc, argv_ptr) },
        #[cfg(target_os = "linux")]
        SISMO_CLI_RECORD => unsafe { rust_bridge::cmd_record::sismo_run_record_linux(argc, argv_ptr) },
        _ => 1,
    }
}
