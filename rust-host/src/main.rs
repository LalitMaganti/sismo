// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Host entry: Rust owns `main`, routing, AND (on macOS) every subcommand.
//!
//! macOS: `main` extracts the subcommand token, routes it via
//! `rust_bridge::cli::sismo_cli_dispatch`, and invokes the matching Rust
//! subcommand (`sismo_cmd_snapshot` / `_prepare` / `_datasource` /
//! `sismo_run_record_macos`) directly with argv — no Zig hop.
//!
//! Linux: the record runner is still Zig (linux_bpf / focus_presets), so `main`
//! hands off to `zig_sismo_main`, which reconstructs the Zig `std.process.Init`
//! and dispatches (unchanged) — including the unified Rust arg parser.

// Force rust-bridge to link so its #[no_mangle] exports (dispatch, captures,
// symbolizer, …) satisfy both the direct calls here and the Zig staticlib.
use rust_bridge as _;

use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

extern "C" {
    fn zig_sismo_main(argc: c_int, argv: *const *const c_char, envp: *const *const c_char) -> c_int;
}

fn main() {
    let args: Vec<CString> = std::env::args_os()
        .map(|a| CString::new(a.into_vec()).expect("nul byte in argv"))
        .collect();
    let mut argv: Vec<*const c_char> = args.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());

    let code = if cfg!(target_os = "macos") {
        dispatch(&args, &argv)
    } else {
        // Linux: the record runner is still Zig; go through the Zig entry.
        let envs: Vec<CString> = std::env::vars_os()
            .map(|(k, v)| {
                let mut kv = k.into_vec();
                kv.push(b'=');
                kv.extend_from_slice(v.as_bytes());
                CString::new(kv).expect("nul byte in env")
            })
            .collect();
        let mut envp: Vec<*const c_char> = envs.iter().map(|e| e.as_ptr()).collect();
        envp.push(std::ptr::null());
        unsafe { zig_sismo_main(args.len() as c_int, argv.as_ptr(), envp.as_ptr()) }
    };
    std::process::exit(code);
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
        _ => 1,
    }
}
