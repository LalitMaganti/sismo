// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Host-flip entry: Rust owns `main`. The subcommand logic still lives in Zig
//! (linked as libsismo_zig.a); this rebuilds the process's argv/envp as C
//! arrays and hands them to `zig_sismo_main`, which reconstructs the Zig
//! `std.process.Init` and dispatches (see src/sismo_entry.zig).

// Force the rust-bridge crate to link so its #[no_mangle] exports (the CLI
// dispatch, proc_maps, symbolizer, …) are present to satisfy the Zig staticlib.
use rust_bridge as _;

use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

extern "C" {
    fn zig_sismo_main(
        argc: c_int,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> c_int;
}

fn main() {
    let args: Vec<CString> = std::env::args_os()
        .map(|a| CString::new(a.into_vec()).expect("nul byte in argv"))
        .collect();
    let mut argv: Vec<*const c_char> = args.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());

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

    let code = unsafe { zig_sismo_main(args.len() as c_int, argv.as_ptr(), envp.as_ptr()) };
    std::process::exit(code);
}
