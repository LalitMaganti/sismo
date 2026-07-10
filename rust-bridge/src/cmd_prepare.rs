// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `sismo prepare` — launch a workload with the sismo dormant heap client (and
//! the well-known producer-socket env) wired in, then `execvp` into the user's
//! command (migrated whole from cmd_prepare.zig). The workload then runs as a
//! normal process; you record it later via `sismo record --pid <pid>`.
//!
//!     sismo prepare ./myapp arg1 arg2 &      # dormant client loaded
//!     sismo record --pid $(pgrep myapp)      # attach + record
//!
//! DYLD_INSERT_LIBRARIES points dyld at libsismo_heap.dylib so the workload
//! loads the dormant client (its constructor binds /tmp/sismo-heap-{pid}.sock
//! and waits for sismo to attach). PERFETTO_PRODUCER_SOCK_NAME points any
//! Perfetto-SDK workload at the well-known producer socket. execvp inherits the
//! env into the user's command.
//!
//! Hardened-runtime caveat (unchanged from the Zig version): macOS strips
//! DYLD_INSERT_LIBRARIES on exec for hardened-runtime / library-validation
//! binaries. Unsigned dev binaries (the audience) are fine; for signed apps heap
//! injection silently fails and the user notices when `sismo record` reports the
//! heap socket missing.
//!
//! POSIX (execvp); cfg-gated off Windows like the rest of the CLI cluster.

use crate::sismo_paths::{resolve_heap_dylib_path, PRODUCER_SOCK};
use std::ffi::CString;
use std::os::raw::{c_char, c_int};

extern "C" {
    fn execvp(file: *const c_char, argv: *const *const c_char) -> c_int;
}

#[derive(clap::Args)]
pub struct PrepareArgs {
    /// The workload command and its arguments. A `--flag` after the command is
    /// passed to the workload, not parsed by sismo.
    #[arg(required = true, trailing_var_arg = true)]
    command: Vec<String>,
}

/// On success this process is replaced by the workload (execvp) and never
/// returns; returns non-zero only on error.
pub fn run(args: PrepareArgs) -> i32 {
    let workload = args.command;

    let heap_dylib = match resolve_heap_dylib_path() {
        Some(p) => p,
        None => {
            eprintln!("sismo prepare: failed to resolve heap dylib path");
            return 0;
        }
    };

    // set_var updates the process environ execvp inherits (on Unix via setenv).
    std::env::set_var("DYLD_INSERT_LIBRARIES", &heap_dylib);
    std::env::set_var("PERFETTO_PRODUCER_SOCK_NAME", PRODUCER_SOCK);

    // Build NUL-terminated argv for execvp.
    let cstrs: Vec<CString> = workload
        .iter()
        .map(|a| CString::new(a.as_str()).unwrap_or_default())
        .collect();
    let mut ptrs: Vec<*const c_char> = cstrs.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());

    // execvp replaces this process; only returns on failure.
    let rc = unsafe { execvp(cstrs[0].as_ptr(), ptrs.as_ptr()) };
    eprintln!("sismo prepare: execvp({}) failed rc={rc}", workload[0]);
    1
}
