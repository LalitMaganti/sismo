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
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

extern "C" {
    fn execvp(file: *const c_char, argv: *const *const c_char) -> c_int;
}

/// What the args say to do.
enum Action<'a> {
    Help,
    NoCommand,
    Run(Vec<&'a str>),
}

/// Parse `sismo prepare`'s args (everything after "prepare"). The first
/// positional is the workload argv[0]; `--help` is only honored as the first
/// token (afterwards it's a workload arg, matching the Zig behavior).
fn parse_prepare<'a>(rest: &[&'a str]) -> Action<'a> {
    if rest.first() == Some(&"--help") {
        return Action::Help;
    }
    if rest.is_empty() {
        return Action::NoCommand;
    }
    Action::Run(rest.to_vec())
}

/// `sismo prepare` subcommand. `argv[0..argc]` are the full process args (exe,
/// "prepare", then the workload command). On success this process is replaced by
/// the workload (execvp) and never returns; returns non-zero only on error.
///
/// # Safety
/// `argv` must point to `argc` valid NUL-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_cmd_prepare(argc: usize, argv: *const *const c_char) -> c_int {
    let args: Vec<&str> = (0..argc)
        .map(|i| unsafe { CStr::from_ptr(*argv.add(i)) }.to_str().unwrap_or(""))
        .collect();
    // Skip argv[0] (exe) + argv[1] ("prepare").
    let rest: &[&str] = if args.len() > 2 { &args[2..] } else { &[] };

    let workload = match parse_prepare(rest) {
        Action::Help => {
            println!(
                "usage: sismo prepare <command> [args...]\n\n  \
                 Launch <command> with sismo's heap-profiler dormant client\n  \
                 preloaded. The launched process can later be recorded via\n  \
                 `sismo record --pid <pid>`."
            );
            return 0;
        }
        Action::NoCommand => {
            eprintln!("sismo prepare: no command specified\nusage: sismo prepare <command> [args...]");
            return 0;
        }
        Action::Run(w) => w,
    };

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
        .map(|a| CString::new(*a).unwrap_or_default())
        .collect();
    let mut ptrs: Vec<*const c_char> = cstrs.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());

    // execvp replaces this process; only returns on failure.
    let rc = unsafe { execvp(cstrs[0].as_ptr(), ptrs.as_ptr()) };
    eprintln!("sismo prepare: execvp({}) failed rc={rc}", workload[0]);
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_as_first_token() {
        assert!(matches!(parse_prepare(&["--help"]), Action::Help));
        assert!(matches!(parse_prepare(&["--help", "extra"]), Action::Help));
    }

    #[test]
    fn empty_is_no_command() {
        assert!(matches!(parse_prepare(&[]), Action::NoCommand));
    }

    #[test]
    fn workload_captured_verbatim() {
        match parse_prepare(&["./app", "-x", "--help"]) {
            // --help after the command is a workload arg, not our flag.
            Action::Run(w) => assert_eq!(w, vec!["./app", "-x", "--help"]),
            _ => panic!("expected Run"),
        }
    }
}
