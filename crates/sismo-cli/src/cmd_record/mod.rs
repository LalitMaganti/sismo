// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `sismo record` — the unified recorder.
//!
//! This module holds the POSIX skeleton both platform runners share: workload
//! spawn (posix_spawnp with env overrides), the SIGINT self-pipe, the
//! workload-exit / --duration watch threads, the start banner, and early
//! teardown. The per-platform flows — which data sources exist, how the
//! workload is acquired, and how captures shut down — live in [`linux`] and
//! [`macos`], each gated once here.
//!
//! The service + consumer session are the C++ shim (permanent); the captures,
//! configs, session lock, and marker are Rust siblings (direct calls).
//! Validated by `sudo tools/e2e-all-sources`.

use crate::record_args::RecordArgs;
use sismo_core::ffi::{sismo_traced_destroy, sismo_traced_stop, TracedSvc};
use sismo_core::sismo_paths::release_session_lock;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::sync::atomic::{AtomicI32, Ordering};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

// ---- libc ------------------------------------------------------------------

use libc::timespec as Timespec;
use libc::{kill, nanosleep, posix_spawnp, read, waitpid, write, SIGTERM};

// posix_spawnp inherits the current environment. The libc crate does not export
// `environ`, so declare it directly.
extern "C" {
    static environ: *const *const c_char;
}

// ---- Entry point -----------------------------------------------------------

/// `sismo record` entry. Resolves the args, then runs the platform flow.
pub fn run(args: RecordArgs) -> i32 {
    let config = match args.resolve() {
        Ok(c) => c,
        Err(code) => return code, // message already printed
    };
    #[cfg(target_os = "macos")]
    {
        macos::run(&config)
    }
    #[cfg(target_os = "linux")]
    {
        linux::run(&config)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = config;
        eprintln!("sismo record: not supported on this platform");
        1
    }
}

// ---- Self-pipe (SIGINT handler → main loop) --------------------------------

static SIGINT_PIPE_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn handle_sigint(_sig: c_int) {
    let fd = SIGINT_PIPE_FD.load(Ordering::Acquire);
    if fd >= 0 {
        let b = b"I";
        unsafe { write(fd, b.as_ptr() as *const c_void, 1) };
    }
}

// ---- Workload spawn --------------------------------------------------------

/// posix_spawnp `path` with `args` (its argv[1..]) after applying `env`
/// overrides. Returns the child pid, or None on failure.
fn maybe_spawn(path: &str, args: &[&str], env: &[(&str, &str)]) -> Option<i32> {
    for (k, v) in env {
        std::env::set_var(k, v);
    }
    let path_c = CString::new(path).ok()?;
    let mut argv_c: Vec<CString> = Vec::with_capacity(args.len() + 1);
    argv_c.push(path_c.clone());
    for a in args {
        argv_c.push(CString::new(*a).ok()?);
    }
    let mut argv: Vec<*const c_char> = argv_c.iter().map(|c| c.as_ptr()).collect();
    argv.push(std::ptr::null());

    let mut pid: c_int = 0;
    let rc = unsafe {
        posix_spawnp(
            &mut pid,
            path_c.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            argv.as_ptr() as *const *mut c_char,
            environ as *const *mut c_char,
        )
    };
    if rc != 0 {
        eprintln!("sismo record: posix_spawnp({path}) rc={rc}");
        return None;
    }
    Some(pid)
}

// ---- Exit / duration watch threads (write one byte to the self-pipe) -------

fn watchpipe_write(fd: c_int, byte: u8) {
    let b = [byte];
    unsafe { write(fd, b.as_ptr() as *const c_void, 1) };
}

/// Spawn-mode: block on waitpid for the owned child, then fire 'X'.
fn waitpid_exit_watch(pid: c_int, write_fd: c_int) {
    unsafe { waitpid(pid, std::ptr::null_mut(), 0) };
    watchpipe_write(write_fd, b'X');
}

/// Block on the self-pipe `rd` until the workload exits ('X') or a stop signal
/// arrives ('I' SIGINT / 'T' --duration). For a spawned workload a stop signal
/// SIGTERMs it and the loop keeps waiting for its 'X'; for an attached pid it
/// just ends recording, leaving the target running.
fn wait_for_workload_exit(rd: c_int, target_pid: c_int, is_attach: bool) {
    let mut read_buf = [0u8; 16];
    let mut workload_done = false;
    while !workload_done {
        let n = unsafe { read(rd, read_buf.as_mut_ptr() as *mut c_void, read_buf.len()) };
        if n <= 0 {
            continue;
        }
        for &b in &read_buf[..n as usize] {
            match b {
                b'I' | b'T' => {
                    let reason = if b == b'I' { "SIGINT" } else { "--duration reached" };
                    if is_attach {
                        eprintln!("sismo record: {reason} — stopping recording (attached pid={target_pid} keeps running)");
                        workload_done = true;
                    } else {
                        eprintln!("sismo record: {reason} — sending SIGTERM to workload pid={target_pid}");
                        unsafe { kill(target_pid, SIGTERM) };
                    }
                }
                b'X' => workload_done = true,
                _ => {}
            }
        }
    }
}

/// Print the "recording started" banner, spelling out how the trace is captured
/// and how to stop, for the default rolling-buffer mode vs. `--long-trace`.
fn print_start_banner(long_trace: bool, buffer_kb: u32, output_path: &str) {
    if long_trace {
        eprintln!(
            "sismo record: recording — long-trace: streaming continuously to {output_path}\n  \
             stop & finalize:   Ctrl-C (or workload exit)"
        );
    } else {
        let buffer_mb = buffer_kb / 1024;
        eprintln!(
            "sismo record: recording — rolling {buffer_mb} MB buffer; trace written to {output_path} on stop\n  \
             snapshot anytime:  sismo snapshot\n  \
             stop & save:       Ctrl-C (or workload exit)\n  \
             long full runs:    re-run with --long-trace to stream continuously to disk"
        );
    }
}

/// --duration timer: sleep `seconds` (looping over EINTR) then fire 'T'.
fn duration_timer(seconds: c_uint, write_fd: c_int) {
    let mut remaining = Timespec { tv_sec: seconds as i64, tv_nsec: 0 };
    while remaining.tv_sec > 0 || remaining.tv_nsec > 0 {
        let mut rem = Timespec { tv_sec: 0, tv_nsec: 0 };
        if unsafe { nanosleep(&remaining, &mut rem) } == 0 {
            break;
        }
        remaining = rem;
    }
    watchpipe_write(write_fd, b'T');
}

/// Teardown for the early-return paths (before the session/pipe exist).
fn teardown_early(svc: *mut TracedSvc, lock_fd: c_int) {
    unsafe {
        sismo_traced_stop(svc);
        sismo_traced_destroy(svc);
    }
    release_session_lock(lock_fd);
}
