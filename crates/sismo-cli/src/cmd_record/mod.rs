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
///
/// `pre_stop` (if any) runs once on the first stop signal, before the workload
/// is terminated — while both the target and the recording are still live.
/// memory.dump uses it to take the heap dump.
fn wait_for_workload_exit(rd: c_int, target_pid: c_int, is_attach: bool, pre_stop: Option<&dyn Fn()>) {
    let mut read_buf = [0u8; 16];
    let mut workload_done = false;
    let mut pre_stop_fired = false;
    while !workload_done {
        let n = unsafe { read(rd, read_buf.as_mut_ptr() as *mut c_void, read_buf.len()) };
        if n <= 0 {
            continue;
        }
        for &b in &read_buf[..n as usize] {
            match b {
                b'I' | b'T' => {
                    let reason = if b == b'I' { "SIGINT" } else { "--duration reached" };
                    if let (Some(hook), false) = (pre_stop, pre_stop_fired) {
                        pre_stop_fired = true;
                        hook();
                    }
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

// ---- memory.dump: the single heap dump at a materialization point -----------
//
// In a `--focus memory.dump` session, each materialization point — record
// stop, `sismo snapshot` — takes exactly one JVM heap dump and bundles it with
// that artifact's trace (which becomes a tar). At record stop the dump must
// fire on the stop *signal*, before the spawned workload is SIGTERMed, so it
// runs via `wait_for_workload_exit`'s pre-stop hook while recording is still
// live (the dump's stop-the-world pause is itself visible in the trace).

/// A dump taken at a materialization point, waiting to be attached to a
/// finished trace by [`finalize_memory_deep_dump`].
pub(crate) struct TakenDump {
    pub tmp_path: String,
    pub runtime: crate::heap_dump::DumpRuntime,
}

/// Take the memory.dump heap dump of `target_pid`, spooling it to a temp file
/// derived from `output_path`. `prefix` labels the log lines ("sismo record" /
/// "sismo snapshot"). Returns the taken dump, ready to finalize once the trace
/// itself is written.
pub(crate) fn take_memory_deep_dump(target_pid: i32, output_path: &str, prefix: &str) -> Option<TakenDump> {
    let alive = unsafe { kill(target_pid, 0) } == 0
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    if !alive {
        eprintln!("{prefix}: memory.dump heap dump skipped — target pid {target_pid} already exited");
        return None;
    }
    let Some(rt) = crate::heap_dump::detect(target_pid) else {
        eprintln!(
            "{prefix}: memory.dump heap dump skipped — no dumpable runtime detected on pid {target_pid} (JVM and Node are supported)"
        );
        return None;
    };
    let tmp_path = format!("{output_path}.heap.{}", rt.ext());
    eprintln!(
        "{prefix}: dumping {} heap (stop-the-world; large heaps pause for seconds)",
        rt.label()
    );
    match crate::heap_dump::take(rt, target_pid, &tmp_path) {
        Some(size) => {
            eprintln!("{prefix}: {} heap dump written ({size} bytes)", rt.label());
            Some(TakenDump { tmp_path, runtime: rt })
        }
        None => {
            eprintln!("{prefix}: {} heap dump failed", rt.label());
            None
        }
    }
}

/// Attach a taken dump to the finished trace at `trace_path`: bundleable
/// artifacts (hprof) turn the trace into a tar; the rest (V8 .heapsnapshot)
/// land as a sibling file next to it. The temp file is consumed either way.
pub(crate) fn finalize_memory_deep_dump(trace_path: &str, dump: &TakenDump, target_pid: i32, prefix: &str) {
    let rt = dump.runtime;
    if rt.bundleable() {
        let member = format!("heap-{target_pid}.{}", rt.ext());
        match crate::tar_bundle::bundle_trace_with_heap_dump(trace_path, &dump.tmp_path, &member) {
            Ok(bytes) => {
                eprintln!("{prefix}: bundled heap dump with the trace into {trace_path} (tar, {bytes} bytes)")
            }
            Err(e) => eprintln!("{prefix}: heap dump bundling failed: {e} — trace left plain"),
        }
        let _ = std::fs::remove_file(&dump.tmp_path);
    } else {
        let sibling = format!("{trace_path}.{}", rt.ext());
        match std::fs::rename(&dump.tmp_path, &sibling) {
            Ok(()) => eprintln!(
                "{prefix}: {} heap dump saved next to the trace: {sibling} (trace_processor has no V8 importer yet; open it in Chrome DevTools)",
                rt.label()
            ),
            Err(e) => eprintln!("{prefix}: failed to place heap dump at {sibling}: {e}"),
        }
    }
}
