// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `sismo record` — the unified recorder (macOS + Linux runners).
//!
//! Parses args (record_args), acquires the workload (spawn
//! with the heap-preload DYLD-inserted, or attach to a prepared pid), embeds
//! the Perfetto `traced` service, registers the in-process capture workers
//! (already-Rust sched/cpu/heap), builds + starts a consumer session, then
//! blocks on a self-pipe fed by a SIGINT handler / a workload-exit watch thread
//! (waitpid for spawned, kqueue NOTE_EXIT for attached) / an optional
//! --duration timer, and finally stops the session, writes the privileged
//! marker, and tears everything down.
//!
//! The service + consumer session are the C++ shim (permanent); the captures,
//! configs, session lock, and marker are Rust siblings (direct calls).
//!
//! macOS-only; gated in lib.rs. Validated by `sudo tools/e2e-all-sources`.

#[cfg(target_os = "macos")]
use sismo_core::proto::{ProtoReader, WireValue};
use crate::record_args::{RecordArgs, RecordConfig, SourceMode};
use sismo_core::proto::session_config::{encode_trace_config, DataSourceEntry, MODE_FILE, MODE_RING};
#[cfg(target_os = "macos")]
use sismo_core::proto::sismo_config;
use sismo_core::sismo_paths::{
    acquire_session_lock, release_session_lock, LockError, CONSUMER_SOCK, PRODUCER_SOCK,
};
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::sync::atomic::{AtomicI32, Ordering};

// Capture workers (Rust siblings, macOS in-process sources).
#[cfg(target_os = "macos")]
use sismo_core::cpu::macos_cpu_capture::CpuCapture;
#[cfg(target_os = "macos")]
use sismo_core::heap::macos_heap_capture::HeapCapture;
#[cfg(target_os = "macos")]
use sismo_core::sched::macos_sched_capture::SchedCapture;

// ---- C++ shim (traced service + consumer session + producer init) ----------

use sismo_core::ffi::{
    sismo_consumer_session_create, sismo_consumer_session_destroy, sismo_consumer_session_setup,
    sismo_consumer_session_start_blocking, sismo_consumer_session_stop_blocking, sismo_init,
    sismo_traced_create, sismo_traced_destroy, sismo_traced_stop, TracedSvc,
};
// Only the macOS runner queries service state (waiting on external sources).
#[cfg(target_os = "macos")]
use sismo_core::ffi::{sismo_consumer_query_service_state, ConsumerSession};

use crate::privileged_marker::append_privileged_marker;

// ---- libc ------------------------------------------------------------------

use libc::timespec as Timespec;
use libc::{
    close, getpid, kill, nanosleep, pipe, posix_spawnp, read, signal, unlink, waitpid, write,
    SIGINT, SIGTERM,
};

// posix_spawnp inherits the current environment. The libc crate does not export
// `environ`, so declare it directly.
extern "C" {
    static environ: *const *const c_char;
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

/// Attach-mode: kqueue EVFILT_PROC/NOTE_EXIT on a non-child pid, then fire 'X'.
#[cfg(target_os = "macos")]
fn kqueue_exit_watch(pid: c_int, write_fd: c_int) {
    use libc::{kevent, kqueue, EVFILT_PROC, EV_ADD, EV_ONESHOT, NOTE_EXIT};
    let kq = unsafe { kqueue() };
    if kq < 0 {
        return; // no kqueue — loop only stops on SIGINT / --duration
    }
    let mut change = libc::kevent {
        ident: pid as usize,
        filter: EVFILT_PROC,
        flags: EV_ADD | EV_ONESHOT,
        fflags: NOTE_EXIT,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    let mut ev = libc::kevent {
        ident: 0,
        filter: 0,
        flags: 0,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    // Register; if the pid is already gone (ESRCH) treat as already-exited.
    if unsafe { kevent(kq, &change, 1, &mut ev, 0, std::ptr::null()) } < 0 {
        watchpipe_write(write_fd, b'X');
        unsafe { close(kq) };
        return;
    }
    // Block until NOTE_EXIT fires.
    unsafe { kevent(kq, &mut change, 0, &mut ev, 1, std::ptr::null()) };
    watchpipe_write(write_fd, b'X');
    unsafe { close(kq) };
}

/// Block on the self-pipe `rd` until the workload exits ('X') or a stop signal
/// arrives ('I' SIGINT / 'T' --duration). For a spawned workload a stop signal
/// SIGTERMs it and the loop keeps waiting for its 'X'; for an attached pid it
/// just ends recording, leaving the target running.
#[cfg(any(target_os = "linux", target_os = "macos"))]
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
#[cfg(any(target_os = "linux", target_os = "macos"))]
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

// ---- External-producer wait (QueryServiceState proto walk) -----------------

/// Call `cb` for each `data_sources[*].ds_descriptor.name` in a
/// TracingServiceState proto. Schema path: field 2 (DataSource) → field 1
/// (DataSourceDescriptor) → field 1 (name). Uses the reusable ProtoReader, so
/// it's a declarative walk rather than hand-rolled varint parsing.
#[cfg(target_os = "macos")]
fn for_each_registered_data_source(bytes: &[u8], mut cb: impl FnMut(&[u8])) {
    for (field, val) in ProtoReader::new(bytes) {
        let WireValue::Len(ds) = val else { continue };
        if field != 2 {
            continue;
        }
        for (field, val) in ProtoReader::new(ds) {
            let WireValue::Len(desc) = val else { continue };
            if field != 1 {
                continue;
            }
            for (field, val) in ProtoReader::new(desc) {
                if let (1, WireValue::Len(name)) = (field, val) {
                    cb(name);
                }
            }
        }
    }
}

/// Poll QueryServiceState until every `expected` name is registered, or
/// `timeout_ms` elapses. Polls every 100 ms.
#[cfg(target_os = "macos")]
fn wait_for_external_data_sources(session: *mut ConsumerSession, expected: &[&str], timeout_ms: u64) -> bool {
    if expected.is_empty() {
        return true;
    }
    let mut buf = vec![0u8; 16 * 1024];
    let mut elapsed_ms: u64 = 0;
    let poll_ms: u64 = 100;
    loop {
        let mut written: usize = 0;
        let rc = unsafe {
            sismo_consumer_query_service_state(session, buf.as_mut_ptr() as *mut c_void, buf.len(), &mut written)
        };
        if rc == 0 {
            let mut seen = vec![false; expected.len()];
            for_each_registered_data_source(&buf[..written], |name| {
                for (idx, want) in expected.iter().enumerate() {
                    if want.as_bytes() == name {
                        seen[idx] = true;
                    }
                }
            });
            if seen.iter().all(|&s| s) {
                return true;
            }
        }
        if elapsed_ms >= timeout_ms {
            return false;
        }
        let ts = Timespec { tv_sec: 0, tv_nsec: (poll_ms * 1_000_000) as i64 };
        unsafe { nanosleep(&ts, std::ptr::null_mut()) };
        elapsed_ms += poll_ms;
    }
}

// ---- Entry point -----------------------------------------------------------

/// `sismo record` on macOS. `argv[0..argc]` are the full process args. Parses
/// `sismo record` entry. Resolves the args, then runs the platform flow.
pub fn run(args: RecordArgs) -> i32 {
    let config = match args.resolve() {
        Ok(c) => c,
        Err(code) => return code, // message already printed
    };
    #[cfg(target_os = "macos")]
    {
        run_macos_flow(&config)
    }
    #[cfg(target_os = "linux")]
    {
        run_linux(&config)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = config;
        eprintln!("sismo record: not supported on this platform");
        1
    }
}

#[cfg(target_os = "macos")]
fn run_macos_flow(config: &RecordConfig) -> c_int {
    let output: String = config.output.clone().unwrap_or_else(crate::trace_sink::timestamped_output_path);
    let output_path_str: &str = &output;
    let output_c = CString::new(output.as_str()).unwrap_or_default();
    let attach_pid: Option<i32> = config.attach_pid;
    let duration_secs: Option<c_uint> = config.duration_secs;
    let long_trace = config.long_trace;
    let buffer_kb = config.buffer_kb;
    let (sched_mode, cpu_mode, heap_mode) = (config.sched_mode, config.cpu_mode, config.heap_mode);
    let no_instrumentation = config.no_instrumentation;

    // Attach sanity check.
    if let Some(pid) = attach_pid {
        if unsafe { kill(pid, 0) } != 0 {
            eprintln!("sismo record: pid {pid} not found (or not signalable)");
            return 0;
        }
    }

    // Privilege warning for in-process privileged sources.
    if unsafe { libc::geteuid() } != 0 {
        let mut unmet: Vec<&str> = Vec::new();
        if sched_mode == SourceMode::InProcess {
            unmet.push("sched");
        }
        if cpu_mode == SourceMode::InProcess {
            unmet.push("cpu");
        }
        if heap_mode == SourceMode::InProcess {
            unmet.push("heap");
        }
        if !unmet.is_empty() {
            eprintln!("sismo record: WARNING — running unprivileged. The following data\n  sources need root and will fail to capture:");
            for n in &unmet {
                eprintln!("    {n}");
            }
            eprintln!(
                "  options:\n    1. re-run with `sudo`     (simple — everything in one process as root)\n    2. pass --external-{{X}}    + run `sudo sismo datasource X` in another\n                                  shell (or --all-external + `sudo sismo\n                                  datasource all-privileged`)\n    3. pass --no-{{X}}          to skip the data source silently"
            );
        }
    }

    // Single-session lock (held for the recording's lifetime).
    let lock_fd = match acquire_session_lock(unsafe { getpid() }) {
        Ok(fd) => fd,
        Err(LockError::Held) => {
            eprintln!("sismo record: another sismo session is already running (lock held on /tmp/sismo.lock)");
            return 0;
        }
        Err(LockError::Open) => {
            eprintln!("sismo record: failed to open session lock at /tmp/sismo.lock");
            return 0;
        }
    };

    let my_pid = unsafe { getpid() };
    eprintln!(
        "sismo record: pid={my_pid} output={output_path_str}\n  producer sock: {PRODUCER_SOCK}\n  consumer sock: {CONSUMER_SOCK}"
    );
    std::env::set_var("PERFETTO_PRODUCER_SOCK_NAME", PRODUCER_SOCK);
    std::env::set_var("PERFETTO_CONSUMER_SOCK_NAME", CONSUMER_SOCK);

    // Embed traced + init the producer client.
    let prod_c = CString::new(PRODUCER_SOCK).unwrap();
    let cons_c = CString::new(CONSUMER_SOCK).unwrap();
    let svc = unsafe { sismo_traced_create(prod_c.as_ptr(), cons_c.as_ptr()) };
    if svc.is_null() {
        eprintln!("sismo record: traced_create failed");
        release_session_lock(lock_fd);
        return 0;
    }
    unsafe { sismo_init(prod_c.as_ptr()) };

    // Acquire the workload: attach, or spawn with the heap-preload DYLD-inserted.
    let target_pid: i32 = match attach_pid {
        Some(pid) => {
            eprintln!("sismo record: attaching to pid={pid}");
            pid
        }
        None => {
            let heap_dylib = match sismo_core::sismo_paths::resolve_heap_dylib_path() {
                Some(p) => p,
                None => {
                    eprintln!("sismo record: failed to resolve heap dylib path");
                    teardown_early(svc, lock_fd);
                    return 0;
                }
            };
            let workload_cmd = config.workload[0].as_str();
            let workload_args: Vec<&str> = config.workload[1..].iter().map(String::as_str).collect();
            let pid = match maybe_spawn(
                workload_cmd,
                &workload_args,
                &[
                    ("DYLD_INSERT_LIBRARIES", &heap_dylib),
                    ("PERFETTO_PRODUCER_SOCK_NAME", PRODUCER_SOCK),
                ],
            ) {
                Some(p) => p,
                None => {
                    eprintln!("sismo record: failed to spawn '{workload_cmd}' — exiting");
                    teardown_early(svc, lock_fd);
                    return 0;
                }
            };
            eprintln!("sismo record: spawned '{workload_cmd}' pid={pid}");
            // Give the target a beat to come up + create its heap socket.
            let ts = Timespec { tv_sec: 0, tv_nsec: 200 * 1_000_000 };
            unsafe { nanosleep(&ts, std::ptr::null_mut()) };
            pid
        }
    };

    // Capture workers (in-process only).
    let mut sched: Option<Box<SchedCapture>> = if sched_mode == SourceMode::InProcess {
        let c = SchedCapture::start();
        if c.is_none() {
            eprintln!("sismo record: sched capture init failed");
        }
        c
    } else {
        None
    };
    let mut cpu: Option<Box<CpuCapture>> = if cpu_mode == SourceMode::InProcess {
        let c = CpuCapture::start(0);
        if c.is_none() {
            eprintln!("sismo record: cpu capture init failed");
        }
        c
    } else {
        None
    };
    let mut heap: Option<Box<HeapCapture>> = if heap_mode == SourceMode::InProcess {
        // In attach mode, heap needs the target prepared (its socket exists).
        let ok = match attach_pid {
            Some(pid) => {
                let mut sock_buf = [0u8; 128];
                let has_socket = match sismo_core::heap::heap_protocol::socket_path(pid, &mut sock_buf) {
                    Some(len) => {
                        sock_buf[len] = 0;
                        unsafe { libc::access(sock_buf.as_ptr() as *const c_char, 0) == 0 } // F_OK
                    }
                    None => false,
                };
                if !has_socket {
                    eprintln!("sismo record: target pid={pid} not prepared (no heap socket); heap disabled — relaunch via `sismo prepare` to enable heap");
                }
                has_socket
            }
            None => true,
        };
        if ok {
            let c = HeapCapture::start();
            if c.is_none() {
                eprintln!("sismo record: heap capture init failed");
            }
            c
        } else {
            None
        }
    } else {
        None
    };

    // Per-DS sismo configs (field 2000 of each DataSourceConfig).
    let cpu_cfg = sismo_config::cpu_encode(target_pid as u32, 0);
    let heap_cfg = sismo_config::heap_encode(target_pid as u32, 0, 0);
    // target_pid enables kperf lazy.wait off-CPU capture on the shared kdebug
    // session; threshold 0 lets the worker pick its default.
    let sched_cfg = sismo_config::sched_encode(0, target_pid as u32, 0);

    // Build the entries + external-name list.
    let mut entries: Vec<DataSourceEntry> = Vec::new();
    let mut external_names: Vec<&str> = Vec::new();
    if !no_instrumentation {
        entries.push(DataSourceEntry::track_event());
    }
    if heap.is_some() || heap_mode == SourceMode::External {
        entries.push(DataSourceEntry::sismo_vendor(b"sismo.heap", &heap_cfg, 0));
        if heap_mode == SourceMode::External {
            external_names.push("sismo.heap");
        }
    }
    if cpu.is_some() || cpu_mode == SourceMode::External {
        entries.push(DataSourceEntry::sismo_vendor(b"sismo.macos_cpu_samples", &cpu_cfg, 0));
        if cpu_mode == SourceMode::External {
            external_names.push("sismo.macos_cpu_samples");
        }
    }
    if sched.is_some() || sched_mode == SourceMode::External {
        // ProtoVM DST for GenericKernelProcessTree.
        entries.push(DataSourceEntry::sismo_vendor(b"sismo.macos_sched", &sched_cfg, 4 * 1024));
        // The sched worker also registers the off-CPU PerfSample DS; enable it so
        // its packets are captured (it only emits when target_pid is set).
        entries.push(DataSourceEntry::sismo_vendor(b"sismo.macos_offcpu", &[], 0));
        if sched_mode == SourceMode::External {
            external_names.push("sismo.macos_sched");
            external_names.push("sismo.macos_offcpu");
        }
    }
    if entries.is_empty() {
        eprintln!("sismo record: no data sources enabled — recording would be empty. Drop one of the --no-* flags.");
        shutdown_captures(&mut heap, &mut cpu, &mut sched);
        teardown_early(svc, lock_fd);
        return 0;
    }

    // --long-trace streams straight to the file, so pre-clear it. The default
    // ring mode writes the file only on exit (a clone, which truncates).
    if long_trace {
        unsafe { unlink(output_c.as_ptr()) };
    }
    let out_path: &[u8] = if long_trace { output_path_str.as_bytes() } else { b"" };
    let session_name = b"sismo_record";
    let cfg = encode_trace_config(
        if long_trace { MODE_FILE } else { MODE_RING }, // stream-to-file : rolling ring
        buffer_kb,
        0,
        out_path,
        1024 * 1024 * 1024,
        session_name,
        &entries,
    );
    let session = unsafe { sismo_consumer_session_create() };
    if session.is_null() {
        eprintln!("sismo record: session_create failed");
        shutdown_captures(&mut heap, &mut cpu, &mut sched);
        teardown_early(svc, lock_fd);
        return 0;
    }
    let setup_rc = unsafe { sismo_consumer_session_setup(session, cfg.as_ptr() as *const c_void, cfg.len()) };
    if setup_rc != 0 {
        eprintln!("sismo record: session_setup rc={setup_rc} (TraceConfig failed to parse)");
        unsafe { sismo_consumer_session_destroy(session) };
        shutdown_captures(&mut heap, &mut cpu, &mut sched);
        teardown_early(svc, lock_fd);
        return 0;
    }

    // Wait for external sidecar producers to register before starting.
    if !external_names.is_empty() {
        eprintln!(
            "sismo record: waiting up to 5s for external producers ({}) — start them with `sudo sismo datasource ...`",
            external_names.len()
        );
        if !wait_for_external_data_sources(session, &external_names, 5_000) {
            eprintln!("sismo record: timed out waiting for external producer(s):");
            for n in &external_names {
                eprintln!("    {n}");
            }
            eprintln!("  start a sidecar with `sudo sismo datasource <name>` (or `all-privileged`) and re-run.");
            unsafe { sismo_consumer_session_destroy(session) };
            shutdown_captures(&mut heap, &mut cpu, &mut sched);
            teardown_early(svc, lock_fd);
            return 0;
        }
    }

    unsafe { sismo_consumer_session_start_blocking(session) };
    print_start_banner(long_trace, buffer_kb, output_path_str);

    // Self-pipe + watch threads.
    let mut pipe_fds = [0 as c_int; 2];
    if unsafe { pipe(pipe_fds.as_mut_ptr()) } != 0 {
        eprintln!("sismo record: pipe() failed");
        unsafe { sismo_consumer_session_destroy(session) };
        shutdown_captures(&mut heap, &mut cpu, &mut sched);
        teardown_early(svc, lock_fd);
        return 0;
    }
    let (rd, wr) = (pipe_fds[0], pipe_fds[1]);
    SIGINT_PIPE_FD.store(wr, Ordering::Release);
    unsafe { signal(SIGINT, handle_sigint as extern "C" fn(c_int) as libc::sighandler_t) };

    let is_attach = attach_pid.is_some();
    let watch = std::thread::spawn(move || {
        if is_attach {
            kqueue_exit_watch(target_pid, wr);
        } else {
            waitpid_exit_watch(target_pid, wr);
        }
    });
    // --duration timer (detached; may write to a closed pipe later — harmless).
    if let Some(secs) = duration_secs {
        std::thread::spawn(move || duration_timer(secs, wr));
    }

    wait_for_workload_exit(rd, target_pid, is_attach);

    if long_trace {
        // Streaming mode: traced already wrote the file; stop finalizes it.
        unsafe { sismo_consumer_session_stop_blocking(session) };
        eprintln!("sismo record: saved {output_path_str}");
        if !append_privileged_marker(output_path_str, &[target_pid], None, false) {
            eprintln!("sismo record: failed to write privileged marker");
        }
    } else {
        // Rolling-buffer mode: clone the live session to the file (the clone
        // flushes the capture workers, exactly like `sismo snapshot`), then stop.
        eprintln!("sismo record: stopping — writing trace to {output_path_str}");
        match crate::trace_sink::clone_session_to_file("sismo_record", output_path_str) {
            Ok(bytes) => {
                eprintln!("sismo record: saved {output_path_str} ({bytes} bytes)");
                if !append_privileged_marker(output_path_str, &[target_pid], None, false) {
                    eprintln!("sismo record: failed to write privileged marker");
                }
            }
            Err(e) => eprintln!("sismo record: failed to write trace: {e}"),
        }
        unsafe { sismo_consumer_session_stop_blocking(session) };
    }

    // Capture shutdowns (with stats).
    shutdown_captures(&mut heap, &mut cpu, &mut sched);

    // Join the exit watcher (it has fired 'X' or is about to), then tear down.
    let _ = watch.join();
    unsafe { sismo_consumer_session_destroy(session) };
    SIGINT_PIPE_FD.store(-1, Ordering::Release);
    unsafe {
        close(rd);
        close(wr);
    }
    unsafe { sismo_traced_stop(svc) };
    unsafe { sismo_traced_destroy(svc) };
    release_session_lock(lock_fd);
    0
}

/// Shut down whichever captures are present, printing per-source stats. Takes
/// each handle out with `Option::take`, so calling it again is a no-op — the
/// error paths and the final teardown can all call it.
#[cfg(target_os = "macos")]
fn shutdown_captures(
    heap: &mut Option<Box<HeapCapture>>,
    cpu: &mut Option<Box<CpuCapture>>,
    sched: &mut Option<Box<SchedCapture>>,
) {
    if let Some(c) = heap.take() {
        let s = c.shutdown();
        eprintln!("sismo record: heap — {} records, ~{} bytes, {} sites", s.records, s.bytes_alloc, s.sites);
    }
    if let Some(c) = cpu.take() {
        let s = c.shutdown();
        eprintln!("sismo record: cpu — {} samples ({} active)", s.samples, s.active_samples);
    }
    if let Some(c) = sched.take() {
        let s = c.shutdown();
        eprintln!(
            "sismo record: sched — {} events emitted across {} drains, {} off-CPU samples",
            s.events_emitted, s.drain_calls, s.offcpu_samples
        );
    }
}

/// Teardown for the early-return paths (before the session/pipe exist).
fn teardown_early(svc: *mut TracedSvc, lock_fd: c_int) {
    unsafe {
        sismo_traced_stop(svc);
        sismo_traced_destroy(svc);
    }
    release_session_lock(lock_fd);
}

// ---- Linux record runner ---------------------------------------------------

#[cfg(target_os = "linux")]
use sismo_core::ffi::{sismo_traced_probes_create, sismo_traced_probes_destroy, sismo_traced_probes_stop};

#[cfg(target_os = "linux")]
use sismo_core::cpu::linux_bpf_capture::{self, Capture, FocusPreset};


#[cfg(target_os = "linux")]
fn run_linux(config: &RecordConfig) -> c_int {
    let output: String = config.output.clone().unwrap_or_else(crate::trace_sink::timestamped_output_path);
    let output_path_str: &str = &output;
    let output_c = CString::new(output.as_str()).unwrap_or_default();
    let duration_secs = config.duration_secs;
    let long_trace = config.long_trace;
    let buffer_kb = config.buffer_kb;
    let no_sched = config.sched_mode == SourceMode::Off;
    let no_cpu = config.cpu_mode == SourceMode::Off;
    let no_instrumentation = config.no_instrumentation;
    let sample_density = config.sample_density;

    // Resolve --focus (only "cache" today); unknown = hard error.
    let focus_int: i32 = match config.focus.as_deref() {
        None => -1,
        Some("cache") => 0,
        Some(other) => {
            eprintln!("sismo record: unknown focus preset '{other}' (supported: cache)");
            return 0;
        }
    };

    let lock_fd = match acquire_session_lock(unsafe { getpid() }) {
        Ok(fd) => fd,
        Err(LockError::Held) => {
            eprintln!("sismo record: another sismo session is already running (lock held on /tmp/sismo.lock)");
            return 0;
        }
        Err(LockError::Open) => {
            eprintln!("sismo record: failed to open session lock at /tmp/sismo.lock");
            return 0;
        }
    };

    eprintln!(
        "sismo record: pid={} output={output_path_str}\n  producer sock: {PRODUCER_SOCK}\n  consumer sock: {CONSUMER_SOCK}",
        unsafe { getpid() }
    );
    std::env::set_var("PERFETTO_PRODUCER_SOCK_NAME", PRODUCER_SOCK);
    std::env::set_var("PERFETTO_CONSUMER_SOCK_NAME", CONSUMER_SOCK);

    // Embed traced + init the producer client.
    let prod_c = CString::new(PRODUCER_SOCK).unwrap();
    let cons_c = CString::new(CONSUMER_SOCK).unwrap();
    let svc = unsafe { sismo_traced_create(prod_c.as_ptr(), cons_c.as_ptr()) };
    if svc.is_null() {
        eprintln!("sismo record: traced_create failed");
        release_session_lock(lock_fd);
        return 0;
    }
    unsafe { sismo_init(prod_c.as_ptr()) };

    // traced_probes (ftrace + procfs) — the sched producer. Skipped by --no-sched.
    let probes = if no_sched {
        std::ptr::null_mut()
    } else {
        let p = unsafe { sismo_traced_probes_create(prod_c.as_ptr()) };
        if p.is_null() {
            eprintln!("sismo record: traced_probes attach failed — sched events disabled");
        }
        p
    };
    let stop_probes = |probes: *mut c_void| {
        if !probes.is_null() {
            unsafe {
                sismo_traced_probes_stop(probes);
                sismo_traced_probes_destroy(probes);
            }
        }
    };

    // Spawn the workload (Linux rejects --pid, so a workload is always present).
    // No DYLD insert — Linux heap preload is a separate pillar.
    let workload_cmd = config.workload[0].as_str();
    let workload_args: Vec<&str> = config.workload[1..].iter().map(String::as_str).collect();
    let target_pid = match maybe_spawn(
        workload_cmd,
        &workload_args,
        &[("PERFETTO_PRODUCER_SOCK_NAME", PRODUCER_SOCK)],
    ) {
        Some(p) => p,
        None => {
            eprintln!("sismo record: failed to spawn '{workload_cmd}' — exiting");
            stop_probes(probes);
            teardown_early(svc, lock_fd);
            return 0;
        }
    };
    eprintln!("sismo record: spawned '{workload_cmd}' pid={target_pid}");

    // BPF CPU collector (per-thread counters + stack sampling), scoped to the
    // workload. Drains on its own worker thread; shut down on the way out.
    let mut bpf: Option<Box<Capture>> = if no_cpu {
        None
    } else {
        let focus = if focus_int == 0 { Some(FocusPreset::Cache) } else { None };
        let c = linux_bpf_capture::init(target_pid as u32, focus, sample_density);
        if c.is_none() {
            eprintln!("sismo record: bpf capture init failed — CPU samples disabled");
        }
        c
    };
    let had_bpf = bpf.is_some();
    let shutdown_bpf = |bpf: Option<Box<Capture>>| -> u8 {
        let Some(c) = bpf else {
            return 0;
        };
        let precise = c.precise_ip();
        let s = c.shutdown();
        eprintln!(
            "sismo record: bpf — {} samples across {} threads (busiest {} cycles)",
            s.samples, s.threads, s.busiest_cycles
        );
        if s.data_frames > 0 {
            eprintln!(
                "sismo record: cache — {} of {} samples carry a data-region frame",
                s.data_frames, s.samples
            );
        }
        if s.offcpu_samples > 0 {
            eprintln!(
                "sismo record: off-CPU — {} blocking stacks, {} ms total off-CPU",
                s.offcpu_samples,
                s.offcpu_ns / 1_000_000
            );
        }
        precise
    };

    // Data source entries.
    let mut entries: Vec<DataSourceEntry> = Vec::new();
    if !no_instrumentation {
        entries.push(DataSourceEntry::track_event());
    }
    if !probes.is_null() {
        entries.push(DataSourceEntry::linux_ftrace());
    }
    if had_bpf {
        entries.push(DataSourceEntry::sismo_vendor(b"sismo.linux_cpu_samples", b"", 0));
    }
    if entries.is_empty() {
        eprintln!("sismo record: no data sources enabled — recording would be empty. Drop one of the --no-* flags.");
        shutdown_bpf(bpf.take());
        stop_probes(probes);
        teardown_early(svc, lock_fd);
        return 0;
    }

    // --long-trace streams straight to the file, so pre-clear it. The default
    // ring mode writes the file only on exit (a clone, which truncates).
    if long_trace {
        unsafe { unlink(output_c.as_ptr()) };
    }
    let out_path: &[u8] = if long_trace { output_path_str.as_bytes() } else { b"" };
    let session_name = b"sismo_record";
    let cfg = encode_trace_config(
        if long_trace { MODE_FILE } else { MODE_RING },
        buffer_kb,
        0,
        out_path,
        1024 * 1024 * 1024,
        session_name,
        &entries,
    );
    let session = unsafe { sismo_consumer_session_create() };
    if session.is_null() {
        eprintln!("sismo record: session_create failed");
        shutdown_bpf(bpf.take());
        stop_probes(probes);
        teardown_early(svc, lock_fd);
        return 0;
    }
    let setup_rc =
        unsafe { sismo_consumer_session_setup(session, cfg.as_ptr() as *const c_void, cfg.len()) };
    if setup_rc != 0 {
        eprintln!("sismo record: session_setup rc={setup_rc} (TraceConfig failed to parse)");
        unsafe { sismo_consumer_session_destroy(session) };
        shutdown_bpf(bpf.take());
        stop_probes(probes);
        teardown_early(svc, lock_fd);
        return 0;
    }

    unsafe { sismo_consumer_session_start_blocking(session) };
    print_start_banner(long_trace, buffer_kb, output_path_str);

    // Self-pipe + watch threads (Linux is spawn-only — no attach).
    let mut pipe_fds = [0 as c_int; 2];
    if unsafe { pipe(pipe_fds.as_mut_ptr()) } != 0 {
        eprintln!("sismo record: pipe() failed");
        unsafe { sismo_consumer_session_destroy(session) };
        shutdown_bpf(bpf.take());
        stop_probes(probes);
        teardown_early(svc, lock_fd);
        return 0;
    }
    let (rd, wr) = (pipe_fds[0], pipe_fds[1]);
    SIGINT_PIPE_FD.store(wr, Ordering::Release);
    unsafe { signal(SIGINT, handle_sigint as extern "C" fn(c_int) as libc::sighandler_t) };

    let watch = std::thread::spawn(move || waitpid_exit_watch(target_pid, wr));
    if let Some(secs) = duration_secs {
        std::thread::spawn(move || duration_timer(secs, wr));
    }

    wait_for_workload_exit(rd, target_pid, false);

    let focus_preset: Option<&[u8]> = if focus_int == 0 { Some(b"cache".as_slice()) } else { None };
    if long_trace {
        // Streaming mode: traced already wrote the file; stop finalizes it.
        unsafe { sismo_consumer_session_stop_blocking(session) };
        let precise = shutdown_bpf(bpf.take());
        eprintln!("sismo record: saved {output_path_str}");
        if !append_privileged_marker(output_path_str, &[target_pid], focus_preset, precise >= 2) {
            eprintln!("sismo record: failed to write privileged marker");
        }
        if had_bpf {
            sismo_core::symbolize::perf_symbolize::symbolize_trace(output_path_str);
        }
    } else {
        // Rolling-buffer mode: drain the BPF worker into the still-active session
        // (it self-drains on shutdown, so this must precede the clone), clone the
        // session to the file, then stop.
        let precise = shutdown_bpf(bpf.take());
        eprintln!("sismo record: stopping — writing trace to {output_path_str}");
        match crate::trace_sink::clone_session_to_file("sismo_record", output_path_str) {
            Ok(bytes) => {
                eprintln!("sismo record: saved {output_path_str} ({bytes} bytes)");
                if !append_privileged_marker(output_path_str, &[target_pid], focus_preset, precise >= 2) {
                    eprintln!("sismo record: failed to write privileged marker");
                }
                if had_bpf {
                    sismo_core::symbolize::perf_symbolize::symbolize_trace(output_path_str);
                }
            }
            Err(e) => eprintln!("sismo record: failed to write trace: {e}"),
        }
        unsafe { sismo_consumer_session_stop_blocking(session) };
    }

    SIGINT_PIPE_FD.store(-1, Ordering::Release);
    unsafe { close(rd) };
    unsafe { close(wr) };
    let _ = watch.join();

    unsafe { sismo_consumer_session_destroy(session) };
    stop_probes(probes);
    unsafe { sismo_traced_stop(svc) };
    release_session_lock(lock_fd);
    0
}
