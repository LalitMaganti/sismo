// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `sismo record` — the macOS unified recorder (migrated whole from
//! cmd_record.zig::runRecordMacos + its helpers).
//!
//! Parses args (rust-bridge/src/record_args.rs), acquires the workload (spawn
//! with the heap-preload DYLD-inserted, or attach to a prepared pid), embeds
//! the Perfetto `traced` service, registers the in-process capture workers
//! (already-Rust sched/cpu/heap), builds + starts a consumer session, then
//! blocks on a self-pipe fed by a SIGINT handler / a workload-exit watch thread
//! (waitpid for spawned, kqueue NOTE_EXIT for attached) / an optional
//! --duration timer, and finally stops the session, writes the privileged
//! marker, and tears everything down.
//!
//! The service + consumer session are the C++ shim (permanent); the captures,
//! configs, session lock, and marker are Rust siblings (direct calls). The Zig
//! runRecordLinux keeps its own copies of the shared helpers until P5.
//!
//! macOS-only; gated in lib.rs. Validated by `sudo tools/e2e-all-sources`.

use crate::proto::{ProtoReader, WireValue};
use crate::record_args::{parse_record_args, RecordArgsC, MODE_EXTERNAL, MODE_IN_PROCESS};
use crate::session_config::{sismo_encode_trace_config, DataSourceEntryC};
use crate::sismo_config::{sismo_config_cpu_encode, sismo_config_heap_encode, sismo_config_sched_encode};
use crate::sismo_paths::{sismo_acquire_session_lock, sismo_release_session_lock, CONSUMER_SOCK, PRODUCER_SOCK};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::sync::atomic::{AtomicI32, Ordering};

// Capture workers (Rust siblings).
use crate::macos_cpu_capture::{sismo_cpu_capture_init, sismo_cpu_capture_shutdown, CpuCapture};
use crate::macos_heap_capture::{sismo_heap_capture_init, sismo_heap_capture_shutdown, HeapCapture};
use crate::macos_sched_capture::{sismo_sched_capture_init, sismo_sched_capture_shutdown, SchedCapture};

// ---- C++ shim (traced service + consumer session + producer init) ----------

#[repr(C)]
struct TracedSvc {
    _opaque: [u8; 0],
}
#[repr(C)]
struct ConsumerSession {
    _opaque: [u8; 0],
}

extern "C" {
    fn sismo_traced_create(producer_socket: *const c_char, consumer_socket: *const c_char) -> *mut TracedSvc;
    fn sismo_traced_stop(svc: *mut TracedSvc);
    fn sismo_traced_destroy(svc: *mut TracedSvc);
    fn sismo_init(producer_socket: *const c_char);
    fn sismo_consumer_session_create() -> *mut ConsumerSession;
    fn sismo_consumer_session_setup(session: *mut ConsumerSession, cfg: *const c_void, cfg_len: usize) -> c_int;
    fn sismo_consumer_session_start_blocking(session: *mut ConsumerSession);
    fn sismo_consumer_session_stop_blocking(session: *mut ConsumerSession);
    fn sismo_consumer_session_destroy(session: *mut ConsumerSession);
    fn sismo_consumer_query_service_state(
        session: *mut ConsumerSession,
        out_buf: *mut c_void,
        out_buf_size: usize,
        written: *mut usize,
    ) -> c_int;

    // The privileged-pid marker (Rust, but called via its C ABI for uniformity).
    fn sismo_append_privileged_marker(
        path: *const u8,
        path_len: usize,
        pids: *const i32,
        pids_len: usize,
        focus: *const u8,
        focus_len: usize,
        is_focus: bool,
    ) -> bool;
}

// ---- libc ------------------------------------------------------------------

extern "C" {
    fn geteuid() -> c_uint;
    fn getpid() -> c_int;
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn unlink(path: *const c_char) -> c_int;
    fn pipe(fds: *mut c_int) -> c_int;
    fn read(fd: c_int, buf: *mut c_void, n: usize) -> isize;
    fn write(fd: c_int, buf: *const c_void, n: usize) -> isize;
    fn close(fd: c_int) -> c_int;
    fn access(path: *const u8, mode: c_int) -> c_int;
    fn nanosleep(req: *const Timespec, rem: *mut Timespec) -> c_int;
    fn signal(sig: c_int, handler: extern "C" fn(c_int)) -> usize;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn kqueue() -> c_int;
    fn kevent(
        kq: c_int,
        changelist: *const Kevent,
        nchanges: c_int,
        eventlist: *mut Kevent,
        nevents: c_int,
        timeout: *const Timespec,
    ) -> c_int;
    fn posix_spawnp(
        pid: *mut c_int,
        path: *const c_char,
        file_actions: *const c_void,
        attrp: *const c_void,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> c_int;
    static environ: *const *const c_char;
}

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

// macOS kevent(2).
#[repr(C)]
struct Kevent {
    ident: usize,
    filter: i16,
    flags: u16,
    fflags: u32,
    data: isize,
    udata: *mut c_void,
}
const EVFILT_PROC: i16 = -5;
const EV_ADD: u16 = 0x0001;
const EV_ONESHOT: u16 = 0x0010;
const NOTE_EXIT: u32 = 0x8000_0000;

const SIGINT: c_int = 2;
const SIGTERM: c_int = 15;

// ---- Self-pipe (SIGINT handler → main loop) --------------------------------

static SIGINT_PIPE_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn handle_sigint(_sig: c_int) {
    let fd = SIGINT_PIPE_FD.load(Ordering::Acquire);
    if fd >= 0 {
        let b = b"I";
        unsafe { write(fd, b.as_ptr() as *const c_void, 1) };
    }
}

fn setenv_str(k: &str, v: &str) {
    std::env::set_var(k, v);
}

// ---- Workload spawn --------------------------------------------------------

/// posix_spawnp `path` with `args` (its argv[1..]) after applying `env`
/// overrides. Returns the child pid, or None on failure.
fn maybe_spawn(path: &str, args: &[&str], env: &[(&str, &str)]) -> Option<i32> {
    for (k, v) in env {
        setenv_str(k, v);
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
        posix_spawnp(&mut pid, path_c.as_ptr(), std::ptr::null(), std::ptr::null(), argv.as_ptr(), environ)
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
fn kqueue_exit_watch(pid: c_int, write_fd: c_int) {
    let kq = unsafe { kqueue() };
    if kq < 0 {
        return; // no kqueue — loop only stops on SIGINT / --duration
    }
    let mut change = Kevent {
        ident: pid as usize,
        filter: EVFILT_PROC,
        flags: EV_ADD | EV_ONESHOT,
        fflags: NOTE_EXIT,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    let mut ev = Kevent {
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

// ---- DataSourceEntry builders ----------------------------------------------

fn ds_track_event() -> DataSourceEntryC {
    DataSourceEntryC {
        kind: 0,
        name: std::ptr::null(),
        name_len: 0,
        sismo_config: std::ptr::null(),
        sismo_config_len: 0,
        protovm_memory_limit_kb: 0,
    }
}

fn ds_sismo_vendor(name: &[u8], cfg: &[u8], protovm_kb: u32) -> DataSourceEntryC {
    DataSourceEntryC {
        kind: 1,
        name: name.as_ptr(),
        name_len: name.len(),
        sismo_config: cfg.as_ptr(),
        sismo_config_len: cfg.len(),
        protovm_memory_limit_kb: protovm_kb,
    }
}

// ---- Entry point -----------------------------------------------------------

/// `sismo record` on macOS. `argv[0..argc]` are the full process args. Parses
/// (Rust) then runs the whole record flow. Returns the process exit code.
///
/// # Safety
/// `argv` must point to `argc` valid NUL-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_run_record_macos(argc: usize, argv: *const *const c_char) -> c_int {
    let all: Vec<&str> = (0..argc)
        .map(|i| unsafe { CStr::from_ptr(*argv.add(i)) }.to_str().unwrap_or(""))
        .collect();
    let args: &[&str] = if all.len() > 2 { &all[2..] } else { &[] };

    let mut rc = RecordArgsC::default();
    if !parse_record_args(args, all.len(), &mut rc) {
        return 0; // help / error already printed
    }
    run(&all, &rc)
}

fn run(all: &[&str], rc: &RecordArgsC) -> c_int {
    let output_path: &[u8] =
        unsafe { std::slice::from_raw_parts(rc.output_path_ptr, rc.output_path_len) };
    let output_path_str = std::str::from_utf8(output_path).unwrap_or("./sismo.pftrace");
    let attach_pid: Option<i32> = if rc.has_attach_pid { Some(rc.attach_pid) } else { None };
    let duration_secs: Option<c_uint> = if rc.has_duration { Some(rc.duration_secs) } else { None };
    let flight_recorder = rc.flight_recorder;
    let buffer_kb = rc.buffer_kb;
    let (sched_mode, cpu_mode, heap_mode) = (rc.sched_mode, rc.cpu_mode, rc.heap_mode);
    let no_instrumentation = rc.no_instrumentation;

    // Attach sanity check.
    if let Some(pid) = attach_pid {
        if unsafe { kill(pid, 0) } != 0 {
            eprintln!("sismo record: pid {pid} not found (or not signalable)");
            return 0;
        }
    }

    // Privilege warning for in-process privileged sources.
    if unsafe { geteuid() } != 0 {
        let mut unmet: Vec<&str> = Vec::new();
        if sched_mode == MODE_IN_PROCESS {
            unmet.push("sched");
        }
        if cpu_mode == MODE_IN_PROCESS {
            unmet.push("cpu");
        }
        if heap_mode == MODE_IN_PROCESS {
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
    let lock_fd = sismo_acquire_session_lock(unsafe { getpid() });
    if lock_fd == -2 {
        eprintln!("sismo record: another sismo session is already running (lock held on /tmp/sismo.lock)");
        return 0;
    }
    if lock_fd < 0 {
        eprintln!("sismo record: failed to open session lock at /tmp/sismo.lock");
        return 0;
    }

    let my_pid = unsafe { getpid() };
    eprintln!(
        "sismo record: pid={my_pid} output={output_path_str}\n  producer sock: {PRODUCER_SOCK}\n  consumer sock: {CONSUMER_SOCK}"
    );
    setenv_str("PERFETTO_PRODUCER_SOCK_NAME", PRODUCER_SOCK);
    setenv_str("PERFETTO_CONSUMER_SOCK_NAME", CONSUMER_SOCK);

    // Embed traced + init the producer client.
    let prod_c = CString::new(PRODUCER_SOCK).unwrap();
    let cons_c = CString::new(CONSUMER_SOCK).unwrap();
    let svc = unsafe { sismo_traced_create(prod_c.as_ptr(), cons_c.as_ptr()) };
    if svc.is_null() {
        eprintln!("sismo record: traced_create failed");
        sismo_release_session_lock(lock_fd);
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
            let heap_dylib = match crate::sismo_paths::resolve_heap_dylib_path() {
                Some(p) => p,
                None => {
                    eprintln!("sismo record: failed to resolve heap dylib path");
                    teardown_early(svc, lock_fd);
                    return 0;
                }
            };
            let workload_cmd = all[rc.workload_start];
            let workload_args: Vec<&str> = all[rc.workload_start + 1..].to_vec();
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
    let sched: *mut SchedCapture = if sched_mode == MODE_IN_PROCESS {
        let c = unsafe { sismo_sched_capture_init() };
        if c.is_null() {
            eprintln!("sismo record: sched capture init failed");
        }
        c
    } else {
        std::ptr::null_mut()
    };
    let cpu: *mut CpuCapture = if cpu_mode == MODE_IN_PROCESS {
        let c = unsafe { sismo_cpu_capture_init(0) };
        if c.is_null() {
            eprintln!("sismo record: cpu capture init failed");
        }
        c
    } else {
        std::ptr::null_mut()
    };
    let heap: *mut HeapCapture = if heap_mode == MODE_IN_PROCESS {
        // In attach mode, heap needs the target prepared (its socket exists).
        let ok = match attach_pid {
            Some(pid) => {
                let mut sock_buf = [0u8; 128];
                let has_socket = match crate::heap_protocol::socket_path(pid, &mut sock_buf) {
                    Some(len) => {
                        sock_buf[len] = 0;
                        unsafe { access(sock_buf.as_ptr(), 0) == 0 } // F_OK
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
            let c = unsafe { sismo_heap_capture_init() };
            if c.is_null() {
                eprintln!("sismo record: heap capture init failed");
            }
            c
        } else {
            std::ptr::null_mut()
        }
    } else {
        std::ptr::null_mut()
    };

    // Per-DS sismo configs (field 2000 of each DataSourceConfig).
    let mut cpu_buf = [0u8; 256];
    let cpu_len = unsafe { sismo_config_cpu_encode(target_pid as u32, 0, cpu_buf.as_mut_ptr(), cpu_buf.len()) };
    let cpu_cfg = &cpu_buf[..cpu_len];
    let mut heap_buf = [0u8; 256];
    let heap_len = unsafe { sismo_config_heap_encode(target_pid as u32, 0, 0, heap_buf.as_mut_ptr(), heap_buf.len()) };
    let heap_cfg = &heap_buf[..heap_len];
    let mut sched_buf = [0u8; 256];
    let sched_len = unsafe { sismo_config_sched_encode(0, sched_buf.as_mut_ptr(), sched_buf.len()) };
    let sched_cfg = &sched_buf[..sched_len];

    // Build the entries + external-name list.
    let mut entries: Vec<DataSourceEntryC> = Vec::new();
    let mut external_names: Vec<&str> = Vec::new();
    if !no_instrumentation {
        entries.push(ds_track_event());
    }
    if !heap.is_null() || heap_mode == MODE_EXTERNAL {
        entries.push(ds_sismo_vendor(b"sismo.heap", heap_cfg, 0));
        if heap_mode == MODE_EXTERNAL {
            external_names.push("sismo.heap");
        }
    }
    if !cpu.is_null() || cpu_mode == MODE_EXTERNAL {
        entries.push(ds_sismo_vendor(b"sismo.macos_cpu_samples", cpu_cfg, 0));
        if cpu_mode == MODE_EXTERNAL {
            external_names.push("sismo.macos_cpu_samples");
        }
    }
    if !sched.is_null() || sched_mode == MODE_EXTERNAL {
        // ProtoVM DST for GenericKernelProcessTree (see the Zig comment).
        entries.push(ds_sismo_vendor(b"sismo.macos_sched", sched_cfg, 4 * 1024));
        if sched_mode == MODE_EXTERNAL {
            external_names.push("sismo.macos_sched");
        }
    }
    if entries.is_empty() {
        eprintln!("sismo record: no data sources enabled — recording would be empty. Drop one of the --no-* flags.");
        shutdown_captures(heap, cpu, sched);
        teardown_early(svc, lock_fd);
        return 0;
    }

    // FILE mode pre-clears the output; flight mode writes nothing.
    if !flight_recorder {
        // output_path is NUL-terminated at [len] (default or argv).
        unsafe { unlink(rc.output_path_ptr as *const c_char) };
    }
    let out_path: &[u8] = if flight_recorder { b"" } else { output_path };
    let session_name = b"sismo_record";
    let mut cfg_buf = [0u8; 16384];
    let cfg_len = unsafe {
        sismo_encode_trace_config(
            if flight_recorder { 0 } else { 2 }, // ring : file
            buffer_kb,
            0,
            out_path.as_ptr(),
            out_path.len(),
            1024 * 1024 * 1024,
            session_name.as_ptr(),
            session_name.len(),
            entries.as_ptr(),
            entries.len(),
            cfg_buf.as_mut_ptr(),
            cfg_buf.len(),
        )
    };
    if cfg_len == 0 {
        eprintln!("sismo record: encodeTraceConfig failed (config exceeds buffer)");
        shutdown_captures(heap, cpu, sched);
        teardown_early(svc, lock_fd);
        return 0;
    }

    let session = unsafe { sismo_consumer_session_create() };
    if session.is_null() {
        eprintln!("sismo record: session_create failed");
        shutdown_captures(heap, cpu, sched);
        teardown_early(svc, lock_fd);
        return 0;
    }
    let setup_rc = unsafe { sismo_consumer_session_setup(session, cfg_buf.as_ptr() as *const c_void, cfg_len) };
    if setup_rc != 0 {
        eprintln!("sismo record: session_setup rc={setup_rc} (TraceConfig failed to parse)");
        unsafe { sismo_consumer_session_destroy(session) };
        shutdown_captures(heap, cpu, sched);
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
            shutdown_captures(heap, cpu, sched);
            teardown_early(svc, lock_fd);
            return 0;
        }
    }

    unsafe { sismo_consumer_session_start_blocking(session) };
    if flight_recorder {
        eprintln!("sismo record: flight-recorder started ({buffer_kb} KB buffer); take snapshots via `sismo snapshot` while running");
    } else {
        eprintln!("sismo record: session started, recording until workload exits (or SIGINT)");
    }

    // Self-pipe + watch threads.
    let mut pipe_fds = [0 as c_int; 2];
    if unsafe { pipe(pipe_fds.as_mut_ptr()) } != 0 {
        eprintln!("sismo record: pipe() failed");
        unsafe { sismo_consumer_session_destroy(session) };
        shutdown_captures(heap, cpu, sched);
        teardown_early(svc, lock_fd);
        return 0;
    }
    let (rd, wr) = (pipe_fds[0], pipe_fds[1]);
    SIGINT_PIPE_FD.store(wr, Ordering::Release);
    unsafe { signal(SIGINT, handle_sigint) };

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

    // Main wait loop.
    let mut read_buf = [0u8; 16];
    let mut workload_done = false;
    while !workload_done {
        let n = unsafe { read(rd, read_buf.as_mut_ptr() as *mut c_void, read_buf.len()) };
        if n <= 0 {
            continue;
        }
        for &b in &read_buf[..n as usize] {
            match b {
                b'I' => {
                    if !is_attach {
                        eprintln!("sismo record: SIGINT — sending SIGTERM to workload pid={target_pid}");
                        unsafe { kill(target_pid, SIGTERM) };
                    } else {
                        eprintln!("sismo record: SIGINT — stopping recording (attached pid={target_pid} keeps running)");
                        workload_done = true;
                    }
                }
                b'T' => {
                    if !is_attach {
                        eprintln!("sismo record: --duration reached — sending SIGTERM to workload pid={target_pid}");
                        unsafe { kill(target_pid, SIGTERM) };
                    } else {
                        eprintln!("sismo record: --duration reached — stopping recording (attached pid={target_pid} keeps running)");
                        workload_done = true;
                    }
                }
                b'X' => workload_done = true,
                _ => {}
            }
        }
    }

    // Stop the session.
    unsafe { sismo_consumer_session_stop_blocking(session) };
    if flight_recorder {
        eprintln!("sismo record: flight-recorder stopped (buffer discarded; use `sismo snapshot` before stopping to capture)");
    } else {
        eprintln!("sismo record: trace saved to {output_path_str}");
        let pids = [target_pid];
        let ok = unsafe {
            sismo_append_privileged_marker(
                rc.output_path_ptr,
                rc.output_path_len,
                pids.as_ptr(),
                pids.len(),
                std::ptr::null(),
                0,
                false,
            )
        };
        if !ok {
            eprintln!("sismo record: failed to write privileged marker");
        }
    }

    // Capture shutdowns (with stats).
    shutdown_captures(heap, cpu, sched);

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
    sismo_release_session_lock(lock_fd);
    0
}

/// Shut down whichever captures are non-null, printing per-source stats.
fn shutdown_captures(heap: *mut HeapCapture, cpu: *mut CpuCapture, sched: *mut SchedCapture) {
    if !heap.is_null() {
        let (mut records, mut bytes, mut sites) = (0u64, 0u64, 0u32);
        unsafe { sismo_heap_capture_shutdown(heap, &mut records, &mut bytes, &mut sites) };
        eprintln!("sismo record: heap — {records} records, ~{bytes} bytes, {sites} sites");
    }
    if !cpu.is_null() {
        let (mut samples, mut active) = (0u64, 0u64);
        unsafe { sismo_cpu_capture_shutdown(cpu, &mut samples, &mut active) };
        eprintln!("sismo record: cpu — {samples} samples ({active} active)");
    }
    if !sched.is_null() {
        let (mut events, mut drains) = (0u64, 0u64);
        unsafe { sismo_sched_capture_shutdown(sched, &mut events, &mut drains) };
        eprintln!("sismo record: sched — {events} events emitted across {drains} drains");
    }
}

/// Teardown for the early-return paths (before the session/pipe exist).
fn teardown_early(svc: *mut TracedSvc, lock_fd: c_int) {
    unsafe {
        sismo_traced_stop(svc);
        sismo_traced_destroy(svc);
    }
    sismo_release_session_lock(lock_fd);
}
