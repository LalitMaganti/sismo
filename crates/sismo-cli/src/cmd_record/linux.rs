// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! The Linux record flow: spawn the workload (Linux rejects --pid), embed the
//! Perfetto `traced` service plus `traced_probes` (ftrace + procfs sched), run
//! the BPF CPU collector (per-thread counters + stack sampling) scoped to the
//! workload, block on the self-pipe (SIGINT / workload exit / --duration),
//! then stop, write the privileged marker, run post-record symbolization, and
//! tear everything down.

use super::{
    duration_timer, handle_sigint, maybe_spawn, print_start_banner, teardown_early,
    wait_for_workload_exit, waitpid_exit_watch, SIGINT_PIPE_FD,
};
use crate::privileged_marker::append_privileged_marker;
use crate::record_args::{RecordConfig, SourceMode};
use sismo_core::cpu::linux_bpf_capture::{self, Capture, FocusPreset};
use sismo_core::cpu::module_registry::{KeepPolicy, ModuleRegistry};
use sismo_core::ffi::{
    sismo_consumer_session_create, sismo_consumer_session_destroy, sismo_consumer_session_setup,
    sismo_consumer_session_start_blocking, sismo_consumer_session_stop_blocking, sismo_init,
    sismo_traced_create, sismo_traced_probes_create, sismo_traced_probes_destroy,
    sismo_traced_probes_stop, sismo_traced_stop,
};
use sismo_core::proto::session_config::{encode_trace_config, DataSourceEntry, MODE_FILE, MODE_RING};
use sismo_core::sismo_paths::{
    acquire_session_lock, release_session_lock, LockError, CONSUMER_SOCK, PRODUCER_SOCK,
};
use std::ffi::CString;
use std::os::raw::{c_int, c_void};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use libc::{close, getpid, pipe, signal, unlink, SIGINT};

pub fn run(config: &RecordConfig) -> c_int {
    let output: String = config.output.clone().unwrap_or_else(crate::trace_sink::timestamped_output_path);
    let output_path_str: &str = &output;
    let output_c = CString::new(output.as_str()).unwrap_or_default();
    let duration_secs = config.duration_secs;
    let long_trace = config.long_trace;
    let buffer_kb = config.buffer_kb;
    let no_sched = config.sched_mode == SourceMode::Off;
    let no_cpu = config.cpu_mode == SourceMode::Off;
    let no_instrumentation = config.no_instrumentation;
    let no_symbolize = config.no_symbolize;
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
        let c = linux_bpf_capture::init(
            target_pid as u32, focus, sample_density, config.capture_offcpu, config.keep_module_files);
        if c.is_none() {
            eprintln!("sismo record: bpf capture init failed — CPU samples disabled");
        }
        c
    };
    let had_bpf = bpf.is_some();
    let shutdown_bpf = |bpf: Option<Box<Capture>>| -> (u8, Arc<Mutex<ModuleRegistry>>) {
        let Some(c) = bpf else {
            return (0, Arc::new(Mutex::new(ModuleRegistry::new(KeepPolicy::None))));
        };
        let precise = c.precise_ip();
        let (s, modules) = c.shutdown();
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
        let held = modules.lock().unwrap().held_count();
        if held > 0 {
            eprintln!("sismo record: keeping {held} module file(s) open for symbolization");
        }
        (precise, modules)
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

    wait_for_workload_exit(rd, target_pid, false, None);

    let focus_preset: Option<&[u8]> = if focus_int == 0 { Some(b"cache".as_slice()) } else { None };
    if long_trace {
        // Streaming mode: traced already wrote the file; stop finalizes it.
        unsafe { sismo_consumer_session_stop_blocking(session) };
        let (precise, modules) = shutdown_bpf(bpf.take());
        eprintln!("sismo record: saved {output_path_str}");
        if !append_privileged_marker(output_path_str, &[target_pid], focus_preset, precise >= 2) {
            eprintln!("sismo record: failed to write privileged marker");
        }
        if had_bpf && !no_symbolize {
            // `modules` stays alive across this call: it owns the fds the held-open
            // paths point at (CAP-3(b)).
            sismo_core::symbolize::perf_symbolize::symbolize_trace(
                output_path_str, &modules.lock().unwrap().held_fd_paths());
        }
    } else {
        // Rolling-buffer mode: drain the BPF worker into the still-active session
        // (it self-drains on shutdown, so this must precede the clone), clone the
        // session to the file, then stop.
        let (precise, modules) = shutdown_bpf(bpf.take());
        eprintln!("sismo record: stopping — writing trace to {output_path_str}");
        match crate::trace_sink::clone_session_to_file("sismo_record", output_path_str) {
            Ok(bytes) => {
                eprintln!("sismo record: saved {output_path_str} ({bytes} bytes)");
                if !append_privileged_marker(output_path_str, &[target_pid], focus_preset, precise >= 2) {
                    eprintln!("sismo record: failed to write privileged marker");
                }
                if had_bpf && !no_symbolize {
                    sismo_core::symbolize::perf_symbolize::symbolize_trace(
                        output_path_str, &modules.lock().unwrap().held_fd_paths());
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
