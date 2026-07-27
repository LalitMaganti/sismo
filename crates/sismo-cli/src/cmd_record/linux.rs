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
    sismo_consumer_session_start_blocking, sismo_consumer_session_stop_blocking,
    sismo_consumer_shutdown, sismo_init,
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
    let mut no_sched = config.sched_mode == SourceMode::Off;
    let no_cpu = config.cpu_mode == SourceMode::Off;
    // A tracefs this user can't use makes its consumers fail late and badly
    // (an unwritable ftrace source crashes Perfetto's controller mid-setup;
    // an unreadable one stalls session start) — degrade up front instead.
    // Off-CPU futex tracking only reads tracepoint ids; ftrace also writes.
    let mut capture_offcpu = config.capture_offcpu;
    if capture_offcpu && !tracefs_readable() {
        eprintln!("sismo record: tracefs is not readable — off-CPU tracking disabled");
        eprintln!("  fix: sudo sismo doctor --fix");
        capture_offcpu = false;
    }
    if !no_sched && !tracefs_writable() {
        eprintln!("sismo record: tracefs is not writable — sched events disabled");
        eprintln!("  fix: sudo sismo doctor --fix");
        no_sched = true;
    }
    let no_instrumentation = config.no_instrumentation;
    let no_symbolize = config.no_symbolize;
    let sample_density = config.sample_density;

    // Resolve --focus. The cpu presets drive the sampler + counter set here;
    // memory.* is a macOS heap-dump preset, not a Linux BPF mode. Unknown =
    // hard error.
    let focus: Option<FocusPreset> = match config.focus.as_deref() {
        None => None,
        Some(name) => match FocusPreset::from_name(name.as_bytes()) {
            Some(p) => Some(p),
            None => {
                eprintln!("sismo record: unknown focus preset '{name}' (supported: cpu, cpu.cache_miss)");
                return 0;
            }
        },
    };

    tracing::info!("record: start");
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
    tracing::info!("record: traced up");

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
    tracing::info!(present = !probes.is_null(), "record: probes up");
    let stop_probes = |probes: *mut c_void| {
        if !probes.is_null() {
            tracing::info!("record: probes stop begin");
            unsafe {
                sismo_traced_probes_stop(probes);
                sismo_traced_probes_destroy(probes);
            }
            tracing::info!("record: probes stopped");
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
    tracing::info!(pid = target_pid, "record: workload spawned");

    // BPF CPU collector (per-thread counters + stack sampling), scoped to the
    // workload. Drains on its own worker thread; shut down on the way out.
    let mut bpf: Option<Box<Capture>> = if no_cpu {
        None
    } else {
        tracing::info!("record: bpf init begin");
        let c = linux_bpf_capture::init(
            target_pid as u32, focus, sample_density, capture_offcpu, config.keep_module_files);
        if c.is_none() {
            eprintln!("sismo record: bpf capture init failed — CPU samples disabled");
            eprintln!("  fix: sudo sismo doctor --fix   (grants cap_bpf,cap_perfmon,cap_sys_resource; or record as root)");
        }
        c
    };
    let had_bpf = bpf.is_some();
    tracing::info!(ok = had_bpf, "record: bpf init done");
    let shutdown_bpf = |bpf: Option<Box<Capture>>| -> (u8, Arc<Mutex<ModuleRegistry>>) {
        let Some(c) = bpf else {
            return (0, Arc::new(Mutex::new(ModuleRegistry::new(KeepPolicy::None))));
        };
        tracing::info!("record: bpf shutdown begin");
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
        tracing::info!("record: bpf shutdown done");
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

    tracing::info!("record: session start begin");
    unsafe { sismo_consumer_session_start_blocking(session) };
    tracing::info!("record: session started");
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
    tracing::info!("record: workload exited");

    let focus_preset: Option<&[u8]> = focus.map(|f| f.name().as_bytes());
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
            // paths point at.
            sismo_core::symbolize::perf_symbolize::symbolize_trace(
                output_path_str, &modules.lock().unwrap().held_fd_paths());
        }
    } else {
        // Rolling-buffer mode: drain the BPF worker into the still-active session
        // (it self-drains on shutdown, so this must precede the clone), clone the
        // session to the file, then stop.
        let (precise, modules) = shutdown_bpf(bpf.take());
        eprintln!("sismo record: stopping — writing trace to {output_path_str}");
        tracing::info!("record: clone begin");
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
        tracing::info!("record: session stop begin");
        unsafe { sismo_consumer_session_stop_blocking(session) };
        tracing::info!("record: session stopped");
    }

    SIGINT_PIPE_FD.store(-1, Ordering::Release);
    unsafe { close(rd) };
    unsafe { close(wr) };
    let _ = watch.join();

    unsafe { sismo_consumer_session_destroy(session) };
    // Session destruction is async (posted to the SDK muxer thread); block
    // until that thread is fully torn down so its IPC-client frees can't
    // interleave with the probes/service teardown below.
    unsafe { sismo_consumer_shutdown() };
    tracing::info!("record: session destroyed");
    stop_probes(probes);
    unsafe { sismo_traced_stop(svc) };
    tracing::info!("record: exit");
    release_session_lock(lock_fd);
    0
}

/// Whether tracefs tracepoint ids are readable — what the off-CPU futex
/// tracepoint attach needs. `sismo doctor --fix` opens this up; a reboot
/// closes it again.
fn tracefs_readable() -> bool {
    ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"].iter().any(|base| {
        std::fs::File::open(format!("{base}/events/syscalls/sys_enter_futex/id")).is_ok()
    })
}

/// Whether tracefs is writable — what the ftrace data source needs (it writes
/// `tracing_on`/`set_event` during setup, and crashes rather than degrades
/// when it can't).
fn tracefs_writable() -> bool {
    ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"].iter().any(|base| {
        std::fs::OpenOptions::new()
            .write(true)
            .open(format!("{base}/tracing_on"))
            .is_ok()
    })
}
