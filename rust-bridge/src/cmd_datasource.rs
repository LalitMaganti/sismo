// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `sismo datasource <id> [<id>...]` — daemonized producer hosting one or more
//! sismo data sources in this single process (migrated whole from
//! cmd_datasource.zig).
//!
//! Connects to PERFETTO_PRODUCER_SOCK_NAME (set by whoever hosts traced —
//! typically `sismo record` in privsep mode), registers each requested data
//! source, and blocks until killed (SIGINT / SIGTERM).
//!
//! Identifiers are platform-independent — sismo maps them to the actual
//! `sismo.*` name for the running OS. `all-privileged` expands per-platform
//! (macOS: sched + cpu + heap). Bundling many in one invocation shares the sudo
//! prompt. Config (target_pid etc.) arrives via on_setup when a session enables
//! a DS — the producer CLI takes no tracing-config flags.
//!
//! The capture workers are already Rust siblings; this drives their init /
//! shutdown lifecycle plus the signal-blocked run loop. The `sismo_init` +
//! producer-socket connection is the C++ shim. macOS-only runtime (the Linux
//! producers aren't wired in this binary yet); POSIX, cfg-gated off Windows.

use std::sync::atomic::{AtomicBool, Ordering};

/// Platform-independent data-source identifier.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Sched,
    Cpu,
    Heap,
}

const USAGE: &str = "usage: sismo datasource <id> [<id>...]\n\n  \
     <id>: sched | cpu | heap | all-privileged\n\n  \
     Connects to PERFETTO_PRODUCER_SOCK_NAME, registers the requested\n  \
     data source(s) in this single process, blocks until SIGINT/SIGTERM.\n  \
     Multiple ids in one invocation share the sudo prompt.\n\n  \
     Identifiers are platform-independent — sismo picks the right\n  \
     `sismo.*` data source name for the running OS internally.\n";

fn parse_kind(name: &str) -> Option<Kind> {
    match name {
        "sched" => Some(Kind::Sched),
        "cpu" => Some(Kind::Cpu),
        "heap" => Some(Kind::Heap),
        _ => None,
    }
}

/// Per-platform expansion of `all-privileged`. macOS: all three need elevation.
fn all_privileged() -> &'static [Kind] {
    #[cfg(target_os = "macos")]
    {
        &[Kind::Sched, Kind::Cpu, Kind::Heap]
    }
    #[cfg(not(target_os = "macos"))]
    {
        &[] // No Linux/Windows producers wired in this binary yet.
    }
}

/// Parse args (everything after "datasource") into a deduped kind list, or
/// `Err(true)` if usage was already printed (help / unknown / empty).
fn collect_kinds(rest: &[&str]) -> Result<Vec<Kind>, ()> {
    let mut kinds: Vec<Kind> = Vec::new();
    let push = |k: Kind, kinds: &mut Vec<Kind>| {
        if !kinds.contains(&k) {
            kinds.push(k);
        }
    };
    for &arg in rest {
        if arg == "all-privileged" {
            for &k in all_privileged() {
                push(k, &mut kinds);
            }
            continue;
        }
        match parse_kind(arg) {
            Some(k) => push(k, &mut kinds),
            None => {
                eprint!("sismo datasource: unknown identifier '{arg}'\n\n{USAGE}");
                return Err(());
            }
        }
    }
    if kinds.is_empty() {
        eprint!("{USAGE}");
        return Err(());
    }
    Ok(kinds)
}

// ---- Signal-driven stop ----------------------------------------------------

static SHOULD_STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_stop(_sig: std::os::raw::c_int) {
    SHOULD_STOP.store(true, Ordering::Release);
}

extern "C" {
    fn signal(sig: std::os::raw::c_int, handler: extern "C" fn(std::os::raw::c_int)) -> usize;
}

const SIGINT: std::os::raw::c_int = 2;
const SIGTERM: std::os::raw::c_int = 15;

fn install_stop_handlers() {
    unsafe {
        signal(SIGINT, handle_stop);
        signal(SIGTERM, handle_stop);
    }
}

fn block_until_stopped() {
    // Coarse poll — the handler can't safely touch a condvar, so check the
    // atomic on a short interval (100 ms latency, fine for SIGTERM).
    while !SHOULD_STOP.load(Ordering::Acquire) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

// ---- Entry point -----------------------------------------------------------

/// `sismo datasource` subcommand. `argv[0..argc]` are the full process args.
///
/// # Safety
/// `argv` must point to `argc` valid NUL-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_cmd_datasource(
    argc: usize,
    argv: *const *const std::os::raw::c_char,
) -> std::os::raw::c_int {
    let args: Vec<&str> = (0..argc)
        .map(|i| unsafe { std::ffi::CStr::from_ptr(*argv.add(i)) }.to_str().unwrap_or(""))
        .collect();
    // Skip argv[0] (exe) + argv[1] ("datasource").
    let rest: &[&str] = if args.len() > 2 { &args[2..] } else { &[] };

    let kinds = match collect_kinds(rest) {
        Ok(k) => k,
        Err(()) => return 0, // usage already printed
    };

    #[cfg(target_os = "macos")]
    {
        return macos_run::run(&kinds);
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = kinds;
        eprintln!("sismo datasource: not yet implemented on this platform");
        0
    }
}

// ---- macOS run loop (drives the Rust capture workers) ----------------------

#[cfg(target_os = "macos")]
mod macos_run {
    use super::{block_until_stopped, install_stop_handlers, Kind};
    use crate::macos_cpu_capture::{sismo_cpu_capture_init, sismo_cpu_capture_shutdown, CpuCapture};
    use crate::macos_heap_capture::{sismo_heap_capture_init, sismo_heap_capture_shutdown, HeapCapture};
    use crate::macos_sched_capture::{sismo_sched_capture_init, sismo_sched_capture_shutdown, SchedCapture};
    use crate::sismo_paths::PRODUCER_SOCK;
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int};

    extern "C" {
        fn sismo_init(producer_socket: *const c_char);
    }

    enum Slot {
        Sched(*mut SchedCapture),
        Cpu(*mut CpuCapture),
        Heap(*mut HeapCapture),
    }

    /// Register one kind's capture worker. Null on registration failure.
    fn register(kind: Kind) -> Option<Slot> {
        match kind {
            Kind::Sched => {
                let c = unsafe { sismo_sched_capture_init() };
                if c.is_null() {
                    return None;
                }
                eprintln!("sismo datasource: sismo.macos_sched registered");
                Some(Slot::Sched(c))
            }
            Kind::Cpu => {
                let c = unsafe { sismo_cpu_capture_init(0) };
                if c.is_null() {
                    return None;
                }
                eprintln!("sismo datasource: sismo.macos_cpu_samples registered");
                Some(Slot::Cpu(c))
            }
            Kind::Heap => {
                let c = unsafe { sismo_heap_capture_init() };
                if c.is_null() {
                    return None;
                }
                eprintln!("sismo datasource: sismo.heap registered");
                Some(Slot::Heap(c))
            }
        }
    }

    fn shutdown(slot: &Slot) {
        match *slot {
            Slot::Sched(c) => {
                let (mut events, mut drains) = (0u64, 0u64);
                unsafe { sismo_sched_capture_shutdown(c, &mut events, &mut drains) };
                eprintln!("sismo datasource: sismo.macos_sched stopped — {events} events / {drains} drains");
            }
            Slot::Cpu(c) => {
                let (mut samples, mut active) = (0u64, 0u64);
                unsafe { sismo_cpu_capture_shutdown(c, &mut samples, &mut active) };
                eprintln!("sismo datasource: sismo.macos_cpu_samples stopped — {samples} samples ({active} active)");
            }
            Slot::Heap(c) => {
                let (mut records, mut bytes, mut sites) = (0u64, 0u64, 0u32);
                unsafe { sismo_heap_capture_shutdown(c, &mut records, &mut bytes, &mut sites) };
                eprintln!("sismo datasource: sismo.heap stopped — {records} records / ~{bytes} bytes / {sites} sites");
            }
        }
    }

    pub fn run(kinds: &[Kind]) -> c_int {
        // Connect to the producer socket via the C++ SDK; each capture init
        // builds + registers its own DataSourceDescriptor.
        let sock = CString::new(PRODUCER_SOCK).unwrap();
        unsafe { sismo_init(sock.as_ptr()) };

        install_stop_handlers();

        // Register each requested kind. A single failure tears down what's
        // already up (partial state is useless when the full set was expected).
        let mut slots: Vec<Slot> = Vec::new();
        for &kind in kinds {
            match register(kind) {
                Some(s) => slots.push(s),
                None => {
                    eprintln!("sismo datasource: capture init failed — tearing down");
                    for s in slots.iter().rev() {
                        shutdown(s);
                    }
                    return 1;
                }
            }
        }

        eprintln!(
            "sismo datasource: {} data source(s) registered; blocking until SIGINT/SIGTERM",
            slots.len()
        );
        block_until_stopped();

        // Reverse registration order so each worker tears down before the next.
        for s in slots.iter().rev() {
            shutdown(s);
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kind_maps_ids() {
        assert!(matches!(parse_kind("sched"), Some(Kind::Sched)));
        assert!(matches!(parse_kind("cpu"), Some(Kind::Cpu)));
        assert!(matches!(parse_kind("heap"), Some(Kind::Heap)));
        assert!(parse_kind("bogus").is_none());
    }

    #[test]
    fn collect_dedups_and_rejects() {
        let k = collect_kinds(&["cpu", "cpu", "sched"]).unwrap();
        assert_eq!(k.len(), 2); // cpu deduped
        assert!(collect_kinds(&["bogus"]).is_err());
        assert!(collect_kinds(&[]).is_err()); // empty prints usage
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn all_privileged_expands_to_three_on_macos() {
        let k = collect_kinds(&["all-privileged"]).unwrap();
        assert_eq!(k.len(), 3);
    }
}
