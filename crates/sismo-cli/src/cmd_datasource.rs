// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `sismo datasource <id> [<id>...]` — daemonized producer hosting one or more
//! sismo data sources in this single process.
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
static SHOULD_STOP: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "macos")]
extern "C" fn handle_stop(_sig: std::os::raw::c_int) {
    SHOULD_STOP.store(true, Ordering::Release);
}

#[cfg(target_os = "macos")]
use libc::{signal, SIGINT, SIGTERM};

#[cfg(target_os = "macos")]
fn install_stop_handlers() {
    unsafe {
        signal(SIGINT, handle_stop as extern "C" fn(std::os::raw::c_int) as libc::sighandler_t);
        signal(SIGTERM, handle_stop as extern "C" fn(std::os::raw::c_int) as libc::sighandler_t);
    }
}

#[cfg(target_os = "macos")]
fn block_until_stopped() {
    // Coarse poll — the handler can't safely touch a condvar, so check the
    // atomic on a short interval (100 ms latency, fine for SIGTERM).
    while !SHOULD_STOP.load(Ordering::Acquire) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

// ---- Entry point -----------------------------------------------------------

#[derive(clap::Args)]
pub struct DatasourceArgs {
    /// One or more of: sched, cpu, heap, all-privileged.
    #[arg(required = true)]
    names: Vec<String>,
}

/// `sismo datasource` subcommand.
pub fn run(args: DatasourceArgs) -> i32 {
    let rest: Vec<&str> = args.names.iter().map(String::as_str).collect();

    let kinds = match collect_kinds(&rest) {
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
    use sismo_core::ffi::sismo_init;
    use sismo_core::heap::macos_heap_capture::HeapCapture;
    use sismo_core::sched::ring_host::{RingConfig, RingHost};
    use sismo_core::sismo_paths::PRODUCER_SOCK;
    use std::ffi::CString;
    use std::os::raw::c_int;

    // sched + cpu (and off-CPU) share the machine-global kdebug ring + kperf, so
    // they run in ONE ring host; heap is independent.
    enum Slot {
        Ring(Box<RingHost>),
        Heap(Box<HeapCapture>),
    }

    fn shutdown(slot: Slot) {
        match slot {
            Slot::Ring(c) => {
                let s = c.shutdown();
                eprintln!(
                    "sismo datasource: ring stopped — {} sched events / {} drains; on-CPU {} / off-CPU {}",
                    s.sched_events, s.drain_calls, s.oncpu_samples, s.offcpu_samples
                );
            }
            Slot::Heap(c) => {
                let s = c.shutdown();
                eprintln!(
                    "sismo datasource: sismo.heap stopped — {} records / ~{} bytes / {} sites",
                    s.records, s.bytes_alloc, s.sites
                );
            }
        }
    }

    pub fn run(kinds: &[Kind]) -> c_int {
        // Connect to the producer socket via the C++ SDK; each capture init
        // builds + registers its own DataSourceDescriptor.
        let sock = CString::new(PRODUCER_SOCK).unwrap();
        unsafe { sismo_init(sock.as_ptr()) };

        install_stop_handlers();

        let has_sched = kinds.contains(&Kind::Sched);
        let has_cpu = kinds.contains(&Kind::Cpu);
        let has_heap = kinds.contains(&Kind::Heap);

        // A single failure tears down what's already up (partial state is useless
        // when the full set was expected).
        let mut slots: Vec<Slot> = Vec::new();
        let fail = |slots: Vec<Slot>| -> c_int {
            eprintln!("sismo datasource: capture init failed — tearing down");
            for s in slots.into_iter().rev() {
                shutdown(s);
            }
            1
        };

        if has_sched || has_cpu {
            // keep: None — a sidecar producer can't hand held fds to the
            // recorder process, so pinning module files here would leak them.
            match RingHost::start(RingConfig {
                sched: has_sched,
                offcpu: has_sched,
                oncpu: has_cpu,
                keep: sismo_core::cpu::module_registry::KeepPolicy::None,
            }) {
                Some(c) => {
                    eprintln!("sismo datasource: kdebug ring host registered (sched={has_sched} cpu={has_cpu})");
                    slots.push(Slot::Ring(c));
                }
                None => return fail(slots),
            }
        }
        if has_heap {
            match HeapCapture::start() {
                Some(c) => {
                    eprintln!("sismo datasource: sismo.heap registered");
                    slots.push(Slot::Heap(c));
                }
                None => return fail(slots),
            }
        }

        eprintln!(
            "sismo datasource: {} producer(s) registered; blocking until SIGINT/SIGTERM",
            slots.len()
        );
        block_until_stopped();

        // Reverse registration order so each worker tears down before the next.
        for s in slots.into_iter().rev() {
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
