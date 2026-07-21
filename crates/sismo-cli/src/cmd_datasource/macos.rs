// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! The macOS datasource run loop: drives the Rust capture workers (the shared
//! kdebug ring host and the heap capture), blocking until SIGINT/SIGTERM.
//! The `sismo_init` + producer-socket connection is the C++ shim.

use super::Kind;
use sismo_core::ffi::sismo_init;
use sismo_core::heap::macos_heap_capture::HeapCapture;
use sismo_core::sched::ring_host::{RingConfig, RingHost};
use sismo_core::sismo_paths::PRODUCER_SOCK;
use std::ffi::CString;
use std::os::raw::c_int;
use std::sync::atomic::{AtomicBool, Ordering};

use libc::{signal, SIGINT, SIGTERM};

// ---- Signal-driven stop ----------------------------------------------------

static SHOULD_STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_stop(_sig: c_int) {
    SHOULD_STOP.store(true, Ordering::Release);
}

fn install_stop_handlers() {
    unsafe {
        signal(SIGINT, handle_stop as extern "C" fn(c_int) as libc::sighandler_t);
        signal(SIGTERM, handle_stop as extern "C" fn(c_int) as libc::sighandler_t);
    }
}

fn block_until_stopped() {
    // Coarse poll — the handler can't safely touch a condvar, so check the
    // atomic on a short interval (100 ms latency, fine for SIGTERM).
    while !SHOULD_STOP.load(Ordering::Acquire) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

// ---- Run loop ---------------------------------------------------------------

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
