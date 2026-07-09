// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! extern "C" facade exposing the Rust-side helpers (framehop unwinder,
//! wholesym symbolizer) to Zig over a cargo→staticlib→Zig link.

pub mod cli;
pub mod data_regions;
pub mod disasm;
// macOS Mach-based module enumeration + mach-o reading.
#[cfg(target_os = "macos")]
pub mod dyld_images;
// macOS kdebug (sched-event sysctl ring).
#[cfg(target_os = "macos")]
pub mod kdebug;
pub mod heap;
// macOS heap shm ring (recorder side; shares the wire layout with the preload).
#[cfg(target_os = "macos")]
pub mod heap_ring;
// macOS heap control channel (recorder side; connect + SCM_RIGHTS fd pass).
#[cfg(target_os = "macos")]
pub mod heap_protocol;
// Temporary privileged-pid marker (hack; appended to the trace file).
pub mod privileged_marker;
// macOS CPU-samples capture worker (owns the worker thread + SDK lifecycle).
#[cfg(target_os = "macos")]
pub mod macos_cpu_capture;
// macOS sched (kdebug) capture worker.
#[cfg(target_os = "macos")]
pub mod macos_sched_capture;
// macOS per-sample CPU capture (Mach thread ops + unwind + encode).
#[cfg(target_os = "macos")]
pub mod mach_sampler;
// macOS libproc bindings (proc_pidinfo/proc_pidpath are Darwin symbols).
#[cfg(target_os = "macos")]
pub mod proc_info;
pub mod proc_maps;
pub mod proto;
pub mod sched_protos;
// Shared capture-worker plumbing (producer C ABI + Event).
pub mod worker_sdk;
pub mod session_config;
pub mod sismo_config;
pub mod symbolizer;
pub mod unwinder;
