// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! extern "C" facade exposing the Rust-side helpers (framehop unwinder,
//! wholesym symbolizer) to Zig over a cargo→staticlib→Zig link.

pub mod cli;
// `sismo record` runners (traced + session + watch threads). macOS + Linux
// runners share the helpers here; each runner body is cfg-gated per OS.
#[cfg(not(target_os = "windows"))]
pub mod cmd_record;
// `sismo datasource` subcommand (daemonized privileged producer). POSIX-only.
#[cfg(not(target_os = "windows"))]
pub mod cmd_datasource;
// `sismo prepare` subcommand (DYLD-insert the heap client + exec). POSIX-only.
#[cfg(not(target_os = "windows"))]
pub mod cmd_prepare;
// `sismo snapshot` subcommand (flight-recorder clone client). POSIX-only.
#[cfg(not(target_os = "windows"))]
pub mod cmd_snapshot;
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
// macOS heap capture worker (drain loop + flush/stop emit via the heap builder).
#[cfg(target_os = "macos")]
pub mod macos_heap_capture;
// macOS sched (kdebug) capture worker.
#[cfg(target_os = "macos")]
pub mod macos_sched_capture;
// macOS per-sample CPU capture (Mach thread ops + unwind + encode).
#[cfg(target_os = "macos")]
pub mod mach_sampler;
// macOS libproc bindings (proc_pidinfo/proc_pidpath are Darwin symbols).
#[cfg(target_os = "macos")]
pub mod proc_info;
// Post-record symbolization + source/asm sidecar (Linux bpf path; POSIX-only).
#[cfg(not(target_os = "windows"))]
pub mod perf_symbolize;
pub mod proc_maps;
pub mod proto;
// `sismo record` arg value-parsers (seed of the eventual full record parser).
pub mod record_args;
pub mod sched_protos;
// Shared capture-worker plumbing (producer C ABI + Event).
pub mod worker_sdk;
pub mod session_config;
pub mod sismo_config;
// Well-known paths + session lock / recorder-pid / heap-dylib resolution (the
// logic behind the sismo_paths.zig facade). POSIX-only.
#[cfg(not(target_os = "windows"))]
pub mod sismo_paths;
pub mod symbolizer;
pub mod unwinder;
