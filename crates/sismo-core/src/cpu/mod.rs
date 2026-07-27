// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! CPU-samples capture: the Linux eBPF collector plus PMU event selection.
//!
//! macOS CPU sampling is not here — it rides the shared kperf timer action in
//! `sched::ring_host` / `sched::kperf_sample` (one worker owns the kdebug ring
//! and kperf singleton for sched, off-CPU, and on-CPU together).

// Linux eBPF CPU-samples collector (owns the worker thread + BPF lifecycle).
#[cfg(target_os = "linux")]
pub mod linux_bpf_capture;
// CAP-3(b): registry of sampled module files (holds fds so deleted binaries
// still symbolize). Platform-agnostic policy + (dev,inode) dedup; the held-fd
// path is /proc/self/fd on Linux, /dev/fd on macOS. POSIX-only.
#[cfg(not(target_os = "windows"))]
pub mod module_registry;
// JIT-1: perf-map (`/tmp/perf-<pid>.map`) JIT symbol lookup, shared by the
// Linux and macOS capture pipelines.
#[cfg(not(target_os = "windows"))]
pub mod jit_map;
#[cfg(target_os = "linux")]
pub mod pmu_events;
// Loads lightswitch-format unwind tables (.eh_frame -> compact
// rows via the lightswitch-unwind-info crate) into the BPF maps the in-kernel
// unwinder in sismo_unwind.bpf.h walks. The walker is x86-64-only; activation
// is gated in capture_init.
#[cfg(target_os = "linux")]
pub mod unwind_tables;
