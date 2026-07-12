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
#[cfg(target_os = "linux")]
pub mod pmu_events;
