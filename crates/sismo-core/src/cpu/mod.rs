// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! CPU-samples capture: the Linux eBPF collector and the macOS Mach sampler,
//! plus PMU event selection.

// Linux eBPF CPU-samples collector (owns the worker thread + BPF lifecycle).
#[cfg(target_os = "linux")]
pub mod linux_bpf_capture;
#[cfg(target_os = "linux")]
pub mod pmu_events;
// macOS per-sample CPU capture (Mach thread ops + unwind + encode).
#[cfg(target_os = "macos")]
pub mod mach_sampler;
// macOS CPU-samples capture worker (owns the worker thread + SDK lifecycle).
#[cfg(target_os = "macos")]
pub mod macos_cpu_capture;
