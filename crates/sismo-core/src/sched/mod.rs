// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! macOS kdebug + kperf capture: the ring host that owns the shared kdebug
//! ring and kperf singleton, its sched / off-CPU / on-CPU consumers, and the
//! libproc bindings for thread naming.

// macOS kdebug (sysctl ring session handle).
#[cfg(target_os = "macos")]
pub mod kdebug;
// Shared ring abstraction (event record types + the RingConsumer contract).
#[cfg(target_os = "macos")]
pub mod ring;
// macOS kperf control plane (the shared action/timer table).
#[cfg(target_os = "macos")]
pub mod kperf;
// macOS kperf stack samples: on-CPU (timer) + off-CPU (lazy.wait) consumers.
#[cfg(target_os = "macos")]
pub mod kperf_sample;
// The ring host worker (owns the ring + kperf + all consumers + DS lifecycle).
#[cfg(target_os = "macos")]
pub mod ring_host;
// macOS libproc bindings (proc_pidinfo/proc_pidpath are Darwin symbols).
#[cfg(target_os = "macos")]
pub mod proc_info;
