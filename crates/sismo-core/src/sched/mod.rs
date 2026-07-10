// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Scheduler-events capture (macOS kdebug): the sysctl ring, the capture
//! worker, and the libproc bindings for thread naming.

// macOS kdebug (sched-event sysctl ring).
#[cfg(target_os = "macos")]
pub mod kdebug;
// macOS sched (kdebug) capture worker.
#[cfg(target_os = "macos")]
pub mod macos_sched_capture;
// macOS libproc bindings (proc_pidinfo/proc_pidpath are Darwin symbols).
#[cfg(target_os = "macos")]
pub mod proc_info;
