// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! The sismo core library: the capture data sources, wire encoding, and
//! symbolization the `sismo-cli` commands build on.
//!
//! Modules are grouped by feature: `cpu`, `heap`, `sched` (the capture data
//! sources), `proto` (wire encoding + configs), and `symbolize`. `ffi`,
//! `worker_sdk`, and `sismo_paths` are the shared plumbing the groups build on.
//! The CLI/command layer lives in the separate `sismo-cli` crate.

pub mod cpu;
// Fsync'd lifecycle breadcrumbs for diagnosing hard machine lockups.
pub mod crashlog;
pub mod heap;
pub mod sched;

// Wire encoding + session/config protos live in their own dependency-free
// crate; re-exported here so the capture modules keep a single `proto` path.
pub use sismo_proto as proto;
// The framehop/wholesym/yaxpeax symbolization stack lives in its own crate;
// re-exported so the capture modules keep a single `symbolize` path.
pub use sismo_symbolize as symbolize;

// Perfetto C++ shim FFI (recording control plane + producer data-plane ABI).
pub mod ffi;
// Mach primitives the libc crate doesn't cover (absent or deprecated).
#[cfg(target_os = "macos")]
pub mod mach;
// Shared capture-worker Event primitive.
pub mod worker_sdk;
// Well-known paths + session lock / recorder-pid / heap-dylib resolution.
// POSIX-only.
#[cfg(not(target_os = "windows"))]
pub mod sismo_paths;
// macOS memory-map snapshot (SmapsPacket via mach_vm_region_recurse), the
// cheap state rung of `sismo dump`.
#[cfg(target_os = "macos")]
pub mod smaps_macos;
