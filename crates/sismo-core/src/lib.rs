// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! extern "C" facade exposing the Rust-side helpers (framehop unwinder,
//! wholesym symbolizer) to Zig over a cargo→staticlib→Zig link.
//!
//! Modules are grouped by feature: `command` (the CLI subcommands), `cpu`,
//! `heap`, `sched` (the capture data sources), `proto` (wire encoding +
//! configs), and `symbolize`. `ffi`, `worker_sdk`, and `sismo_paths` are the
//! shared plumbing the groups build on.

pub mod command;
pub mod cpu;
pub mod heap;
pub mod proto;
pub mod sched;
pub mod symbolize;

// Perfetto C++ shim FFI (recording control plane + producer data-plane ABI).
pub mod ffi;
// Shared capture-worker Event primitive.
pub mod worker_sdk;
// Well-known paths + session lock / recorder-pid / heap-dylib resolution.
// POSIX-only.
#[cfg(not(target_os = "windows"))]
pub mod sismo_paths;
