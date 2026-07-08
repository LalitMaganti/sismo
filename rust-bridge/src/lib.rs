// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! extern "C" facade exposing the Rust-side helpers (framehop unwinder,
//! wholesym symbolizer) to Zig over a cargo→staticlib→Zig link.

pub mod cli;
pub mod data_regions;
pub mod disasm;
pub mod heap;
// macOS libproc bindings (proc_pidinfo/proc_pidpath are Darwin symbols).
#[cfg(target_os = "macos")]
pub mod proc_info;
pub mod proc_maps;
pub mod proto;
pub mod session_config;
pub mod sismo_config;
pub mod symbolizer;
pub mod unwinder;
