// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! extern "C" facade exposing the Rust-side helpers (framehop unwinder,
//! wholesym symbolizer) to Zig over a cargo→staticlib→Zig link.

pub mod cli;
pub mod data_regions;
pub mod disasm;
pub mod heap;
pub mod proc_maps;
pub mod proto;
pub mod symbolizer;
pub mod unwinder;
