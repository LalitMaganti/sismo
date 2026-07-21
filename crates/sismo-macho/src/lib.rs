// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Mach-O / dyld platform support: the macOS-specific substrate the capture
//! and symbolization layers build on. Everything OS-specific about mach-o
//! images lives here — in-memory image enumeration and reading via Mach APIs,
//! and symbol extraction from the dyld shared cache — so the cross-platform
//! crates hold policy, not platform code.
//!
//! Both modules are macOS-gated here (not at the call sites): on any other OS
//! this crate compiles to nothing, which keeps workspace-wide lint/test sweeps
//! working without per-consumer cfg scatter.

// Module enumeration + in-memory mach-o reading (Mach task APIs).
#[cfg(target_os = "macos")]
pub mod dyld_images;
// Symbol extraction for dylibs that exist only inside the dyld shared cache.
#[cfg(target_os = "macos")]
pub mod dyld_cache;
// LC_UUID identity checks for on-disk mach-o files (symbolize side).
#[cfg(target_os = "macos")]
pub mod file_uuid;
