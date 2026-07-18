// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Symbolization and address→region resolution: the framehop unwinder, the
//! wholesym symbolizer, the post-record symbolize pass, the disassembler, and
//! the process-map / data-region / dyld-image helpers they build on.

pub mod data_regions;
pub mod disasm;
// `.dynsym`-via-PT_DYNAMIC fallback for section-header-stripped ELF (Linux/ELF).
#[cfg(not(target_os = "windows"))]
pub mod dynsym;
mod maps_common;
// DIA-0: per-module stack-quality primitive (truncation signal + eh_frame probe).
#[cfg(not(target_os = "windows"))]
pub mod stack_quality;
// macOS Mach-based module enumeration + mach-o reading.
#[cfg(target_os = "macos")]
pub mod dyld_images;
// Post-record symbolization + source/asm sidecar (Linux bpf path; POSIX-only).
#[cfg(not(target_os = "windows"))]
pub mod perf_symbolize;
pub mod proc_maps;
pub mod symbolizer;
pub mod unwinder;
