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
// `.gopclntab` function-name resolver for stripped Go binaries (Linux/ELF).
#[cfg(not(target_os = "windows"))]
pub mod gopclntab;
mod maps_common;
// PY-1: `_Py_DebugOffsets` table parser (pure, no OS dependency; Linux-only
// because its sole consumer, python_stack, reads /proc/<pid>/mem).
#[cfg(target_os = "linux")]
pub mod python_offsets;
// PY-1: live CPython 3.14+ frame recovery via /proc/<pid>/mem (Linux-only).
#[cfg(target_os = "linux")]
pub mod python_stack;
// DIA-0: per-module stack-quality primitive (truncation signal + eh_frame probe).
#[cfg(not(target_os = "windows"))]
pub mod stack_quality;
// FLAG-noeh: detect a module with no .eh_frame FDE coverage for its own code and
// no frame pointers — the one build shape sismo cannot unwind by any path.
#[cfg(not(target_os = "windows"))]
pub mod unwind_tables;
// macOS Mach-based module enumeration + mach-o reading.
#[cfg(target_os = "macos")]
pub mod dyld_images;
// Post-record symbolization + source/asm sidecar (Linux bpf path; POSIX-only).
#[cfg(not(target_os = "windows"))]
pub mod perf_symbolize;
pub mod proc_maps;
pub mod symbolizer;
pub mod unwinder;
