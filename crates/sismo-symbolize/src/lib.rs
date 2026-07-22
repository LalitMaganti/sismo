// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Symbolization and address→region resolution: the framehop unwinder, the
//! wholesym symbolizer, the post-record symbolize pass, the disassembler, and
//! the process-map / data-region / dyld-image helpers they build on.

pub mod data_regions;
pub mod disasm;
// Shared 64-bit ELF view (program headers, PT_DYNAMIC, sections) over object's
// typed reader — the common substrate for the phdr/shdr parsers below.
#[cfg(not(target_os = "windows"))]
pub mod elf;
// `.dynsym`-via-PT_DYNAMIC fallback for section-header-stripped ELF (Linux/ELF).
#[cfg(not(target_os = "windows"))]
pub mod dynsym;
// `.gopclntab` function-name resolver for stripped Go binaries (Linux/ELF).
#[cfg(not(target_os = "windows"))]
pub mod gopclntab;
// /proc/kallsyms kernel-symbol source: kernel frames ship raw and resolve here.
#[cfg(target_os = "linux")]
pub mod kallsyms;
mod maps_common;
// PY-1: `_Py_DebugOffsets` table parser (pure, no OS dependency).
#[cfg(not(target_os = "windows"))]
pub mod python_offsets;
// PY-1: live CPython 3.14+ frame recovery. The walk is memory-source-generic
// (RemoteMem); Linux reads /proc/<pid>/mem, macOS reads via the task port,
// Windows will read via ReadProcessMemory.
#[cfg(not(target_os = "windows"))]
pub mod python_stack;
// DIA-0: per-module stack-quality primitive (truncation signal + eh_frame probe).
#[cfg(not(target_os = "windows"))]
pub mod stack_quality;
// FLAG-noeh: detect a module with no .eh_frame FDE coverage for its own code and
// no frame pointers — the one build shape sismo cannot unwind by any path.
#[cfg(not(target_os = "windows"))]
pub mod unwind_tables;
// macOS module registration glue over sismo-macho's dyld image reading (the
// Mach/mach-o platform code itself lives in the sismo-macho crate).
#[cfg(target_os = "macos")]
pub mod dyld_images;
// Trust decisions about on-disk byte sources — the one place a trace build-id
// is matched against a file's platform identity (ELF note vs mach-o LC_UUID).
pub mod byte_source;
// The names-only fallback sources behind wholesym, and the one place the
// per-platform set is chosen.
pub mod fallback;
// Post-record symbolization + source/asm sidecar (both record paths; POSIX-only).
#[cfg(not(target_os = "windows"))]
pub mod perf_symbolize;
pub mod proc_maps;
pub mod symbolizer;
pub mod unwinder;
