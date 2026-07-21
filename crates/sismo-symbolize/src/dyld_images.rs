// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Registration glue over `sismo-macho`'s dyld image reading: enumerate a
//! task's images and feed them to the symbolizer (wholesym) and unwinder
//! (framehop). The Mach reads and mach-o parsing live in `sismo_macho`
//! (re-exported here so consumers keep one import path); this module owns only
//! the part that needs those consumers' types.
//!
//! macOS-only; gated in lib.rs.

pub use sismo_macho::dyld_images::*;

use crate::symbolizer::Symbolizer;
use crate::unwinder::Unwinder;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;

type MachPort = u32;

/// Map (cputype, cpusubtype) to wholesym's arch string, or None for unknown.
/// (<mach/machine.h>: CPU_TYPE_X86_64 = 0x01000007, CPU_TYPE_ARM64 = 0x0100000C;
/// the top byte of cpusubtype is feature bits.)
fn arch_string(cputype: u32, cpusubtype: u32) -> Option<&'static str> {
    let sub = cpusubtype & 0x00FF_FFFF;
    match cputype {
        0x0100_0007 => match sub {
            0 | 3 => Some("x86_64"),
            8 => Some("x86_64h"),
            _ => None,
        },
        0x0100_000C => match sub {
            0 | 1 => Some("arm64"),
            2 => Some("arm64e"),
            _ => None,
        },
        _ => None,
    }
}

/// Enumerate the target's modules (retrying the post-spawn empty-list window,
/// polling `abort` between tries), sort by load address, and register each into
/// `symbolizer` and/or `unwinder` when present — reading each image's `__TEXT`
/// slab and computing its end address from `__TEXT` vmsize clamped to the next
/// image's base. Returns the sorted `ImageList` for the caller to reuse (e.g.
/// heap mappings); `Err(ERR_*)` on enumerate failure.
///
/// The dyld read, the mach-o parse, and the symbolizer/unwinder registration
/// all happen here, so the `__TEXT` bytes never cross a module boundary.
pub fn load_target_modules(
    task: MachPort,
    mut symbolizer: Option<&mut Symbolizer>,
    mut unwinder: Option<&mut Unwinder>,
    poll_interval_ns: u64,
    max_total_ns: u64,
    abort: impl Fn() -> bool,
) -> Result<ImageList, u32> {
    // Enumerate with retry on the empty-list window.
    let max_attempts = if poll_interval_ns == 0 { 1 } else { max_total_ns / poll_interval_ns };
    let mut attempt: u64 = 0;
    let mut list = loop {
        match ImageList::enumerate(task) {
            Ok(l) => break l,
            Err(err) => {
                if err != ERR_EMPTY || attempt + 1 >= max_attempts {
                    return Err(err);
                }
                if abort() {
                    return Err(ERR_EMPTY);
                }
                std::thread::sleep(Duration::from_nanos(poll_interval_ns));
                attempt += 1;
            }
        }
    };

    list.sort_by_base();

    let n = list.len();
    for idx in 0..n {
        let base = list.images()[idx].0;
        let next_base = if idx + 1 < n { list.images()[idx + 1].0 } else { u64::MAX };

        let macho = match read_macho(task, base) {
            Some(m) => m,
            None => continue,
        };

        let end_avma = base.wrapping_add(macho.text_vmsize).min(next_base);
        if let Some(sym) = symbolizer.as_deref_mut() {
            let path = &list.images()[idx].1;
            let arch = arch_string(macho.cputype, macho.cpusubtype);
            sym.add_module(base, end_avma, Path::new(OsStr::from_bytes(path)), Some(macho.uuid), arch);
        }
        if let Some(unw) = unwinder.as_deref_mut() {
            unw.add_module(base, &macho.text);
        }
    }

    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" {
        static mach_task_self_: MachPort;
    }

    #[test]
    fn load_own_modules_into_symbolizer_and_unwinder() {
        // End-to-end: enumerate own images, read each mach-o, and register into
        // a real symbolizer + unwinder, exercised without root.
        let task = unsafe { mach_task_self_ };
        let mut sym = Symbolizer::new().unwrap();
        let mut unw = Unwinder::new_arm64();
        let list = load_target_modules(task, Some(&mut sym), Some(&mut unw), 0, 0, || false)
            .expect("load failed");
        assert!(!list.is_empty());
    }
}
