// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Module enumeration + in-memory mach-o reading. Walks a task's
//! `dyld_all_image_infos` to yield
//! (base_avma, path) tuples, and reads each image's `__TEXT` segment + UUID —
//! the inputs framehop (unwinder) and wholesym (symbolizer) consume.
//!
//! Data path (same as samply's DyldInfoManager): `task_info(TASK_DYLD_INFO)`
//! gives the address of the target's `dyld_all_image_infos`; `mach_vm_read`
//! reads the header (infoArrayCount + infoArray), then the image array, then
//! each `imageLoadAddress` / `imageFilePath`.
//!
//! macOS-only (Mach APIs); gated in lib.rs. Works on the caller's own task
//! (`mach_task_self_`) without root — the tests exercise it that way.

use crate::symbolizer::Symbolizer;
use crate::unwinder::Unwinder;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;

type MachPort = u32;
const KERN_SUCCESS: i32 = 0;
const TASK_DYLD_INFO: u32 = 17;

const MH_MAGIC_64: u32 = 0xfeed_facf;
const LC_SEGMENT_64: u32 = 0x19;
const LC_UUID: u32 = 0x1b;

// dyld_image_info entry (64-bit): imageLoadAddress, imageFilePath, modDate.
const IMAGE_INFO_SIZE: usize = 24;

// Enumerate error codes; only EMPTY drives the retry loop.
const ERR_TASK_INFO: u32 = 1;
const ERR_EMPTY: u32 = 2;
const ERR_VM_READ: u32 = 3;

extern "C" {
    fn task_info(target: MachPort, flavor: u32, task_info_out: *mut i32, count: *mut u32) -> i32;
    fn mach_vm_read_overwrite(
        target: MachPort,
        address: u64,
        size: u64,
        data: u64,
        out_size: *mut u64,
    ) -> i32;
}

// Only the tests read the caller's own task (production always passes a
// task_for_pid'd port in from Zig).
#[cfg(test)]
extern "C" {
    static mach_task_self_: MachPort;
}

#[repr(C)]
#[derive(Default)]
struct TaskDyldInfo {
    all_image_info_addr: u64,
    all_image_info_size: u64,
    all_image_info_format: i32,
}

/// Read up to `buf.len()` bytes from `task`'s address space at `addr`. Returns
/// the transferred count (short reads are success), or None on Mach failure.
unsafe fn vm_read(task: MachPort, addr: u64, buf: &mut [u8]) -> Option<usize> {
    let mut got: u64 = 0;
    let rc = unsafe {
        mach_vm_read_overwrite(task, addr, buf.len() as u64, buf.as_mut_ptr() as u64, &mut got)
    };
    if rc != KERN_SUCCESS {
        return None;
    }
    Some(got as usize)
}

fn read_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn read_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// Read a NUL-terminated path from `addr` in `task`. "" for a null address,
/// "?" on read failure.
unsafe fn read_cstring(task: MachPort, addr: u64) -> Vec<u8> {
    if addr == 0 {
        return Vec::new();
    }
    let mut buf = [0u8; 1024];
    match unsafe { vm_read(task, addr, &mut buf) } {
        Some(got) => {
            let s = &buf[..got];
            let nul = s.iter().position(|&b| b == 0).unwrap_or(got);
            s[..nul].to_vec()
        }
        None => b"?".to_vec(),
    }
}

/// Owned list of loaded mach-o images: `(base_avma, path)` per image.
pub struct ImageList {
    images: Vec<(u64, Vec<u8>)>,
}

impl ImageList {
    /// Enumerate all loaded mach-o images in `task`. `Err(ERR_*)` on failure
    /// (the caller retries on `ERR_EMPTY`).
    pub fn enumerate(task: MachPort) -> Result<ImageList, u32> {
        let mut info = TaskDyldInfo::default();
        let mut count = (std::mem::size_of::<TaskDyldInfo>() / 4) as u32;
        let rc = unsafe {
            task_info(task, TASK_DYLD_INFO, &mut info as *mut TaskDyldInfo as *mut i32, &mut count)
        };
        if rc != KERN_SUCCESS {
            return Err(ERR_TASK_INFO);
        }
        if info.all_image_info_addr == 0 {
            return Err(ERR_EMPTY);
        }

        // dyld_all_image_infos head: version(u32), infoArrayCount(u32), infoArray(u64).
        let mut head = [0u8; 16];
        match unsafe { vm_read(task, info.all_image_info_addr, &mut head) } {
            Some(n) if n >= 16 => {}
            _ => return Err(ERR_VM_READ),
        }
        let info_array_count = read_u32(&head, 4);
        let info_array = read_u64(&head, 8);
        if info_array == 0 || info_array_count == 0 {
            return Err(ERR_EMPTY);
        }

        let mut entries = vec![0u8; info_array_count as usize * IMAGE_INFO_SIZE];
        let got = match unsafe { vm_read(task, info_array, &mut entries) } {
            Some(g) => g,
            None => return Err(ERR_VM_READ),
        };
        let usable = got / IMAGE_INFO_SIZE;

        let mut images = Vec::with_capacity(usable);
        for i in 0..usable {
            let e = &entries[i * IMAGE_INFO_SIZE..];
            let load_address = read_u64(e, 0);
            let file_path = read_u64(e, 8);
            let path = unsafe { read_cstring(task, file_path) };
            images.push((load_address, path));
        }
        Ok(ImageList { images })
    }

    pub fn len(&self) -> usize {
        self.images.len()
    }

    pub fn is_empty(&self) -> bool {
        self.images.is_empty()
    }

    /// `(base_avma, path)` for each image (sorted by base after `load_target_modules`).
    pub fn images(&self) -> &[(u64, Vec<u8>)] {
        &self.images
    }
}

/// An in-memory mach-o image read from a target task.
pub struct MachoImage {
    /// The `__TEXT` slab; may be a short read near a mapping edge — framehop's
    /// parser tolerates partial section data.
    pub text: Vec<u8>,
    pub text_vmsize: u64,
    pub cputype: u32,
    pub cpusubtype: u32,
    pub uuid: [u8; 16],
}

/// Read the in-memory mach-o image at `base_avma`: enough of `__TEXT` for
/// framehop, plus metadata. `None` on any failure (not a 64-bit mach-o, no
/// `__TEXT`, or a failed read).
pub fn read_macho(task: MachPort, base_avma: u64) -> Option<MachoImage> {
    // Header (mach_header_64, 32 bytes).
    let mut hdr = [0u8; 32];
    match unsafe { vm_read(task, base_avma, &mut hdr) } {
        Some(n) if n >= 32 => {}
        _ => return None,
    }
    if read_u32(&hdr, 0) != MH_MAGIC_64 {
        return None;
    }
    let cputype = read_u32(&hdr, 4);
    let cpusubtype = read_u32(&hdr, 8);
    let ncmds = read_u32(&hdr, 16);
    let sizeofcmds = read_u32(&hdr, 20) as usize;

    // Load commands.
    let mut cmds = vec![0u8; sizeofcmds];
    match unsafe { vm_read(task, base_avma + 32, &mut cmds) } {
        Some(n) if n >= sizeofcmds => {}
        _ => return None,
    }

    // Walk for __TEXT.vmsize (the executable footprint) + LC_UUID.
    let mut text_vmsize: u64 = 0;
    let mut uuid = [0u8; 16];
    let mut off = 0usize;
    for _ in 0..ncmds {
        if off + 8 > cmds.len() {
            break;
        }
        let cmd = read_u32(&cmds, off);
        let cmdsize = read_u32(&cmds, off + 4) as usize;
        if cmdsize == 0 || off + cmdsize > cmds.len() {
            break;
        }
        if cmd == LC_SEGMENT_64 && cmdsize >= 72 {
            // segment_command_64: cmd,cmdsize, segname[16], vmaddr:u64, vmsize:u64,...
            let segname = &cmds[off + 8..off + 24];
            let nlen = segname.iter().position(|&b| b == 0).unwrap_or(16);
            if &segname[..nlen] == b"__TEXT" {
                text_vmsize = read_u64(&cmds, off + 32);
            }
        } else if cmd == LC_UUID && cmdsize >= 24 {
            uuid.copy_from_slice(&cmds[off + 8..off + 24]);
        }
        off += cmdsize;
    }
    if text_vmsize == 0 {
        return None;
    }

    // Read the full __TEXT segment (short reads near a mapping edge are fine).
    let mut buf = vec![0u8; text_vmsize as usize];
    let got = match unsafe { vm_read(task, base_avma, &mut buf) } {
        Some(g) => g,
        None => return None,
    };
    buf.truncate(got);

    Some(MachoImage { text: buf, text_vmsize, cputype, cpusubtype, uuid })
}

/// Map (cputype, cpusubtype) to wholesym's arch string, or None for unknown.
/// (<mach/machine.h>: CPU_TYPE_X86_64 = 0x01000007, CPU_TYPE_ARM64 = 0x0100000C;
/// the top byte of cpusubtype is feature bits.)
fn arch_string(cputype: u32, cpusubtype: u32) -> Option<&'static [u8]> {
    let sub = cpusubtype & 0x00FF_FFFF;
    match cputype {
        0x0100_0007 => match sub {
            0 | 3 => Some(b"x86_64"),
            8 => Some(b"x86_64h"),
            _ => None,
        },
        0x0100_000C => match sub {
            0 | 1 => Some(b"arm64"),
            2 => Some(b"arm64e"),
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
/// This folds what was a Zig setup loop into one Rust call: the dyld read, the
/// mach-o parse, and the symbolizer/unwinder registration are all Rust-side.
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

    list.images.sort_by_key(|(base, _)| *base);

    let n = list.images.len();
    for idx in 0..n {
        let base = list.images[idx].0;
        let next_base = if idx + 1 < n { list.images[idx + 1].0 } else { u64::MAX };

        let macho = match read_macho(task, base) {
            Some(m) => m,
            None => continue,
        };

        let end_avma = base.wrapping_add(macho.text_vmsize).min(next_base);
        if let Some(sym) = symbolizer.as_deref_mut() {
            let path = &list.images[idx].1;
            let arch = arch_string(macho.cputype, macho.cpusubtype).and_then(|a| std::str::from_utf8(a).ok());
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

    #[test]
    fn enumerate_and_read_own_images() {
        // Read our OWN task — no root needed (reading self, not task_for_pid).
        let task = unsafe { mach_task_self_ };
        let list = ImageList::enumerate(task).expect("enumerate failed");
        assert!(!list.is_empty(), "expected at least the main executable + dylibs");
        assert_ne!(list.images()[0].0, 0);

        // Find an image that reads as a 64-bit mach-o with a __TEXT segment
        // (the main executable always does).
        let mut found_macho = false;
        for (base, _) in list.images() {
            if let Some(m) = read_macho(task, *base) {
                assert!(m.text_vmsize > 0 && !m.text.is_empty());
                // Slab starts with the mach-o magic.
                assert_eq!(read_u32(&m.text, 0), MH_MAGIC_64);
                found_macho = true;
                break;
            }
        }
        assert!(found_macho, "no readable 64-bit mach-o among own images");
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

    #[test]
    fn read_macho_rejects_non_macho_address() {
        let task = unsafe { mach_task_self_ };
        // Address 0 is unmapped → vm_read fails → None.
        assert!(read_macho(task, 0).is_none());
    }
}
