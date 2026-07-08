// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Module enumeration + in-memory mach-o reading (migrated from
//! src/macos/dyld_images.zig). Walks a task's `dyld_all_image_infos` to yield
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

use crate::symbolizer::{sismo_symbolizer_add_module, Symbolizer};
use crate::unwinder::{sismo_unwinder_add_module, Unwinder};
use std::os::raw::c_void;
use std::time::Duration;

type MachPort = u32;
const KERN_SUCCESS: i32 = 0;
const TASK_DYLD_INFO: u32 = 17;

const MH_MAGIC_64: u32 = 0xfeed_facf;
const LC_SEGMENT_64: u32 = 0x19;
const LC_UUID: u32 = 0x1b;

// dyld_image_info entry (64-bit): imageLoadAddress, imageFilePath, modDate.
const IMAGE_INFO_SIZE: usize = 24;

// Enumerate error codes surfaced to the Zig facade (which maps them back to
// its error set; only EMPTY drives the retry loop).
const ERR_OK: u32 = 0;
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
/// "?" on read failure (matching the prior Zig behavior).
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

/// Owned image list handed to the Zig facade via index accessors.
pub struct ImageList {
    images: Vec<(u64, Vec<u8>)>, // (base_avma, path)
}

/// Enumerate all loaded mach-o images in `task`. On success returns a heap
/// `ImageList` (free with `sismo_dyld_list_free`) and writes ERR_OK; on failure
/// returns null and writes an ERR_* code (the facade retries on ERR_EMPTY).
///
/// # Safety
/// `out_err` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_dyld_enumerate(task: MachPort, out_err: *mut u32) -> *mut ImageList {
    let set_err = |e: u32| unsafe { *out_err = e };

    let mut info = TaskDyldInfo::default();
    let mut count = (std::mem::size_of::<TaskDyldInfo>() / 4) as u32;
    let rc = unsafe {
        task_info(task, TASK_DYLD_INFO, &mut info as *mut TaskDyldInfo as *mut i32, &mut count)
    };
    if rc != KERN_SUCCESS {
        set_err(ERR_TASK_INFO);
        return std::ptr::null_mut();
    }
    if info.all_image_info_addr == 0 {
        set_err(ERR_EMPTY);
        return std::ptr::null_mut();
    }

    // dyld_all_image_infos head: version(u32), infoArrayCount(u32), infoArray(u64).
    let mut head = [0u8; 16];
    match unsafe { vm_read(task, info.all_image_info_addr, &mut head) } {
        Some(n) if n >= 16 => {}
        _ => {
            set_err(ERR_VM_READ);
            return std::ptr::null_mut();
        }
    }
    let info_array_count = read_u32(&head, 4);
    let info_array = read_u64(&head, 8);
    if info_array == 0 || info_array_count == 0 {
        set_err(ERR_EMPTY);
        return std::ptr::null_mut();
    }

    let mut entries = vec![0u8; info_array_count as usize * IMAGE_INFO_SIZE];
    let got = match unsafe { vm_read(task, info_array, &mut entries) } {
        Some(g) => g,
        None => {
            set_err(ERR_VM_READ);
            return std::ptr::null_mut();
        }
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
    set_err(ERR_OK);
    Box::into_raw(Box::new(ImageList { images }))
}

/// # Safety
/// `list` must be a valid pointer from `sismo_dyld_enumerate`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_dyld_list_count(list: *const ImageList) -> usize {
    unsafe { &*list }.images.len()
}

/// Write the base address + borrowed path pointer for image `idx`. The path
/// pointer is valid until `sismo_dyld_list_free`.
///
/// # Safety
/// `list` valid; `idx < count`; out-params writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_dyld_list_get(
    list: *const ImageList,
    idx: usize,
    out_base: *mut u64,
    out_path: *mut *const u8,
    out_path_len: *mut usize,
) {
    let (base, path) = &unsafe { &*list }.images[idx];
    unsafe {
        *out_base = *base;
        *out_path = path.as_ptr();
        *out_path_len = path.len();
    }
}

/// # Safety
/// `list` must be a valid pointer from `sismo_dyld_enumerate`, freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_dyld_list_free(list: *mut ImageList) {
    if !list.is_null() {
        drop(unsafe { Box::from_raw(list) });
    }
}

/// Read the in-memory mach-o image at `base_avma`: enough of `__TEXT` for
/// framehop, plus metadata. Returns the `__TEXT` slab (free with
/// `sismo_dyld_free_bytes`) and writes metadata to the out-params; null on any
/// failure (not a 64-bit mach-o, no `__TEXT`, or a failed read).
///
/// # Safety
/// out-params writable; `out_uuid` writable for 16 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_dyld_read_macho(
    task: MachPort,
    base_avma: u64,
    out_text_vmsize: *mut u64,
    out_cputype: *mut u32,
    out_cpusubtype: *mut u32,
    out_uuid: *mut u8,
    out_bytes_len: *mut usize,
) -> *mut u8 {
    // Header (mach_header_64, 32 bytes).
    let mut hdr = [0u8; 32];
    match unsafe { vm_read(task, base_avma, &mut hdr) } {
        Some(n) if n >= 32 => {}
        _ => return std::ptr::null_mut(),
    }
    if read_u32(&hdr, 0) != MH_MAGIC_64 {
        return std::ptr::null_mut();
    }
    let cputype = read_u32(&hdr, 4);
    let cpusubtype = read_u32(&hdr, 8);
    let ncmds = read_u32(&hdr, 16);
    let sizeofcmds = read_u32(&hdr, 20) as usize;

    // Load commands.
    let mut cmds = vec![0u8; sizeofcmds];
    match unsafe { vm_read(task, base_avma + 32, &mut cmds) } {
        Some(n) if n >= sizeofcmds => {}
        _ => return std::ptr::null_mut(),
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
        return std::ptr::null_mut();
    }

    // Read the full __TEXT segment (short reads near a mapping edge are fine —
    // framehop's parser tolerates partial section data).
    let mut buf = vec![0u8; text_vmsize as usize];
    let got = match unsafe { vm_read(task, base_avma, &mut buf) } {
        Some(g) => g,
        None => return std::ptr::null_mut(),
    };
    buf.truncate(got);

    unsafe {
        *out_text_vmsize = text_vmsize;
        *out_cputype = cputype;
        *out_cpusubtype = cpusubtype;
        std::ptr::copy_nonoverlapping(uuid.as_ptr(), out_uuid, 16);
        *out_bytes_len = buf.len();
    }
    let boxed = buf.into_boxed_slice();
    Box::into_raw(boxed) as *mut u8
}

/// Free a buffer returned by `sismo_dyld_read_macho`.
///
/// # Safety
/// `ptr`/`len` must be exactly what `sismo_dyld_read_macho` returned, freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_dyld_free_bytes(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
    drop(unsafe { Box::from_raw(slice as *mut [u8]) });
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

/// Abort callback (polled between enumerate retries): return true to bail.
type AbortCb = extern "C" fn(*mut c_void) -> bool;

/// Enumerate the target's modules (retrying the post-spawn empty-list window,
/// polling `abort_cb` between tries), sort by load address, and register each
/// into the symbolizer (if non-null) + unwinder (if non-null) — reading each
/// image's `__TEXT` slab and computing its end address from `__TEXT` vmsize
/// clamped to the next image's base. Returns the sorted `ImageList` (free with
/// `sismo_dyld_list_free`) for the caller to reuse (e.g. heap mappings); writes
/// an ERR_* code to `out_err` and returns null on enumerate failure.
///
/// This folds what was a Zig setup loop into one Rust call: the dyld read, the
/// mach-o parse, and the symbolizer/unwinder registration are all Rust-side, so
/// the `__TEXT` bytes never cross FFI.
///
/// # Safety
/// `symbolizer`/`unwinder` valid-or-null; `abort_cb`/`abort_ctx` valid together
/// or the callback absent; `out_err` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_load_target_modules(
    task: MachPort,
    symbolizer: *mut Symbolizer,
    unwinder: *mut Unwinder,
    poll_interval_ns: u64,
    max_total_ns: u64,
    abort_ctx: *mut c_void,
    abort_cb: Option<AbortCb>,
    out_err: *mut u32,
) -> *mut ImageList {
    // Enumerate with retry on the empty-list window.
    let max_attempts = if poll_interval_ns == 0 { 1 } else { max_total_ns / poll_interval_ns };
    let mut attempt: u64 = 0;
    let list_ptr = loop {
        let mut err = ERR_OK;
        let p = unsafe { sismo_dyld_enumerate(task, &mut err) };
        if !p.is_null() {
            break p;
        }
        if err != ERR_EMPTY || attempt + 1 >= max_attempts {
            unsafe { *out_err = err };
            return std::ptr::null_mut();
        }
        if let Some(cb) = abort_cb {
            if cb(abort_ctx) {
                unsafe { *out_err = ERR_EMPTY };
                return std::ptr::null_mut();
            }
        }
        std::thread::sleep(Duration::from_nanos(poll_interval_ns));
        attempt += 1;
    };

    let list = unsafe { &mut *list_ptr };
    list.images.sort_by_key(|(base, _)| *base);

    let n = list.images.len();
    for idx in 0..n {
        let base = list.images[idx].0;
        let next_base = if idx + 1 < n { list.images[idx + 1].0 } else { u64::MAX };

        let (mut text_vmsize, mut cputype, mut cpusubtype, mut bytes_len) = (0u64, 0u32, 0u32, 0usize);
        let mut uuid = [0u8; 16];
        let bytes = unsafe {
            sismo_dyld_read_macho(
                task,
                base,
                &mut text_vmsize,
                &mut cputype,
                &mut cpusubtype,
                uuid.as_mut_ptr(),
                &mut bytes_len,
            )
        };
        if bytes.is_null() {
            continue;
        }

        let end_avma = base.wrapping_add(text_vmsize).min(next_base);
        if !symbolizer.is_null() {
            let (arch_ptr, arch_len) = match arch_string(cputype, cpusubtype) {
                Some(a) => (a.as_ptr(), a.len()),
                None => (std::ptr::null(), 0),
            };
            let path = &list.images[idx].1;
            unsafe {
                sismo_symbolizer_add_module(
                    symbolizer,
                    base,
                    end_avma,
                    path.as_ptr(),
                    path.len(),
                    uuid.as_ptr(),
                    arch_ptr,
                    arch_len,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    0,
                );
            }
        }
        if !unwinder.is_null() {
            unsafe { sismo_unwinder_add_module(unwinder, base, bytes, bytes_len) };
        }
        unsafe { sismo_dyld_free_bytes(bytes, bytes_len) };
    }

    unsafe { *out_err = ERR_OK };
    list_ptr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerate_and_read_own_images() {
        // Read our OWN task — no root needed (reading self, not task_for_pid).
        let task = unsafe { mach_task_self_ };
        let mut err = ERR_OK;
        let list = unsafe { sismo_dyld_enumerate(task, &mut err) };
        assert!(!list.is_null(), "enumerate failed, err={err}");
        let n = unsafe { sismo_dyld_list_count(list) };
        assert!(n > 0, "expected at least the main executable + dylibs");

        // First image: base + path present.
        let (mut base, mut path_ptr, mut path_len) = (0u64, std::ptr::null::<u8>(), 0usize);
        unsafe { sismo_dyld_list_get(list, 0, &mut base, &mut path_ptr, &mut path_len) };
        assert_ne!(base, 0);

        // Find an image that reads as a 64-bit mach-o with a __TEXT segment
        // (the main executable always does).
        let mut found_macho = false;
        for i in 0..n {
            let (mut b, mut p, mut pl) = (0u64, std::ptr::null::<u8>(), 0usize);
            unsafe { sismo_dyld_list_get(list, i, &mut b, &mut p, &mut pl) };
            let (mut tvs, mut ct, mut cst, mut blen) = (0u64, 0u32, 0u32, 0usize);
            let mut uuid = [0u8; 16];
            let bytes = unsafe {
                sismo_dyld_read_macho(task, b, &mut tvs, &mut ct, &mut cst, uuid.as_mut_ptr(), &mut blen)
            };
            if !bytes.is_null() {
                assert!(tvs > 0 && blen > 0);
                // Slab starts with the mach-o magic.
                let slab = unsafe { std::slice::from_raw_parts(bytes, blen) };
                assert_eq!(read_u32(slab, 0), MH_MAGIC_64);
                unsafe { sismo_dyld_free_bytes(bytes, blen) };
                found_macho = true;
                break;
            }
        }
        assert!(found_macho, "no readable 64-bit mach-o among own images");
        unsafe { sismo_dyld_list_free(list) };
    }

    #[test]
    fn load_own_modules_into_symbolizer_and_unwinder() {
        // End-to-end: enumerate own images, read each mach-o, and register into
        // a real symbolizer + unwinder — the whole loop that replaced the Zig
        // setup code, exercised without root.
        let task = unsafe { mach_task_self_ };
        let sym = crate::symbolizer::sismo_symbolizer_create();
        let unw = crate::unwinder::sismo_unwinder_create_arm64();
        let mut err = ERR_OK;
        let list = unsafe {
            sismo_load_target_modules(task, sym, unw, 0, 0, std::ptr::null_mut(), None, &mut err)
        };
        assert!(!list.is_null(), "load failed, err={err}");
        assert!(unsafe { sismo_dyld_list_count(list) } > 0);
        unsafe {
            sismo_dyld_list_free(list);
            crate::symbolizer::sismo_symbolizer_destroy(sym);
            crate::unwinder::sismo_unwinder_destroy(unw);
        }
    }

    #[test]
    fn read_macho_rejects_non_macho_address() {
        let task = unsafe { mach_task_self_ };
        // Address 0 is unmapped → vm_read fails → null.
        let (mut tvs, mut ct, mut cst, mut blen) = (0u64, 0u32, 0u32, 0usize);
        let mut uuid = [0u8; 16];
        let bytes =
            unsafe { sismo_dyld_read_macho(task, 0, &mut tvs, &mut ct, &mut cst, uuid.as_mut_ptr(), &mut blen) };
        assert!(bytes.is_null());
    }
}
