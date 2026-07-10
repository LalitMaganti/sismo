// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Framehop FFI surface — the Rust unwinder samply uses, exposed for Zig.
//!
//! Lifecycle: `sismo_unwinder_create_arm64()` returns an opaque handle;
//! callers register one or more loaded mach-o images with
//! `sismo_unwinder_add_module(...)`, then unwind a thread snapshot via
//! `sismo_unwinder_walk(...)`. `sismo_unwinder_destroy(...)` releases
//! everything.
//!
//! The opaque `*mut Unwinder` is a `Box<Unwinder>::into_raw()` — never
//! deref'd outside Rust. The Zig side treats it as opaque.
//!
//! Mach-o data passed to `add_module` is expected to be the in-memory
//! image as seen in the target process — i.e. a contiguous slab read via
//! `mach_vm_read_overwrite` starting at the LC_SEGMENT_64 __TEXT base
//! (= `base_avma`). If a section's bytes lie outside the buffer (caller
//! didn't read enough), that section is silently skipped; framehop
//! tolerates partial section info as long as `unwind_info` or `eh_frame`
//! is present.

use framehop::aarch64::{CacheAarch64, PtrAuthMask, UnwindRegsAarch64, UnwinderAarch64};
use framehop::{ExplicitModuleSectionInfo, Module, Unwinder as _};
use object::endian::{BigEndian, LittleEndian};
use object::macho::{MachHeader64, Section64, SegmentCommand64, LC_SEGMENT_64, MH_CIGAM_64};
use object::pod;
use std::os::raw::{c_int, c_void};
use std::slice;

/// Opaque handle exposed to C / Zig. Bundles the unwinder state and the
/// per-thread cache framehop wants `&mut`'d on every `iter_frames` call.
/// One handle per profiled process is the intended usage.
pub struct Unwinder {
    inner: UnwinderAarch64<Vec<u8>>,
    cache: CacheAarch64,
}

/// Callback signature passed to `sismo_unwinder_walk`. Reads 8 bytes from
/// the target task's address space at `addr`, writes them to `*out_value`.
/// Returns 0 on success, non-zero on failure (e.g. address unmapped).
/// `user_data` is the opaque pointer the caller passed alongside the cb.
pub type ReadStackCb =
    unsafe extern "C" fn(addr: u64, out_value: *mut u64, user_data: *mut c_void) -> c_int;

#[unsafe(no_mangle)]
pub extern "C" fn sismo_unwinder_create_arm64() -> *mut Unwinder {
    let u = Box::new(Unwinder {
        inner: UnwinderAarch64::new(),
        cache: CacheAarch64::new(),
    });
    Box::into_raw(u)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_unwinder_destroy(p: *mut Unwinder) {
    if p.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(p) });
}

/// Register a loaded mach-o image. Returns:
///   `0` on success,
///  `-1` if the bytes don't parse as a 64-bit mach-o,
///  `-2` if the parse succeeded but no usable unwind sections were found.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_unwinder_add_module(
    p: *mut Unwinder,
    base_avma: u64,
    mach_o_data: *const u8,
    mach_o_len: usize,
) -> c_int {
    if p.is_null() || mach_o_data.is_null() || mach_o_len == 0 {
        return -1;
    }
    let unwinder = unsafe { &mut *p };
    let bytes = unsafe { slice::from_raw_parts(mach_o_data, mach_o_len) };

    // Parse manually rather than via `MachOFile64::parse` — that path
    // eagerly validates LC_SYMTAB's offset, which lives in __LINKEDIT
    // and is therefore outside our __TEXT-only buffer. We only care
    // about LC_SEGMENT_64 commands here.
    let endian = LittleEndian;

    let (header, after_header): (&MachHeader64<LittleEndian>, _) =
        match pod::from_bytes(bytes) {
            Ok(x) => x,
            Err(_) => return -1,
        };
    // object's convention: magic is always read as BigEndian. The result
    // equals MH_CIGAM_64 for a little-endian-encoded mach-o (e.g. arm64
    // macOS). Anything else: not a 64-bit LE mach-o.
    if header.magic.get(BigEndian) != MH_CIGAM_64 {
        return -1;
    }
    let ncmds = header.ncmds.get(endian) as usize;
    let sizeofcmds = header.sizeofcmds.get(endian) as usize;
    let cmds = match after_header.get(..sizeofcmds) {
        Some(s) => s,
        None => return -1,
    };

    let mut info: ExplicitModuleSectionInfo<Vec<u8>> = Default::default();
    let mut base_svma: u64 = 0;
    let mut max_end_svma: u64 = 0;
    let mut have_text_segment = false;

    let mut off: usize = 0;
    for _ in 0..ncmds {
        // load_command header: cmd:u32, cmdsize:u32.
        if off + 8 > cmds.len() {
            break;
        }
        let cmd = u32::from_le_bytes([cmds[off], cmds[off + 1], cmds[off + 2], cmds[off + 3]]);
        let cmdsize_u32 =
            u32::from_le_bytes([cmds[off + 4], cmds[off + 5], cmds[off + 6], cmds[off + 7]]);
        let cmdsize = cmdsize_u32 as usize;
        if cmdsize == 0 || off + cmdsize > cmds.len() {
            break;
        }

        if cmd == LC_SEGMENT_64 && cmdsize >= core::mem::size_of::<SegmentCommand64<LittleEndian>>()
        {
            let seg_bytes = &cmds[off..off + cmdsize];
            let (seg, after_seg): (&SegmentCommand64<LittleEndian>, _) =
                match pod::from_bytes(seg_bytes) {
                    Ok(x) => x,
                    Err(_) => {
                        off += cmdsize;
                        continue;
                    }
                };
            let segname_len = seg.segname.iter().position(|&b| b == 0).unwrap_or(16);
            let segname = &seg.segname[..segname_len];
            let vmaddr = seg.vmaddr.get(endian);
            let vmsize = seg.vmsize.get(endian);
            let seg_end = vmaddr.saturating_add(vmsize);
            max_end_svma = max_end_svma.max(seg_end);

            if segname == b"__TEXT" {
                have_text_segment = true;
                base_svma = vmaddr;
                info.text_segment_svma = Some(vmaddr..seg_end);
                let fileoff = seg.fileoff.get(endian) as usize;
                let filesize = seg.filesize.get(endian) as usize;
                if let Some(slab) = bytes.get(fileoff..fileoff.saturating_add(filesize)) {
                    info.text_segment = Some(slab.to_vec());
                }
            }

            // Sections live inline right after the segment_command_64
            // struct, in `after_seg`. Cast `nsects` of them.
            let nsects = seg.nsects.get(endian) as usize;
            let (sections, _): (&[Section64<LittleEndian>], _) =
                match pod::slice_from_bytes(after_seg, nsects) {
                    Ok(x) => x,
                    Err(_) => {
                        off += cmdsize;
                        continue;
                    }
                };
            for sect in sections {
                let sec_segname_len =
                    sect.segname.iter().position(|&b| b == 0).unwrap_or(16);
                let sec_segname = &sect.segname[..sec_segname_len];
                let sectname_len =
                    sect.sectname.iter().position(|&b| b == 0).unwrap_or(16);
                let sectname = &sect.sectname[..sectname_len];
                let addr = sect.addr.get(endian);
                let size = sect.size.get(endian);
                let sec_end = addr.saturating_add(size);
                let foff = sect.offset.get(endian) as usize;
                let data = bytes.get(foff..foff.saturating_add(size as usize));

                match (sec_segname, sectname) {
                    (b"__TEXT", b"__text") => {
                        info.text_svma = Some(addr..sec_end);
                        if let Some(d) = data {
                            info.text = Some(d.to_vec());
                        }
                    }
                    (b"__TEXT", b"__stubs") => {
                        info.stubs_svma = Some(addr..sec_end);
                    }
                    (b"__TEXT", b"__stub_helper") => {
                        info.stub_helper_svma = Some(addr..sec_end);
                    }
                    (b"__TEXT", b"__unwind_info") => {
                        if let Some(d) = data {
                            info.unwind_info = Some(d.to_vec());
                        }
                    }
                    (b"__TEXT", b"__eh_frame") => {
                        info.eh_frame_svma = Some(addr..sec_end);
                        if let Some(d) = data {
                            info.eh_frame = Some(d.to_vec());
                        }
                    }
                    (b"__DATA", b"__got") | (b"__DATA_CONST", b"__got") => {
                        info.got_svma = Some(addr..sec_end);
                    }
                    _ => {}
                }
            }
        }

        off += cmdsize;
    }

    if !have_text_segment {
        return -1;
    }
    info.base_svma = base_svma;
    if info.unwind_info.is_none() && info.eh_frame.is_none() {
        return -2;
    }

    let span = max_end_svma.saturating_sub(base_svma);
    let avma_range = base_avma..base_avma.saturating_add(span);
    let module = Module::new(
        format!("module@{:#x}", base_avma),
        avma_range,
        base_avma,
        info,
    );
    unwinder.inner.add_module(module);
    0
}

/// Walk the stack from a thread snapshot. Writes up to `max_pcs` AVMAs
/// into `out_pcs`. The first slot is always the snapshot `pc`; subsequent
/// slots are return addresses recovered by framehop. Returns the number
/// of slots written. Stops on first iter error (best-effort partial walk).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_unwinder_walk(
    p: *mut Unwinder,
    pc: u64,
    fp: u64,
    lr: u64,
    sp: u64,
    read_stack_cb: ReadStackCb,
    user_data: *mut c_void,
    out_pcs: *mut u64,
    max_pcs: usize,
) -> usize {
    if p.is_null() || out_pcs.is_null() || max_pcs == 0 {
        return 0;
    }
    let unwinder = unsafe { &mut *p };
    let out = unsafe { slice::from_raw_parts_mut(out_pcs, max_pcs) };

    let mut closure = |addr: u64| -> Result<u64, ()> {
        let mut v: u64 = 0;
        let rc = unsafe { read_stack_cb(addr, &mut v, user_data) };
        if rc == 0 {
            Ok(v)
        } else {
            Err(())
        }
    };

    // Apply the macOS arm64e 24/40 PAC mask to LRs framehop reads from
    // the stack. The `lr` passed in is expected to already be stripped
    // by the caller; the mask is idempotent on already-clean pointers.
    let mut iter = unwinder.inner.iter_frames(
        pc,
        UnwindRegsAarch64::new_with_ptr_auth_mask(PtrAuthMask::new_24_40(), lr, sp, fp),
        &mut unwinder.cache,
        &mut closure,
    );

    let mut n = 0;
    while n < max_pcs {
        match iter.next() {
            Ok(Some(frame)) => {
                // Write the *lookup* address: IP for slot 0 (the active
                // PC), but `LR - 1` for the return-address slots
                // (subsequent frames). The -1 is the standard adjustment
                // because LR points to the instruction *after* the bl;
                // looking up that byte often lands in the wrong basic
                // block or function. samply records the same adjusted
                // values in its profile.json.
                out[n] = frame.address_for_lookup();
                n += 1;
            }
            _ => break,
        }
    }
    n
}

/// Snapshot-mode walk: unwind from a captured stack-bytes buffer
/// instead of live process memory. Mirrors samply's
/// `linux_shared/converter.rs::get_sample_stack` pattern for
/// perf_event DWARF callstacks.
///
/// `snapshot_sp` is the stack-pointer value at capture time;
/// `snapshot_bytes` is the contents of [snapshot_sp .. snapshot_sp+len)
/// captured at that moment. Reads outside the buffer return Err to
/// framehop, which terminates the walk gracefully (samply pattern).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_unwinder_walk_snapshot(
    p: *mut Unwinder,
    pc: u64,
    fp: u64,
    lr: u64,
    sp: u64,
    snapshot_bytes: *const u8,
    snapshot_len: usize,
    snapshot_sp: u64,
    out_pcs: *mut u64,
    max_pcs: usize,
) -> usize {
    if p.is_null() || out_pcs.is_null() || max_pcs == 0 || snapshot_bytes.is_null() {
        return 0;
    }
    let unwinder = unsafe { &mut *p };
    let out = unsafe { slice::from_raw_parts_mut(out_pcs, max_pcs) };
    let snap = unsafe { slice::from_raw_parts(snapshot_bytes, snapshot_len) };

    // Per samply: read 8 bytes at virtual address `addr` by translating
    // (addr − snapshot_sp) into a buffer offset. Out-of-range reads
    // return Err — framehop emits a TruncatedStackMarker and the walk
    // ends cleanly.
    let mut read_stack = |addr: u64| -> Result<u64, ()> {
        let offset = addr.checked_sub(snapshot_sp).ok_or(())?;
        let idx_end = offset.checked_add(8).ok_or(())? as usize;
        if idx_end > snap.len() {
            return Err(());
        }
        let bytes = &snap[offset as usize..idx_end];
        let mut a = [0u8; 8];
        a.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(a))
    };

    let mut iter = unwinder.inner.iter_frames(
        pc,
        UnwindRegsAarch64::new_with_ptr_auth_mask(PtrAuthMask::new_24_40(), lr, sp, fp),
        &mut unwinder.cache,
        &mut read_stack,
    );

    let mut n = 0;
    while n < max_pcs {
        match iter.next() {
            Ok(Some(frame)) => {
                out[n] = frame.address_for_lookup();
                n += 1;
            }
            _ => break,
        }
    }
    n
}
