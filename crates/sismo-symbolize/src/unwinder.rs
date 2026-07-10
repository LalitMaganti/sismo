// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Framehop-based stack unwinder for arm64 targets (the one samply uses).
//!
//! [`Unwinder::new_arm64`] creates one; register loaded mach-o images with
//! [`Unwinder::add_module`], then unwind a live thread via [`Unwinder::walk`]
//! or a captured stack buffer via [`Unwinder::walk_snapshot`].
//!
//! Mach-o data passed to `add_module` is the in-memory image as seen in the
//! target process — a contiguous slab read via `mach_vm_read_overwrite` from
//! the LC_SEGMENT_64 __TEXT base (= `base_avma`). Sections whose bytes lie
//! outside the slab are silently skipped; framehop tolerates partial section
//! info as long as `unwind_info` or `eh_frame` is present.

use framehop::aarch64::{CacheAarch64, PtrAuthMask, UnwindRegsAarch64, UnwinderAarch64};
use framehop::{ExplicitModuleSectionInfo, Module, Unwinder as _};
use object::endian::{BigEndian, LittleEndian};
use object::macho::{MachHeader64, Section64, SegmentCommand64, LC_SEGMENT_64, MH_CIGAM_64};
use object::pod;

/// The framehop unwinder plus the per-thread cache framehop wants `&mut`'d on
/// every `iter_frames` call. One handle per profiled process is intended.
pub struct Unwinder {
    inner: UnwinderAarch64<Vec<u8>>,
    cache: CacheAarch64,
}

/// The arm64 registers a stack walk starts from. `lr`/`pc` are expected to be
/// PAC-stripped by the caller.
pub struct StackRegs {
    pub pc: u64,
    pub fp: u64,
    pub lr: u64,
    pub sp: u64,
}

/// Outcome of [`Unwinder::add_module`].
pub enum AddModule {
    /// The image parsed and its unwind sections were registered.
    Added,
    /// The bytes didn't parse as a 64-bit mach-o (or had no __TEXT segment).
    NotMachO,
    /// The parse succeeded but no usable unwind sections were found.
    NoUnwindInfo,
}

impl Unwinder {
    pub fn new_arm64() -> Unwinder {
        Unwinder {
            inner: UnwinderAarch64::new(),
            cache: CacheAarch64::new(),
        }
    }

    /// Register a loaded mach-o image (the in-memory `__TEXT`-based slab read
    /// from the target at `base_avma`). Sections whose bytes lie outside the
    /// slab are skipped; framehop tolerates partial info as long as
    /// `unwind_info` or `eh_frame` is present.
    pub fn add_module(&mut self, base_avma: u64, mach_o_data: &[u8]) -> AddModule {
        register_macho(&mut self.inner, base_avma, mach_o_data)
    }

    /// Walk the stack from a live thread snapshot, reading target memory via
    /// `read_stack` (8 bytes at a virtual address, `Err` on an unmapped read).
    /// Returns up to `max_pcs` AVMAs: slot 0 is the snapshot `pc`, the rest are
    /// framehop-recovered return addresses. Stops on the first iter error.
    pub fn walk(
        &mut self,
        regs: StackRegs,
        mut read_stack: impl FnMut(u64) -> Result<u64, ()>,
        max_pcs: usize,
    ) -> Vec<u64> {
        // Apply the macOS arm64e 24/40 PAC mask to LRs framehop reads from the
        // stack. The `lr` passed in is expected to already be stripped; the mask
        // is idempotent on already-clean pointers.
        let mut iter = self.inner.iter_frames(
            regs.pc,
            UnwindRegsAarch64::new_with_ptr_auth_mask(PtrAuthMask::new_24_40(), regs.lr, regs.sp, regs.fp),
            &mut self.cache,
            &mut read_stack,
        );

        let mut out = Vec::new();
        while out.len() < max_pcs {
            match iter.next() {
                // Push the *lookup* address: IP for slot 0 (the active PC), but
                // `LR - 1` for return-address slots — LR points just past the
                // `bl`, so looking up that byte often lands in the wrong basic
                // block. framehop's `address_for_lookup` applies the -1; samply
                // records the same adjusted values.
                Ok(Some(frame)) => out.push(frame.address_for_lookup()),
                _ => break,
            }
        }
        out
    }

    /// Snapshot-mode walk: unwind from a captured stack-bytes buffer instead of
    /// live process memory. `snapshot_sp` is the stack pointer at capture time
    /// and `snapshot_bytes` is `[snapshot_sp .. snapshot_sp+len)`. Reads outside
    /// the buffer terminate the walk gracefully (samply's DWARF-callstack
    /// pattern).
    pub fn walk_snapshot(
        &mut self,
        regs: StackRegs,
        snapshot_bytes: &[u8],
        snapshot_sp: u64,
        max_pcs: usize,
    ) -> Vec<u64> {
        let read_stack = |addr: u64| -> Result<u64, ()> {
            let offset = addr.checked_sub(snapshot_sp).ok_or(())?;
            let idx_end = offset.checked_add(8).ok_or(())? as usize;
            let bytes = snapshot_bytes.get(offset as usize..idx_end).ok_or(())?;
            Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
        };
        self.walk(regs, read_stack, max_pcs)
    }
}

/// Parse a mach-o `__TEXT` slab and register its unwind sections into `inner`.
/// Split out from [`Unwinder::add_module`] to keep the parse at free-function
/// indentation.
fn register_macho(
    inner: &mut UnwinderAarch64<Vec<u8>>,
    base_avma: u64,
    bytes: &[u8],
) -> AddModule {
    if bytes.is_empty() {
        return AddModule::NotMachO;
    }

    // Parse manually rather than via `MachOFile64::parse` — that path
    // eagerly validates LC_SYMTAB's offset, which lives in __LINKEDIT
    // and is therefore outside our __TEXT-only buffer. We only care
    // about LC_SEGMENT_64 commands here.
    let endian = LittleEndian;

    let (header, after_header): (&MachHeader64<LittleEndian>, _) =
        match pod::from_bytes(bytes) {
            Ok(x) => x,
            Err(_) => return AddModule::NotMachO,
        };
    // object's convention: magic is always read as BigEndian. The result
    // equals MH_CIGAM_64 for a little-endian-encoded mach-o (e.g. arm64
    // macOS). Anything else: not a 64-bit LE mach-o.
    if header.magic.get(BigEndian) != MH_CIGAM_64 {
        return AddModule::NotMachO;
    }
    let ncmds = header.ncmds.get(endian) as usize;
    let sizeofcmds = header.sizeofcmds.get(endian) as usize;
    let cmds = match after_header.get(..sizeofcmds) {
        Some(s) => s,
        None => return AddModule::NotMachO,
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
        return AddModule::NotMachO;
    }
    info.base_svma = base_svma;
    if info.unwind_info.is_none() && info.eh_frame.is_none() {
        return AddModule::NoUnwindInfo;
    }

    let span = max_end_svma.saturating_sub(base_svma);
    let avma_range = base_avma..base_avma.saturating_add(span);
    let module = Module::new(
        format!("module@{:#x}", base_avma),
        avma_range,
        base_avma,
        info,
    );
    inner.add_module(module);
    AddModule::Added
}

