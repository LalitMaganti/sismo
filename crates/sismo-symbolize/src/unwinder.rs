// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Framehop-based stack unwinder for arm64/mach-o and x86-64/ELF targets (the
//! offline model samply uses).
//!
//! [`Unwinder::new_arm64`] / [`Unwinder::new_x86_64`] create one; register
//! loaded images with [`Unwinder::add_module`], then unwind a captured stack
//! buffer via [`Unwinder::walk_snapshot`] (or live memory via [`Unwinder::walk`]).
//!
//! The bytes passed to `add_module` are interpreted per the unwinder's arch:
//!
//! - **arm64** — the in-memory mach-o image as seen in the target process, a
//!   contiguous slab read via `mach_vm_read_overwrite` from the LC_SEGMENT_64
//!   __TEXT base (= `base_avma`). Sections whose bytes lie outside the slab are
//!   silently skipped; framehop tolerates partial info as long as `unwind_info`
//!   or `eh_frame` is present.
//! - **x86-64** — the on-disk ELF file (`.text`/`.eh_frame`/`.eh_frame_hdr`
//!   read through the section table). `base_avma` is the module's runtime load
//!   address (the AVMA the ELF's min PT_LOAD vaddr maps to). This is the Linux
//!   NAT-1 path: capture stack bytes + `pt_regs` in BPF, unwind host-side with
//!   the executable's DWARF CFI.

use framehop::aarch64::{CacheAarch64, PtrAuthMask, UnwindRegsAarch64, UnwinderAarch64};
use framehop::x86_64::{CacheX86_64, UnwindRegsX86_64, UnwinderX86_64};
use framehop::{ExplicitModuleSectionInfo, Module, Unwinder as _};
use object::endian::{BigEndian, LittleEndian};
use object::macho::{MachHeader64, Section64, SegmentCommand64, LC_SEGMENT_64, MH_CIGAM_64};
use object::pod;

/// The framehop unwinder plus the per-thread cache framehop wants `&mut`'d on
/// every `iter_frames` call. One handle per profiled process is intended.
///
/// Tagged by target arch: arm64 registers mach-o images, x86-64 registers ELF.
pub struct Unwinder {
    inner: Inner,
}

enum Inner {
    Aarch64(UnwinderAarch64<Vec<u8>>, CacheAarch64),
    X86_64(UnwinderX86_64<Vec<u8>>, CacheX86_64),
}

/// The registers a stack walk starts from. `pc`/`fp`/`sp` are the program
/// counter, frame pointer (arm64 `fp` / x86-64 `rbp`), and stack pointer; `lr`
/// is the arm64 link register (ignored on x86-64). On arm64 `lr`/`pc` are
/// expected to be PAC-stripped by the caller.
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
    /// The bytes didn't parse as the expected object format for this arch.
    NotObject,
    /// The parse succeeded but no usable unwind sections were found.
    NoUnwindInfo,
}

impl Unwinder {
    pub fn new_arm64() -> Unwinder {
        Unwinder {
            inner: Inner::Aarch64(UnwinderAarch64::new(), CacheAarch64::new()),
        }
    }

    pub fn new_x86_64() -> Unwinder {
        Unwinder {
            inner: Inner::X86_64(UnwinderX86_64::new(), CacheX86_64::new()),
        }
    }

    /// Register a loaded image at `base_avma`. The bytes are a mach-o `__TEXT`
    /// slab (arm64) or an on-disk ELF (x86-64); see the module docs.
    pub fn add_module(&mut self, base_avma: u64, data: &[u8]) -> AddModule {
        match &mut self.inner {
            Inner::Aarch64(inner, _) => register_macho(inner, base_avma, data),
            Inner::X86_64(inner, _) => register_elf(inner, base_avma, data),
        }
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
        // Push the *lookup* address for each frame: the IP for slot 0 (the
        // active PC), but the return address minus 1 for return-address slots —
        // a return address points just past the call, so looking up that byte
        // often lands in the wrong basic block. framehop's `address_for_lookup`
        // applies the -1; samply records the same adjusted values.
        let mut out = Vec::new();
        match &mut self.inner {
            Inner::Aarch64(inner, cache) => {
                // Apply the macOS arm64e 24/40 PAC mask to LRs framehop reads
                // from the stack. The `lr` passed in is expected to already be
                // stripped; the mask is idempotent on already-clean pointers.
                let mut iter = inner.iter_frames(
                    regs.pc,
                    UnwindRegsAarch64::new_with_ptr_auth_mask(
                        PtrAuthMask::new_24_40(),
                        regs.lr,
                        regs.sp,
                        regs.fp,
                    ),
                    cache,
                    &mut read_stack,
                );
                while out.len() < max_pcs {
                    match iter.next() {
                        Ok(Some(frame)) => out.push(frame.address_for_lookup()),
                        _ => break,
                    }
                }
            }
            Inner::X86_64(inner, cache) => {
                let mut iter = inner.iter_frames(
                    regs.pc,
                    UnwindRegsX86_64::new(regs.pc, regs.sp, regs.fp),
                    cache,
                    &mut read_stack,
                );
                while out.len() < max_pcs {
                    match iter.next() {
                        Ok(Some(frame)) => out.push(frame.address_for_lookup()),
                        _ => break,
                    }
                }
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
        return AddModule::NotObject;
    }

    // Parse manually rather than via `MachOFile64::parse` — that path
    // eagerly validates LC_SYMTAB's offset, which lives in __LINKEDIT
    // and is therefore outside our __TEXT-only buffer. We only care
    // about LC_SEGMENT_64 commands here.
    let endian = LittleEndian;

    let (header, after_header): (&MachHeader64<LittleEndian>, _) =
        match pod::from_bytes(bytes) {
            Ok(x) => x,
            Err(_) => return AddModule::NotObject,
        };
    // object's convention: magic is always read as BigEndian. The result
    // equals MH_CIGAM_64 for a little-endian-encoded mach-o (e.g. arm64
    // macOS). Anything else: not a 64-bit LE mach-o.
    if header.magic.get(BigEndian) != MH_CIGAM_64 {
        return AddModule::NotObject;
    }
    let ncmds = header.ncmds.get(endian) as usize;
    let sizeofcmds = header.sizeofcmds.get(endian) as usize;
    let cmds = match after_header.get(..sizeofcmds) {
        Some(s) => s,
        None => return AddModule::NotObject,
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
        return AddModule::NotObject;
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

/// Parse an on-disk ELF and register its DWARF CFI (`.eh_frame`) into `inner`.
/// `base_avma` is the module's runtime load address — the AVMA the ELF's min
/// PT_LOAD vaddr (`base_svma`) maps to, so framehop's `avma = svma + (base_avma
/// - base_svma)` bias holds for both PIE (`base_svma == 0`) and fixed-address
/// (`ET_EXEC`) binaries.
fn register_elf(
    inner: &mut UnwinderX86_64<Vec<u8>>,
    base_avma: u64,
    bytes: &[u8],
) -> AddModule {
    use object::{Object, ObjectSection, ObjectSegment};

    let file = match object::File::parse(bytes) {
        Ok(f) => f,
        Err(_) => return AddModule::NotObject,
    };

    let mut info: ExplicitModuleSectionInfo<Vec<u8>> = Default::default();
    // The image's preferred base: the lowest PT_LOAD vaddr (0 for a PIE).
    let base_svma = file.segments().map(|s| s.address()).min().unwrap_or(0);
    info.base_svma = base_svma;

    let mut max_end_svma = base_svma;
    for seg in file.segments() {
        max_end_svma = max_end_svma.max(seg.address().saturating_add(seg.size()));
    }

    for sect in file.sections() {
        let addr = sect.address();
        let svma = addr..addr.saturating_add(sect.size());
        match sect.name() {
            Ok(".text") => {
                info.text_svma = Some(svma);
                if let Ok(d) = sect.data() {
                    info.text = Some(d.to_vec());
                }
            }
            Ok(".eh_frame") => {
                info.eh_frame_svma = Some(svma);
                if let Ok(d) = sect.data() {
                    info.eh_frame = Some(d.to_vec());
                }
            }
            Ok(".eh_frame_hdr") => {
                info.eh_frame_hdr_svma = Some(svma);
                if let Ok(d) = sect.data() {
                    info.eh_frame_hdr = Some(d.to_vec());
                }
            }
            Ok(".got") => info.got_svma = Some(svma),
            _ => {}
        }
    }

    if info.eh_frame.is_none() {
        // No `.eh_frame` reachable through the section table — either the
        // headers were stripped (`objcopy --strip-section-headers`) or there is
        // no section named `.eh_frame`. Reach the unwind sections through the
        // program headers the way the loader does, mirroring dynsym.rs's
        // PT_DYNAMIC symbol fallback. A binary with genuinely no CFI (Go) has no
        // PT_GNU_EH_FRAME either, so this leaves `info` untouched and we still
        // report NoUnwindInfo.
        let _ = fill_eh_frame_from_phdrs(bytes, &mut info);
    }

    if info.eh_frame.is_none() {
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

// Program header types for the section-header-stripped `.eh_frame` fallback.
const PT_LOAD: u32 = 1;
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;

/// Recover `.eh_frame`/`.eh_frame_hdr` from the program headers when the section
/// table can't reach them. `PT_GNU_EH_FRAME` covers `.eh_frame_hdr`, whose header
/// points at `.eh_frame`; the containing `PT_LOAD` bounds the bytes. Returns
/// `None` (leaving `info` untouched) on any malformed field or a binary with no
/// CFI, so a hostile ELF can't panic us. `bytes` is the whole on-disk ELF.
fn fill_eh_frame_from_phdrs(
    bytes: &[u8],
    info: &mut ExplicitModuleSectionInfo<Vec<u8>>,
) -> Option<()> {
    let ehdr = bytes.get(..64)?;
    if &ehdr[0..4] != b"\x7fELF" || ehdr[4] != 2 {
        return None; // not ELFCLASS64
    }
    let e_phoff = u64::from_le_bytes(ehdr[32..40].try_into().unwrap());
    let e_phentsize = u16::from_le_bytes(ehdr[54..56].try_into().unwrap()) as u64;
    let e_phnum = u16::from_le_bytes(ehdr[56..58].try_into().unwrap());
    if e_phentsize < 56 || e_phnum == 0 || e_phnum > 4096 {
        return None;
    }

    // Every PT_LOAD as (vaddr, offset, filesz) — used to map the .eh_frame vaddr
    // to a file offset — plus the PT_GNU_EH_FRAME (.eh_frame_hdr) location.
    let mut loads: Vec<(u64, u64, u64)> = Vec::new();
    let mut hdr_seg: Option<(u64, u64, u64)> = None;
    for i in 0..e_phnum as u64 {
        let off = (e_phoff + i * e_phentsize) as usize;
        let ph = bytes.get(off..off.checked_add(56)?)?;
        let p_type = u32::from_le_bytes(ph[0..4].try_into().unwrap());
        let p_offset = u64::from_le_bytes(ph[8..16].try_into().unwrap());
        let p_vaddr = u64::from_le_bytes(ph[16..24].try_into().unwrap());
        let p_filesz = u64::from_le_bytes(ph[32..40].try_into().unwrap());
        match p_type {
            PT_LOAD => loads.push((p_vaddr, p_offset, p_filesz)),
            PT_GNU_EH_FRAME => hdr_seg = Some((p_vaddr, p_offset, p_filesz)),
            _ => {}
        }
    }
    let (hdr_vaddr, hdr_off, hdr_filesz) = hdr_seg?;
    let hdr_bytes = bytes.get(hdr_off as usize..hdr_off.checked_add(hdr_filesz)? as usize)?;

    // Decode just the `eh_frame_ptr` field of `.eh_frame_hdr` to find where
    // `.eh_frame` begins; framehop re-parses the header for the FDE index.
    let eh_frame_vaddr = decode_eh_frame_ptr(hdr_bytes, hdr_vaddr)?;

    // `.eh_frame` runs from that vaddr to the end of its PT_LOAD. Handing
    // framehop the `.eh_frame_hdr` too means it binary-searches to the exact
    // FDE, so the trailing bytes past the real section are never scanned.
    let (lv, lo, lf) = loads
        .iter()
        .copied()
        .find(|&(v, _, f)| eh_frame_vaddr >= v && eh_frame_vaddr < v.checked_add(f).unwrap_or(v))?;
    let start_off = (eh_frame_vaddr - lv).checked_add(lo)? as usize;
    let end_off = lo.checked_add(lf)? as usize;
    let eh_frame = bytes.get(start_off..end_off)?;
    let eh_frame_end_vaddr = eh_frame_vaddr + (end_off - start_off) as u64;

    info.eh_frame_hdr = Some(hdr_bytes.to_vec());
    info.eh_frame_hdr_svma = Some(hdr_vaddr..hdr_vaddr + hdr_filesz);
    info.eh_frame = Some(eh_frame.to_vec());
    info.eh_frame_svma = Some(eh_frame_vaddr..eh_frame_end_vaddr);
    Some(())
}

/// Decode the `eh_frame_ptr` at offset 4 of a `.eh_frame_hdr` to an svma.
/// The header's first four bytes are `version`, `eh_frame_ptr_enc`,
/// `fde_count_enc`, `table_enc`; `eh_frame_ptr` follows, encoded per the second
/// byte (a DW_EH_PE code). gcc/clang emit `pcrel|sdata4` (0x1b); the other
/// fixed-width forms are handled too. `None` on an unsupported encoding.
fn decode_eh_frame_ptr(hdr: &[u8], hdr_vaddr: u64) -> Option<u64> {
    if hdr.len() < 4 || hdr[0] != 1 {
        return None; // unsupported .eh_frame_hdr version
    }
    let enc = hdr[1];
    const FIELD_OFF: usize = 4;
    let data = hdr.get(FIELD_OFF..)?;
    let field_vaddr = hdr_vaddr + FIELD_OFF as u64;
    let raw: i128 = match enc & 0x0f {
        0x00 | 0x04 => u64::from_le_bytes(data.get(..8)?.try_into().ok()?) as i128, // absptr/udata8
        0x03 => u32::from_le_bytes(data.get(..4)?.try_into().ok()?) as i128,        // udata4
        0x0b => i32::from_le_bytes(data.get(..4)?.try_into().ok()?) as i128,        // sdata4
        0x0c => i64::from_le_bytes(data.get(..8)?.try_into().ok()?) as i128,        // sdata8
        _ => return None,
    };
    let base: i128 = match enc & 0x70 {
        0x00 => 0,                    // absolute
        0x10 => field_vaddr as i128,  // pcrel — relative to the field itself
        0x30 => hdr_vaddr as i128,    // datarel — relative to .eh_frame_hdr start
        _ => return None,
    };
    u64::try_from(base.checked_add(raw)?).ok()
}

// A self-unwind test: capture this thread's own regs + stack, register the
// running executable's ELF, walk, and confirm framehop recovers the actual
// call chain through frame-pointer-independent DWARF CFI. This is the NAT-1
// x86-64 foundation verified in isolation, no BPF capture needed.
#[cfg(all(test, target_arch = "x86_64", target_os = "linux"))]
mod x86_64_self_unwind {
    use super::*;

    #[inline(never)]
    fn level1(out: &mut Vec<u64>, module: &[u8]) {
        level2(out, module);
        std::hint::black_box(out);
    }
    #[inline(never)]
    fn level2(out: &mut Vec<u64>, module: &[u8]) {
        level3(out, module);
        std::hint::black_box(out);
    }
    #[inline(never)]
    fn level3(out: &mut Vec<u64>, module: &[u8]) {
        capture_and_walk(out, module);
        std::hint::black_box(out);
    }

    /// The runtime load address of `/proc/self/exe`: the start of its
    /// file-offset-0 mapping, which for both a PIE (`base_svma == 0`) and a
    /// fixed-address binary equals the AVMA that `base_svma` maps to.
    fn exe_load_address() -> u64 {
        let exe = std::fs::read_link("/proc/self/exe").unwrap();
        let exe = exe.to_str().unwrap();
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        for line in maps.lines() {
            let mut it = line.split_whitespace();
            let range = it.next().unwrap();
            let _perms = it.next().unwrap();
            let offset = it.next().unwrap();
            let _dev = it.next();
            let _inode = it.next();
            let path = it.next().unwrap_or("");
            if path == exe && offset == "00000000" {
                let start = range.split('-').next().unwrap();
                return u64::from_str_radix(start, 16).unwrap();
            }
        }
        panic!("no file-offset-0 mapping for {exe}");
    }

    fn capture_and_walk(out: &mut Vec<u64>, module: &[u8]) {
        let (rip, rsp, rbp): (u64, u64, u64);
        unsafe {
            core::arch::asm!(
                "lea {rip}, [rip]",
                "mov {rsp}, rsp",
                "mov {rbp}, rbp",
                rip = out(reg) rip,
                rsp = out(reg) rsp,
                rbp = out(reg) rbp,
            );
        }
        // Snapshot our own stack upward from rsp via /proc/self/mem rather than
        // a raw copy. The stack grows down, so the caller frames we want live at
        // higher addresses. This runs on a spawned test thread whose stack is
        // far smaller than main's, and the call chain here is shallow, so rsp
        // sits close to the top — a blind 64 KiB copy runs off the end into the
        // guard page and SIGSEGVs. A pread stops cleanly at the first unmapped
        // page (short read, no fault), giving exactly the mapped stack, which is
        // all the walk needs.
        use std::os::unix::fs::FileExt;
        const SNAP: usize = 64 * 1024;
        let mem = std::fs::File::open("/proc/self/mem").unwrap();
        let mut buf = vec![0u8; SNAP];
        let n = mem.read_at(&mut buf, rsp).unwrap_or(0);
        buf.truncate(n);

        let mut unw = Unwinder::new_x86_64();
        assert!(matches!(
            unw.add_module(exe_load_address(), module),
            AddModule::Added
        ));

        *out = unw.walk_snapshot(
            StackRegs { pc: rip, fp: rbp, lr: 0, sp: rsp },
            &buf,
            rsp,
            64,
        );
    }

    /// Assert the walk recovered the level1→2→3 chain. Each caller's return
    /// address lands within a small window after its entry; these functions are
    /// tiny, so 4 KiB bounds each. Finding all three proves framehop stepped the
    /// real chain, not just that it produced some frames.
    fn assert_recovered_chain(pcs: &[u64]) {
        assert!(
            pcs.len() >= 4,
            "expected a deep chain from CFI unwinding, got {} frames: {pcs:x?}",
            pcs.len()
        );
        let want = [
            ("level1", level1 as *const () as u64),
            ("level2", level2 as *const () as u64),
            ("level3", level3 as *const () as u64),
        ];
        for (name, entry) in want {
            assert!(
                pcs.iter().any(|&pc| pc >= entry && pc < entry + 0x1000),
                "{name} (@{entry:#x}) not found in recovered pcs {pcs:x?}"
            );
        }
    }

    /// Zero the section-header fields of an ELF header, simulating `objcopy
    /// --strip-section-headers`: `object` then finds no sections and unwinding
    /// must fall back to the program headers.
    fn strip_section_headers(elf: &[u8]) -> Vec<u8> {
        let mut b = elf.to_vec();
        b[40..48].fill(0); // e_shoff
        b[58..60].fill(0); // e_shentsize
        b[60..62].fill(0); // e_shnum
        b[62..64].fill(0); // e_shstrndx
        b
    }

    #[test]
    fn recovers_the_call_chain() {
        let exe = std::fs::read("/proc/self/exe").unwrap();
        let mut pcs = Vec::new();
        level1(&mut pcs, &exe);
        assert_recovered_chain(&pcs);
    }

    // The core FLAG-sectionless-eh guarantee: with the section header table
    // gone, `register_elf` must still reach `.eh_frame`/`.eh_frame_hdr` through
    // PT_GNU_EH_FRAME + PT_LOAD and unwind exactly as it does with sections.
    #[test]
    fn recovers_the_call_chain_without_section_headers() {
        let exe = std::fs::read("/proc/self/exe").unwrap();
        let stripped = strip_section_headers(&exe);
        // Sanity: the strip really removed section-based access.
        {
            use object::Object;
            let f = object::File::parse(&stripped[..]).unwrap();
            assert!(f.section_by_name(".eh_frame").is_none());
        }
        let mut pcs = Vec::new();
        level1(&mut pcs, &stripped);
        assert_recovered_chain(&pcs);
    }
}
