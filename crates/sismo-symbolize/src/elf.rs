// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! A small shared view over a 64-bit ELF, built on `object`'s typed reader.
//!
//! sismo reaches ELF program headers, `PT_DYNAMIC`, and section headers from
//! several places — recovering `.eh_frame` from phdrs on a section-stripped
//! binary, resolving `.dynsym` via `PT_DYNAMIC`, probing for build-id notes,
//! checking for an `.eh_frame`/`.symtab` section. Each used to hand-decode the
//! ELF header and walk the header tables at raw byte offsets, so the same
//! `e_phoff`/`e_phentsize` boilerplate and off-by-one risk lived in four files.
//!
//! This centralizes it. `Elf` is generic over [`object::ReadRef`], so the same
//! code serves an in-memory image (`&[u8]`) and a frugal on-disk read
//! ([`object::ReadCache`] over a `File`, which pulls in only the ranges the
//! caller touches — headers are a few KB even for a large binary). The typed
//! accessors come from `object`; callers keep only the format-specific logic
//! (the `DW_EH_PE` pointer decode, the `DT_*` walk, the note parse).

use object::read::elf::{Dyn, ElfFile64, ProgramHeader, SectionHeader, SectionTable};
use object::{Endianness, ReadRef};

// Program header types.
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_NOTE: u32 = 4;
pub const PT_GNU_EH_FRAME: u32 = 0x6474_e550;

// Section header types.
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_NOTE: u32 = 7;

/// One program header, fields copied out so nothing borrows the source.
#[derive(Clone, Copy, Debug)]
pub struct Segment {
    pub p_type: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
}

impl Segment {
    /// Translate a file offset through this PT_LOAD segment. The upper bound is
    /// exclusive; bytes in the zero-filled memsz tail have no file offset.
    pub fn file_offset_to_vaddr(&self, file_offset: u64) -> Option<u64> {
        if self.p_type != PT_LOAD {
            return None;
        }
        let delta = file_offset.checked_sub(self.offset)?;
        (delta < self.filesz).then(|| self.vaddr.checked_add(delta)).flatten()
    }

    /// Whether `vaddr` lies in this segment's virtual range.
    fn contains_vaddr(&self, vaddr: u64) -> bool {
        vaddr >= self.vaddr && vaddr < self.vaddr.saturating_add(self.filesz)
    }
}

/// One section header, with its resolved name.
#[derive(Clone, Debug)]
pub struct Section {
    pub sh_type: u32,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub name: Vec<u8>,
}

/// A parsed 64-bit ELF over an arbitrary byte source.
pub struct Elf<'d, R: ReadRef<'d>> {
    file: ElfFile64<'d, Endianness, R>,
    data: R,
}

impl<'d, R: ReadRef<'d>> Elf<'d, R> {
    /// Parse `data` as a 64-bit ELF. `None` if it isn't one (wrong class, not an
    /// ELF, or malformed) — best-effort, so a hostile file bails rather than
    /// panics.
    pub fn parse(data: R) -> Option<Elf<'d, R>> {
        Some(Elf { file: ElfFile64::parse(data).ok()?, data })
    }

    fn endian(&self) -> Endianness {
        self.file.endian()
    }

    /// Every program header.
    pub fn segments(&self) -> impl Iterator<Item = Segment> + '_ {
        let e = self.endian();
        self.file.elf_program_headers().iter().map(move |p| Segment {
            p_type: p.p_type(e),
            offset: p.p_offset(e),
            vaddr: p.p_vaddr(e),
            filesz: p.p_filesz(e),
            memsz: p.p_memsz(e),
        })
    }

    /// The first program header of type `p_type`.
    pub fn segment(&self, p_type: u32) -> Option<Segment> {
        self.segments().find(|s| s.p_type == p_type)
    }

    /// Every `PT_LOAD` segment.
    pub fn loads(&self) -> Vec<Segment> {
        self.segments().filter(|s| s.p_type == PT_LOAD).collect()
    }

    /// The image base: the lowest `PT_LOAD` vaddr (0 for a PIE). This is the base
    /// that `wholesym`'s ELF "relative" addresses and dynamic-symbol values are
    /// measured from.
    pub fn image_base(&self) -> Option<u64> {
        self.segments()
            .filter(|s| s.p_type == PT_LOAD)
            .map(|s| s.vaddr)
            .min()
    }

    /// Translate an ELF file offset to link-time vaddr through the first PT_LOAD
    /// whose file-backed interval contains it.
    pub fn file_offset_to_vaddr(&self, file_offset: u64) -> Option<u64> {
        self.segments().find_map(|s| s.file_offset_to_vaddr(file_offset))
    }

    /// Map a `vaddr` range of `len` bytes to a file offset through the containing
    /// `PT_LOAD`, or `None` if no single segment covers it.
    pub fn vaddr_to_offset(&self, vaddr: u64, len: u64) -> Option<u64> {
        self.segments().filter(|s| s.p_type == PT_LOAD).find_map(|s| {
            let end = vaddr.checked_add(len)?;
            (vaddr >= s.vaddr && end <= s.vaddr.checked_add(s.filesz)?)
                .then_some(vaddr - s.vaddr + s.offset)
        })
    }

    /// The `PT_LOAD` segment whose virtual range contains `vaddr`.
    pub fn load_containing(&self, vaddr: u64) -> Option<Segment> {
        self.segments()
            .find(|s| s.p_type == PT_LOAD && s.contains_vaddr(vaddr))
    }

    /// `len` bytes at file `offset` from the underlying source.
    pub fn read(&self, offset: u64, len: u64) -> Option<&'d [u8]> {
        self.data.read_bytes_at(offset, len).ok()
    }

    /// The `PT_DYNAMIC` array as `(d_tag, d_val)` pairs, if present.
    pub fn dynamic(&self) -> Option<Vec<(i64, u64)>> {
        let e = self.endian();
        self.file.elf_program_headers().iter().find_map(|p| {
            let dyns = p.dynamic(e, self.data).ok().flatten()?;
            Some(dyns.iter().map(|d| (d.d_tag(e), d.d_val(e))).collect())
        })
    }

    /// Every section header, with names resolved through the section string
    /// table. Empty when the section header table was stripped.
    pub fn sections(&self) -> Vec<Section> {
        let e = self.endian();
        let table: &SectionTable<_, R> = self.file.elf_section_table();
        table
            .iter()
            .map(|sh| Section {
                sh_type: sh.sh_type(e),
                addr: sh.sh_addr(e),
                offset: sh.sh_offset(e),
                size: sh.sh_size(e),
                name: table.section_name(e, sh).map(<[u8]>::to_vec).unwrap_or_default(),
            })
            .collect()
    }

    /// Whether a section named exactly `name` is present.
    pub fn has_section(&self, name: &[u8]) -> bool {
        self.sections().iter().any(|s| s.name == name)
    }
}

/// Parse the ELF at `path` off disk, reading only the ranges accessed (headers,
/// not the whole file). The returned closure hands the caller an [`Elf`] view;
/// this indirection keeps the backing `ReadCache` alive for the view's borrow.
pub fn with_elf_at_path<T>(path: &str, f: impl FnOnce(&Elf<&object::ReadCache<std::fs::File>>) -> T) -> Option<T> {
    let file = std::fs::File::open(path).ok()?;
    let cache = object::ReadCache::new(file);
    let elf = Elf::parse(&cache)?;
    Some(f(&elf))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Parse the running test binary from memory and confirm the shared view sees
    // the same structure the old hand-rolled readers did: PT_LOAD segments, an
    // image base, an .eh_frame section, and a resolvable vaddr→offset mapping.
    #[cfg(target_os = "linux")]
    #[test]
    fn parses_self_from_memory() {
        let bytes = std::fs::read("/proc/self/exe").unwrap();
        let elf = Elf::parse(&bytes[..]).expect("parse self");
        assert!(!elf.loads().is_empty(), "self has PT_LOAD segments");
        assert!(elf.image_base().is_some());
        assert!(elf.has_section(b".text"));
        assert!(elf.has_section(b".eh_frame"));
        // The .text section's vaddr must map back to a file offset.
        let text = elf.sections().into_iter().find(|s| s.name == b".text").unwrap();
        assert!(elf.vaddr_to_offset(text.addr, 1).is_some());
        // A PIE binary keeps a PT_DYNAMIC; either way, dynamic() must not panic.
        let _ = elf.dynamic();
    }

    // The same parse over a frugal on-disk ReadCache must agree with the
    // in-memory parse — this is the path the disk-backed callers use.
    #[cfg(target_os = "linux")]
    #[test]
    fn parses_self_from_disk_cache() {
        let mem = std::fs::read("/proc/self/exe").unwrap();
        let base_mem = Elf::parse(&mem[..]).unwrap().image_base();
        let base_disk =
            with_elf_at_path("/proc/self/exe", |elf| elf.image_base()).unwrap();
        assert_eq!(base_mem, base_disk);
    }

    #[test]
    fn file_offsets_translate_for_pie_and_non_pie_layouts() {
        let pie = Segment { p_type: PT_LOAD, offset: 0x1000, vaddr: 0x1000, filesz: 0x200, memsz: 0x300 };
        assert_eq!(pie.file_offset_to_vaddr(0x1000), Some(0x1000));
        assert_eq!(pie.file_offset_to_vaddr(0x11ff), Some(0x11ff));
        assert_eq!(pie.file_offset_to_vaddr(0x1200), None);

        let exec = Segment { p_type: PT_LOAD, offset: 0x2000, vaddr: 0x402000, filesz: 0x100, memsz: 0x100 };
        assert_eq!(exec.file_offset_to_vaddr(0x2042), Some(0x402042));
        assert_eq!(exec.file_offset_to_vaddr(0x1fff), None);
    }

    #[test]
    fn parse_rejects_non_elf() {
        assert!(Elf::parse(&b"not an elf"[..]).is_none());
    }
}
