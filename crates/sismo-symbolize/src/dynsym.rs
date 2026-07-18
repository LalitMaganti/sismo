// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `.dynsym`-via-`PT_DYNAMIC` symbol resolver for ELF binaries whose section
//! header table was removed (`objcopy --strip-section-headers`, a shape real
//! distro/packing tooling produces).
//!
//! Without section headers, `object` (and therefore wholesym) finds no symbols
//! at all — it reaches `.dynsym`/`.symtab` through the section table, which is
//! gone. But the dynamic linker never needed sections: it reaches the dynamic
//! symbol table through the program headers, via `PT_DYNAMIC`'s `DT_SYMTAB` /
//! `DT_STRTAB`. This resolver does the same, so an `-rdynamic` (or any
//! exported-symbol) binary still yields function names. blazesym and the OTel
//! profiler take the same fallback.
//!
//! Scope: 64-bit little-endian ELF (x86-64 / aarch64), function symbols only.
//! No source line info — that lives in DWARF, which a sectionless binary also
//! lacks. This is a symtab-quality fallback, tried only when wholesym loaded
//! zero symbols.

use std::os::unix::fs::FileExt;

// Program header types.
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;

// Dynamic array tags (Elf64_Dyn.d_tag).
const DT_NULL: i64 = 0;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;

// Symbol type / section-index constants.
const STT_FUNC: u8 = 2;
const STT_GNU_IFUNC: u8 = 10;
const SHN_UNDEF: u16 = 0;

const ELF64_SYM_SIZE: u64 = 24;
// Guards so a malformed or hostile ELF can't make us allocate unboundedly.
const MAX_TABLE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PHNUM: u16 = 4096;

/// One defined function symbol: its link-time value/size and its name.
struct Sym {
    value: u64,
    size: u64,
    name: String,
}

/// A parsed dynamic symbol table, sorted by `value` for binary-search lookup.
pub struct DynSyms {
    syms: Vec<Sym>,
}

/// A PT_LOAD segment, used to translate a vaddr (as `DT_SYMTAB`/`DT_STRTAB`
/// store it) into a file offset for reading.
struct Load {
    vaddr: u64,
    offset: u64,
    filesz: u64,
}

fn vaddr_to_offset(loads: &[Load], vaddr: u64, len: u64) -> Option<u64> {
    for l in loads {
        if vaddr >= l.vaddr && vaddr.checked_add(len)? <= l.vaddr.checked_add(l.filesz)? {
            return Some(vaddr - l.vaddr + l.offset);
        }
    }
    None
}

impl DynSyms {
    /// Parse the dynamic symbol table of the ELF at `path`. Returns `None` when
    /// the file isn't a 64-bit LE ELF, has no dynamic segment, or yields no
    /// usable function symbols. Best effort: any malformed field bails to None.
    pub fn from_path(path: &str) -> Option<DynSyms> {
        let f = std::fs::File::open(path).ok()?;

        let mut ehdr = [0u8; 64];
        f.read_exact_at(&mut ehdr, 0).ok()?;
        if &ehdr[0..4] != b"\x7fELF" || ehdr[4] != 2 {
            return None; // not ELFCLASS64
        }
        let e_phoff = u64::from_le_bytes(ehdr[32..40].try_into().unwrap());
        let e_phentsize = u16::from_le_bytes(ehdr[54..56].try_into().unwrap());
        let e_phnum = u16::from_le_bytes(ehdr[56..58].try_into().unwrap());
        if e_phentsize < 56 || e_phnum == 0 || e_phnum > MAX_PHNUM {
            return None;
        }

        let mut loads: Vec<Load> = Vec::new();
        let mut dyn_range: Option<(u64, u64)> = None; // (offset, filesz)
        for i in 0..e_phnum {
            let mut phdr = [0u8; 56];
            f.read_exact_at(&mut phdr, e_phoff + i as u64 * e_phentsize as u64)
                .ok()?;
            let p_type = u32::from_le_bytes(phdr[0..4].try_into().unwrap());
            let p_offset = u64::from_le_bytes(phdr[8..16].try_into().unwrap());
            let p_vaddr = u64::from_le_bytes(phdr[16..24].try_into().unwrap());
            let p_filesz = u64::from_le_bytes(phdr[32..40].try_into().unwrap());
            match p_type {
                PT_LOAD => loads.push(Load { vaddr: p_vaddr, offset: p_offset, filesz: p_filesz }),
                PT_DYNAMIC => dyn_range = Some((p_offset, p_filesz)),
                _ => {}
            }
        }
        let (dyn_off, dyn_sz) = dyn_range?;

        // The caller compares against `avma - base_avma`, where base_avma is the
        // image's lowest mapping — the first PT_LOAD. samply/wholesym likewise
        // normalize ELF symbol addresses to that base, so a non-PIE symbol at
        // vaddr 0x401060 in an image based at 0x400000 must become 0x1060.
        // Subtract the image base (min PT_LOAD vaddr) from every st_value.
        let image_base = loads.iter().map(|l| l.vaddr).min()?;

        // Walk the dynamic array (Elf64_Dyn: i64 tag, u64 val) to DT_NULL.
        let mut symtab_va = None;
        let mut strtab_va = None;
        let mut strsz = None;
        let mut syment = ELF64_SYM_SIZE;
        if dyn_sz == 0 || dyn_sz > MAX_TABLE_BYTES {
            return None;
        }
        let mut dynbuf = vec![0u8; dyn_sz as usize];
        f.read_exact_at(&mut dynbuf, dyn_off).ok()?;
        let mut off = 0usize;
        while off + 16 <= dynbuf.len() {
            let tag = i64::from_le_bytes(dynbuf[off..off + 8].try_into().unwrap());
            let val = u64::from_le_bytes(dynbuf[off + 8..off + 16].try_into().unwrap());
            match tag {
                DT_NULL => break,
                DT_SYMTAB => symtab_va = Some(val),
                DT_STRTAB => strtab_va = Some(val),
                DT_STRSZ => strsz = Some(val),
                DT_SYMENT => syment = val,
                _ => {}
            }
            off += 16;
        }
        let symtab_va = symtab_va?;
        let strtab_va = strtab_va?;
        let strsz = strsz?;
        if syment != ELF64_SYM_SIZE {
            return None; // only the standard Elf64_Sym layout
        }

        // The dynamic array records no symbol count. The linker lays `.dynsym`
        // out immediately before `.dynstr`, so the byte gap between them, over
        // the entry size, is the count. This is blazesym's fallback and holds
        // for every normally-linked binary.
        if strtab_va <= symtab_va {
            return None;
        }
        let nsyms = (strtab_va - symtab_va) / syment;
        let symtab_bytes = nsyms.checked_mul(syment)?;
        if nsyms == 0 || symtab_bytes > MAX_TABLE_BYTES || strsz > MAX_TABLE_BYTES {
            return None;
        }

        let symtab_off = vaddr_to_offset(&loads, symtab_va, symtab_bytes)?;
        let strtab_off = vaddr_to_offset(&loads, strtab_va, strsz)?;

        let mut symtab = vec![0u8; symtab_bytes as usize];
        f.read_exact_at(&mut symtab, symtab_off).ok()?;
        let mut strtab = vec![0u8; strsz as usize];
        f.read_exact_at(&mut strtab, strtab_off).ok()?;

        let syms = parse_syms(&symtab, &strtab, image_base);
        if syms.is_empty() {
            return None;
        }
        Some(DynSyms { syms })
    }

    /// Resolve an image-relative address (`avma - base_avma`, i.e. the link-time
    /// vaddr, matching wholesym's zero-based ELF relative addresses) to a
    /// function name and the byte offset from that function's start.
    pub fn resolve(&self, rel: u64) -> Option<(&str, u64)> {
        // Greatest symbol whose value is <= rel.
        let idx = match self.syms.binary_search_by(|s| s.value.cmp(&rel)) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let s = &self.syms[idx];
        // Bound the match: a sized symbol contains rel only within its extent;
        // a size-0 symbol runs until the next symbol's value.
        let end = if s.size > 0 {
            s.value + s.size
        } else {
            self.syms.get(idx + 1).map(|n| n.value).unwrap_or(u64::MAX)
        };
        if rel < end {
            Some((&s.name, rel - s.value))
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.syms.len()
    }
}

/// Parse `Elf64_Sym` entries, keeping only defined function symbols with a
/// non-empty name, sorted by value ascending for binary search. `st_value` is
/// rebased to `image_base` (the min PT_LOAD vaddr) so it matches the caller's
/// `avma - base_avma` relative addresses.
fn parse_syms(symtab: &[u8], strtab: &[u8], image_base: u64) -> Vec<Sym> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 24 <= symtab.len() {
        let st_name = u32::from_le_bytes(symtab[off..off + 4].try_into().unwrap());
        let st_info = symtab[off + 4];
        let st_shndx = u16::from_le_bytes(symtab[off + 6..off + 8].try_into().unwrap());
        let st_value = u64::from_le_bytes(symtab[off + 8..off + 16].try_into().unwrap());
        let st_size = u64::from_le_bytes(symtab[off + 16..off + 24].try_into().unwrap());
        off += 24;

        let sym_type = st_info & 0xf;
        if (sym_type != STT_FUNC && sym_type != STT_GNU_IFUNC)
            || st_shndx == SHN_UNDEF
            || st_value < image_base
        {
            continue;
        }
        if let Some(name) = cstr_at(strtab, st_name as usize) {
            if !name.is_empty() {
                out.push(Sym { value: st_value - image_base, size: st_size, name: name.to_owned() });
            }
        }
    }
    out.sort_by_key(|s| s.value);
    out
}

// Section header type for a local symbol table.
const SHT_SYMTAB: u32 = 2;

/// Whether the ELF at `path` still carries a local symbol table (`.symtab`).
/// `Some(false)` means it was stripped — only `.dynsym`/exports remain, or the
/// section header table is gone entirely. `None` if the file isn't a readable
/// 64-bit LE ELF. This is the reliable "is this binary stripped" signal: a
/// stripped binary keeps its dynamic symbols but drops `.symtab`.
pub fn has_symtab(path: &str) -> Option<bool> {
    let f = std::fs::File::open(path).ok()?;
    let mut ehdr = [0u8; 64];
    f.read_exact_at(&mut ehdr, 0).ok()?;
    if &ehdr[0..4] != b"\x7fELF" || ehdr[4] != 2 {
        return None; // not ELFCLASS64
    }
    let e_shoff = u64::from_le_bytes(ehdr[40..48].try_into().unwrap());
    let e_shentsize = u16::from_le_bytes(ehdr[58..60].try_into().unwrap());
    let e_shnum = u16::from_le_bytes(ehdr[60..62].try_into().unwrap());
    // No section header table (0 offset/count, or `--strip-section-headers`) →
    // no `.symtab` reachable, so treat as stripped.
    if e_shoff == 0 || e_shnum == 0 || e_shentsize < 64 {
        return Some(false);
    }
    for i in 0..e_shnum {
        // sh_name (u32) + sh_type (u32) are the first 8 bytes of Elf64_Shdr.
        let mut shdr = [0u8; 8];
        if f
            .read_exact_at(&mut shdr, e_shoff + i as u64 * e_shentsize as u64)
            .is_err()
        {
            return Some(false);
        }
        if u32::from_le_bytes(shdr[4..8].try_into().unwrap()) == SHT_SYMTAB {
            return Some(true);
        }
    }
    Some(false)
}

/// A NUL-terminated string at `off` in the string table, as UTF-8 (dynamic
/// symbol names are ASCII in practice; non-UTF-8 bytes yield None).
fn cstr_at(strtab: &[u8], off: usize) -> Option<&str> {
    if off >= strtab.len() {
        return None;
    }
    let end = strtab[off..].iter().position(|&b| b == 0)? + off;
    std::str::from_utf8(&strtab[off..end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(value: u64, size: u64, name: &str) -> Sym {
        Sym { value, size, name: name.to_owned() }
    }

    #[test]
    fn resolve_sized_symbol_bounds_the_match() {
        let d = DynSyms { syms: vec![mk(0x1000, 0x40, "foo"), mk(0x2000, 0x10, "bar")] };
        assert_eq!(d.resolve(0x1000), Some(("foo", 0)));
        assert_eq!(d.resolve(0x1020), Some(("foo", 0x20)));
        assert_eq!(d.resolve(0x103f), Some(("foo", 0x3f)));
        // Past foo's extent (size 0x40) but before bar → no match, not "foo+huge".
        assert_eq!(d.resolve(0x1500), None);
        assert_eq!(d.resolve(0x2008), Some(("bar", 8)));
        // Before the first symbol.
        assert_eq!(d.resolve(0x500), None);
    }

    #[test]
    fn resolve_zero_size_runs_to_next_symbol() {
        let d = DynSyms { syms: vec![mk(0x1000, 0, "foo"), mk(0x2000, 0, "bar")] };
        assert_eq!(d.resolve(0x1abc), Some(("foo", 0xabc))); // covered up to bar
        assert_eq!(d.resolve(0x2000), Some(("bar", 0)));
        assert_eq!(d.resolve(0x9999), Some(("bar", 0x7999))); // last runs open-ended
    }

    #[test]
    fn parse_syms_keeps_only_defined_functions() {
        // Three entries: a defined FUNC, an undefined FUNC (skip), an OBJECT (skip).
        let mut strtab = vec![0u8]; // index 0 is the empty string
        let foo_off = strtab.len();
        strtab.extend_from_slice(b"foo\0");
        let bar_off = strtab.len();
        strtab.extend_from_slice(b"bar\0");

        let mut symtab = Vec::new();
        let mut push = |name_off: u32, info: u8, shndx: u16, value: u64, size: u64| {
            symtab.extend_from_slice(&name_off.to_le_bytes());
            symtab.push(info);
            symtab.push(0); // st_other
            symtab.extend_from_slice(&shndx.to_le_bytes());
            symtab.extend_from_slice(&value.to_le_bytes());
            symtab.extend_from_slice(&size.to_le_bytes());
        };
        push(foo_off as u32, STT_FUNC, 12, 0x401000, 0x20); // kept
        push(bar_off as u32, STT_FUNC, SHN_UNDEF, 0, 0); // undefined → skip
        push(foo_off as u32, 1 /* OBJECT */, 12, 0x403000, 8); // not a func → skip

        // image_base 0x400000 → the kept symbol rebases to 0x1000.
        let syms = parse_syms(&symtab, &strtab, 0x400000);
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].name, "foo");
        assert_eq!(syms[0].value, 0x1000);
    }

    #[test]
    fn cstr_at_reads_terminated_strings() {
        let strtab = b"\0foo\0bar\0";
        assert_eq!(cstr_at(strtab, 1), Some("foo"));
        assert_eq!(cstr_at(strtab, 5), Some("bar"));
        assert_eq!(cstr_at(strtab, 0), Some("")); // empty string at index 0
        assert_eq!(cstr_at(strtab, 99), None); // out of range
    }

    // The test binary is compiled with debug info, so it keeps a `.symtab`;
    // a non-ELF path yields None.
    #[cfg(target_os = "linux")]
    #[test]
    fn has_symtab_detects_local_symbols() {
        let exe = std::fs::read_link("/proc/self/exe").expect("readlink");
        assert_eq!(has_symtab(exe.to_str().unwrap()), Some(true));
        assert_eq!(has_symtab("/etc/hostname"), None);
        assert_eq!(has_symtab("/no/such/path"), None);
    }

    // End to end against the running test binary itself: it's a normally-linked
    // ELF with a dynamic symbol table reachable via PT_DYNAMIC, so parsing must
    // succeed and find a positive number of function symbols.
    #[cfg(target_os = "linux")]
    #[test]
    fn from_path_self_finds_functions() {
        let exe = std::fs::read_link("/proc/self/exe").expect("readlink");
        match DynSyms::from_path(exe.to_str().unwrap()) {
            Some(d) => assert!(d.len() > 0),
            None => {} // a fully static binary may have no dynamic symtab; ok
        }
    }
}
