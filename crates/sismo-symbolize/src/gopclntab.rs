// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `.gopclntab` function-name resolver for stripped Go binaries.
//!
//! `go build -ldflags=-s -w` drops the symbol table, so wholesym resolves
//! almost nothing — but Go always ships `.gopclntab`, the program-counter/line
//! table the runtime uses for stack traces, and it carries every function's
//! name. This parses it to recover names when the symbol table is gone. It is
//! the same table Go's `debug/gosym` and systing read.
//!
//! Scope: the go1.18+ table layout (`0xfffffff0` / `0xfffffff1` magic), 64-bit
//! little-endian, function names only (no file/line). The functab entry offsets
//! are relative to `textStart`; the on-disk `textStart` is a placeholder (0,
//! relocated at load), so we use the `.text` section's vaddr instead — the
//! standard offline convention.

use std::os::unix::fs::FileExt;

const SHT_NULL: u32 = 0;
// go1.18/1.19 and go1.20+ pcHeader magics (the layout is identical for our use).
const MAGIC_118: u32 = 0xffff_fff0;
const MAGIC_120: u32 = 0xffff_fff1;

/// A parsed `.gopclntab`, ready to resolve a link-time address to a Go function
/// name. Holds the whole section (a few hundred KB) plus the parsed offsets.
pub struct GoPclntab {
    data: Vec<u8>,
    /// `.text` vaddr minus the image base (min PT_LOAD vaddr). functab entry
    /// offsets are relative to `textStart` (= `.text` vaddr), but callers pass
    /// `avma - base_avma`, which is relative to the image base; subtracting this
    /// converts between the two so a non-PIE binary's `.text` at 0x401000 in an
    /// image based at 0x400000 lines up.
    text_off: u64,
    nfunc: usize,
    funcname_off: usize,
    functab_off: usize,
}

impl GoPclntab {
    /// Parse the `.gopclntab` of the ELF at `path`, or `None` if it isn't a
    /// 64-bit LE ELF, has no `.gopclntab`/`.text`, or the header is unrecognized.
    pub fn from_path(path: &str) -> Option<GoPclntab> {
        let f = std::fs::File::open(path).ok()?;
        let (gopcln, text_vaddr) = find_sections(&f)?;
        let image_base = min_pt_load_vaddr(&f)?;
        let text_off = text_vaddr.checked_sub(image_base)?;
        let (off, size) = gopcln;
        if size < 64 || size > 256 * 1024 * 1024 {
            return None;
        }
        let mut data = vec![0u8; size as usize];
        f.read_exact_at(&mut data, off).ok()?;

        // pcHeader: magic(4) pad(2) minLC(1) ptrSize(1), then uintptr fields.
        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if magic != MAGIC_118 && magic != MAGIC_120 {
            return None;
        }
        if data[7] != 8 {
            return None; // ptrSize: 64-bit only
        }
        let rd = |i: usize| -> Option<u64> {
            data.get(i..i + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        };
        let nfunc = rd(8)? as usize;
        // rd(16) = nfiles, rd(24) = textStart (0 on disk — use .text vaddr).
        let funcname_off = rd(32)? as usize;
        // rd(40) cuOffset, rd(48) filetabOffset, rd(56) pctabOffset.
        let functab_off = rd(64)? as usize; // pclnOffset → the functab array
        // The functab has nfunc entries + 1 sentinel, each 8 bytes (go1.18+).
        let functab_bytes = nfunc.checked_add(1)?.checked_mul(8)?;
        if nfunc == 0
            || funcname_off >= data.len()
            || functab_off.checked_add(functab_bytes)? > data.len()
        {
            return None;
        }
        Some(GoPclntab { data, text_off, nfunc, funcname_off, functab_off })
    }

    /// The i'th functab entry: `(entryoff, funcoff)` — entryoff relative to
    /// textStart, funcoff relative to the functab base (the `_func` structs
    /// follow the functab array within the same region).
    fn functab(&self, i: usize) -> (u32, u32) {
        let base = self.functab_off + i * 8;
        let e = u32::from_le_bytes(self.data[base..base + 4].try_into().unwrap());
        let o = u32::from_le_bytes(self.data[base + 4..base + 8].try_into().unwrap());
        (e, o)
    }

    /// The function name for a functab `funcoff`: the `_func` struct at
    /// `functab_off + funcoff` carries `nameOff` (i32 @4) into the funcnametab.
    fn func_name(&self, funcoff: u32) -> Option<&str> {
        let no = self.functab_off + funcoff as usize + 4;
        let nameoff = i32::from_le_bytes(self.data.get(no..no + 4)?.try_into().ok()?);
        if nameoff < 0 {
            return None;
        }
        cstr_at(&self.data, self.funcname_off + nameoff as usize)
    }

    /// Resolve a link-time address to `(function name, offset into function)`, or
    /// `None` if it is outside every Go function.
    pub fn resolve(&self, addr: u64) -> Option<(&str, u64)> {
        let q = u32::try_from(addr.checked_sub(self.text_off)?).ok()?;
        // Binary search the functab (entryoff ascending) for the last entry with
        // entryoff <= q; the sentinel (index nfunc) bounds the final function.
        let (mut lo, mut hi) = (0usize, self.nfunc); // search among real entries
        if q < self.functab(0).0 || q >= self.functab(self.nfunc).0 {
            return None; // before the first function or past the text end
        }
        while lo + 1 < hi {
            let mid = (lo + hi) / 2;
            if self.functab(mid).0 <= q {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        let (entryoff, funcoff) = self.functab(lo);
        let name = self.func_name(funcoff)?;
        Some((name, (q - entryoff) as u64))
    }

    pub fn len(&self) -> usize {
        self.nfunc
    }
}

/// Locate the `.gopclntab` (offset, size) and `.text` vaddr via the ELF section
/// header table (Go binaries keep section headers even when `-s` strips symbols).
fn find_sections(f: &std::fs::File) -> Option<((u64, u64), u64)> {
    let mut ehdr = [0u8; 64];
    f.read_exact_at(&mut ehdr, 0).ok()?;
    if &ehdr[0..4] != b"\x7fELF" || ehdr[4] != 2 {
        return None;
    }
    let e_shoff = u64::from_le_bytes(ehdr[40..48].try_into().unwrap());
    let e_shentsize = u16::from_le_bytes(ehdr[58..60].try_into().unwrap()) as u64;
    let e_shnum = u16::from_le_bytes(ehdr[60..62].try_into().unwrap()) as u64;
    let e_shstrndx = u16::from_le_bytes(ehdr[62..64].try_into().unwrap()) as u64;
    if e_shoff == 0 || e_shnum == 0 || e_shentsize < 64 || e_shstrndx >= e_shnum {
        return None;
    }

    // Read the section-header string table so section names can be matched.
    let read_shdr = |i: u64| -> Option<[u8; 64]> {
        let mut b = [0u8; 64];
        f.read_exact_at(&mut b, e_shoff + i * e_shentsize).ok()?;
        Some(b)
    };
    let shstr = read_shdr(e_shstrndx)?;
    let shstr_off = u64::from_le_bytes(shstr[24..32].try_into().unwrap());
    let shstr_size = u64::from_le_bytes(shstr[32..40].try_into().unwrap());
    if shstr_size == 0 || shstr_size > 16 * 1024 * 1024 {
        return None;
    }
    let mut names = vec![0u8; shstr_size as usize];
    f.read_exact_at(&mut names, shstr_off).ok()?;

    const SHT_PROGBITS: u32 = 1;
    let mut gopcln_named = None;
    let mut gopcln_magic = None;
    let mut text_vaddr = None;
    for i in 0..e_shnum {
        let sh = read_shdr(i)?;
        let sh_type = u32::from_le_bytes(sh[4..8].try_into().unwrap());
        if sh_type == SHT_NULL {
            continue;
        }
        let name_off = u32::from_le_bytes(sh[0..4].try_into().unwrap()) as usize;
        let name = cstr_at(&names, name_off)?;
        let off = u64::from_le_bytes(sh[24..32].try_into().unwrap());
        let size = u64::from_le_bytes(sh[32..40].try_into().unwrap());
        if name == ".text" {
            text_vaddr = Some(u64::from_le_bytes(sh[16..24].try_into().unwrap()));
            continue;
        }
        if name == ".gopclntab" {
            gopcln_named = Some((off, size));
            continue;
        }
        // systing #158: some Go binaries rename the section (objcopy
        // --rename-section .gopclntab=.data.rel.ro.pcln), so match a PROGBITS
        // section whose content starts with the pcHeader magic + a 64-bit
        // ptrSize instead of relying on the name.
        if gopcln_magic.is_none() && sh_type == SHT_PROGBITS && size >= 64 {
            let mut head = [0u8; 8];
            if f.read_exact_at(&mut head, off).is_ok() {
                let magic = u32::from_le_bytes(head[0..4].try_into().unwrap());
                if (magic == MAGIC_118 || magic == MAGIC_120) && head[7] == 8 {
                    gopcln_magic = Some((off, size));
                }
            }
        }
    }
    Some((gopcln_named.or(gopcln_magic)?, text_vaddr?))
}

/// The image base — the lowest PT_LOAD vaddr — which `avma - base_avma` relative
/// addresses are measured from. Read from the program headers.
fn min_pt_load_vaddr(f: &std::fs::File) -> Option<u64> {
    const PT_LOAD: u32 = 1;
    let mut ehdr = [0u8; 64];
    f.read_exact_at(&mut ehdr, 0).ok()?;
    let e_phoff = u64::from_le_bytes(ehdr[32..40].try_into().unwrap());
    let e_phentsize = u16::from_le_bytes(ehdr[54..56].try_into().unwrap()) as u64;
    let e_phnum = u16::from_le_bytes(ehdr[56..58].try_into().unwrap());
    if e_phentsize < 56 {
        return None;
    }
    let mut min = None;
    for i in 0..e_phnum {
        let mut ph = [0u8; 56];
        f.read_exact_at(&mut ph, e_phoff + i as u64 * e_phentsize).ok()?;
        if u32::from_le_bytes(ph[0..4].try_into().unwrap()) == PT_LOAD {
            let vaddr = u64::from_le_bytes(ph[16..24].try_into().unwrap());
            min = Some(min.map_or(vaddr, |m: u64| m.min(vaddr)));
        }
    }
    min
}

/// A NUL-terminated string at `off`, as UTF-8 (Go symbol names are UTF-8).
fn cstr_at(buf: &[u8], off: usize) -> Option<&str> {
    let rest = buf.get(off..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    std::str::from_utf8(&rest[..end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cstr_at_reads_names() {
        let b = b"\0main.foo\0bar\0";
        assert_eq!(cstr_at(b, 1), Some("main.foo"));
        assert_eq!(cstr_at(b, 10), Some("bar"));
        assert_eq!(cstr_at(b, 99), None);
    }

    // End to end against the stripped Go matrix binary if it's present: parsing
    // must succeed and resolve the workload's hot functions by name.
    #[test]
    fn resolves_go_stripped_workload() {
        let bin = concat!(env!("CARGO_MANIFEST_DIR"), "/../../out/matrix/bin/go-stripped");
        if !std::path::Path::new(bin).exists() {
            return; // matrix not built here
        }
        let pcln = match GoPclntab::from_path(bin) {
            Some(p) => p,
            None => panic!("failed to parse .gopclntab of {bin}"),
        };
        assert!(pcln.len() > 100, "expected many Go functions, got {}", pcln.len());
        // Scan the funcname table for the workload's functions to prove names
        // are reachable (their exact PCs vary by build).
        let names: Vec<&str> = (0..pcln.nfunc)
            .filter_map(|i| pcln.func_name(pcln.functab(i).1))
            .collect();
        assert!(
            names.iter().any(|n| n.contains("sismo_wl_leaf")),
            "expected main.sismo_wl_leaf among {} names",
            names.len()
        );
    }
}
