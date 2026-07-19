// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! FLAG-noeh: detect a module whose own code sismo can't unwind by any path —
//! no `.eh_frame` FDE coverage for the sampled functions *and* no frame
//! pointers. `-fno-asynchronous-unwind-tables -fno-unwind-tables` at `-O2`
//! produces exactly this: the workload's functions get no FDEs (crt/libc keep
//! theirs, and PT_GNU_EH_FRAME survives, so a phdr probe can't tell), and `-O2`
//! omits frame pointers, so the chain comes back silently degraded.
//!
//! The distinguishing signal is per-sample: a `.eh_frame` that covers the crt
//! but not the hot code, with FP-less prologues on the sampled functions. Both
//! checks are static reads of the on-disk ELF — no runtime state. Requiring
//! *both* keeps this from firing on a healthy build: one that ships FDEs for its
//! code, or one that keeps frame pointers, is excluded.

use gimli::{BaseAddresses, CieOrFde, EhFrame, LittleEndian, UnwindSection};
use object::{Object, ObjectSection};
use std::ops::Range;

/// Below this fraction of sampled addresses covered by an FDE, the module's own
/// code is treated as having no DWARF unwind tables. The crt frames that keep
/// their FDEs are never sampled (they run once at startup), so a `-fno-unwind-
/// tables` build sits at ~0 while any normally-built module sits near 1.0.
const COVERED_FRACTION_FLOOR: f64 = 0.10;

/// The PC ranges (link-time vaddr) an ELF's `.eh_frame` describes FDEs for.
struct FdeCoverage {
    ranges: Vec<Range<u64>>, // sorted by start
}

impl FdeCoverage {
    /// Parse `.eh_frame` FDE address ranges from a parsed ELF. Empty (not
    /// `None`) when there is no `.eh_frame` or it holds no FDEs — an absent
    /// table is itself zero coverage.
    fn from_object(file: &object::File) -> FdeCoverage {
        let mut ranges = Vec::new();
        if let Some(sect) = file.section_by_name(".eh_frame") {
            if let Ok(data) = sect.data() {
                let addr = |name: &str| {
                    file.section_by_name(name).map(|s| s.address()).unwrap_or(0)
                };
                let bases = BaseAddresses::default()
                    .set_eh_frame(sect.address())
                    .set_text(addr(".text"))
                    .set_got(addr(".got"));
                let mut eh = EhFrame::new(data, LittleEndian);
                eh.set_address_size(8);
                let mut it = eh.entries(&bases);
                while let Ok(Some(entry)) = it.next() {
                    if let CieOrFde::Fde(partial) = entry {
                        if let Ok(fde) =
                            partial.parse(|s, b, o| s.cie_from_offset(b, o))
                        {
                            let start = fde.initial_address();
                            ranges.push(start..start.saturating_add(fde.len()));
                        }
                    }
                }
            }
        }
        ranges.sort_by_key(|r| r.start);
        FdeCoverage { ranges }
    }

    /// Whether `svma` falls inside some FDE range.
    fn covers(&self, svma: u64) -> bool {
        let i = self.ranges.partition_point(|r| r.start <= svma);
        i.checked_sub(1).is_some_and(|j| svma < self.ranges[j].end)
    }

    fn covered_fraction(&self, svmas: &[u64]) -> f64 {
        if svmas.is_empty() {
            return 1.0; // nothing sampled → nothing to warn about
        }
        let n = svmas.iter().filter(|&&a| self.covers(a)).count();
        n as f64 / svmas.len() as f64
    }
}

/// The bytes at link-time vaddr `svma` from whichever section maps it, up to
/// `n`. Used to read a function's prologue without a separate PT_LOAD walk.
fn read_at_svma<'a>(file: &'a object::File, svma: u64, n: usize) -> Option<&'a [u8]> {
    for sect in file.sections() {
        let start = sect.address();
        let end = start.checked_add(sect.size())?;
        if svma >= start && svma < end {
            let off = (svma - start) as usize;
            return sect.data().ok()?.get(off..off.checked_add(n)?);
        }
    }
    None
}

/// Whether the function at `fn_start_svma` opens with the x86-64 frame-pointer
/// prologue `push %rbp; mov %rsp,%rbp` (`55 48 89 e5`), optionally behind a CET
/// `endbr64` (`f3 0f 1e fa`) that `-fcf-protection` inserts first. `None` if the
/// bytes can't be read.
fn has_frame_pointer_prologue(file: &object::File, fn_start_svma: u64) -> Option<bool> {
    let p = read_at_svma(file, fn_start_svma, 8)?;
    let after_endbr = if p[..4] == [0xf3, 0x0f, 0x1e, 0xfa] { 4 } else { 0 };
    let win = p.get(after_endbr..after_endbr + 4)?;
    Some(win == [0x55, 0x48, 0x89, 0xe5])
}

/// The link-time vaddr of the first LOAD segment — the base wholesym's ELF
/// "relative" addresses are measured from. Adding it converts a relative address
/// back to the raw svma that gimli's FDEs and object's sections use.
fn image_base(file: &object::File) -> u64 {
    use object::ObjectSegment;
    file.segments().next().map(|s| s.address()).unwrap_or(0)
}

/// Whether essentially none of the sampled code is covered by `.eh_frame` FDEs
/// — the DWARF half of the no-recourse condition. `sampled_rel` are
/// *image-relative* addresses (`rel_pc - load_bias`, wholesym's ELF relative
/// address space). This is the cheap gate: a healthy module returns false here
/// without the caller having to resolve function starts.
///
/// x86-64 only, matching the frame-pointer half of the diagnosis.
pub fn sampled_code_lacks_fde_coverage(bytes: &[u8], sampled_rel: &[u64]) -> bool {
    if !cfg!(target_arch = "x86_64") || sampled_rel.is_empty() {
        return false;
    }
    let Ok(file) = object::File::parse(bytes) else {
        return false;
    };
    // gimli FDEs speak raw svma; the caller's addresses are relative to the
    // first LOAD segment. Rebase into raw svma to compare.
    let base = image_base(&file);
    let svmas: Vec<u64> = sampled_rel.iter().map(|&a| a.saturating_add(base)).collect();
    FdeCoverage::from_object(&file).covered_fraction(&svmas) < COVERED_FRACTION_FLOOR
}

/// Whether every checked function omits the frame-pointer prologue — the frame-
/// pointer half. `fn_start_rel` are image-relative function starts. Requires at
/// least one readable prologue, so an unreadable module never reads as "no FP".
/// A single hot function that keeps a frame pointer means the FP walk can climb
/// the module, so the diagnosis does not apply.
pub fn functions_omit_frame_pointer(bytes: &[u8], fn_start_rel: &[u64]) -> bool {
    if !cfg!(target_arch = "x86_64") {
        return false;
    }
    let Ok(file) = object::File::parse(bytes) else {
        return false;
    };
    let base = image_base(&file);
    let mut checked = 0usize;
    for &start in fn_start_rel {
        match has_frame_pointer_prologue(&file, start.saturating_add(base)) {
            Some(true) => return false,
            Some(false) => checked += 1,
            None => {}
        }
    }
    checked > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covers_uses_ranges() {
        let c = FdeCoverage { ranges: vec![0x1000..0x1040, 0x2000..0x2010] };
        assert!(c.covers(0x1000));
        assert!(c.covers(0x103f));
        assert!(!c.covers(0x1040)); // one past the end
        assert!(!c.covers(0x1500)); // gap between functions
        assert!(c.covers(0x2008));
        assert!(!c.covers(0x500)); // before the first FDE
        assert!(!c.covers(0x9999)); // past the last FDE — the noeh shape
    }

    #[test]
    fn covered_fraction_counts_hits() {
        let c = FdeCoverage { ranges: vec![0x1000..0x1040] };
        // Two covered, two not.
        assert_eq!(c.covered_fraction(&[0x1000, 0x1020, 0x5000, 0x6000]), 0.5);
        assert_eq!(c.covered_fraction(&[]), 1.0);
    }

    // The running test binary carries `.eh_frame` covering its own code and
    // resolves the FP prologue read path, so a real sampled address in it must
    // read as covered — the inverse of the noeh condition.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn self_binary_is_fde_covered() {
        let bytes = std::fs::read("/proc/self/exe").unwrap();
        let file = object::File::parse(&bytes[..]).unwrap();
        let coverage = FdeCoverage::from_object(&file);
        assert!(!coverage.ranges.is_empty(), "self has .eh_frame FDEs");
        // A known function's link-time vaddr: read it from the symbol table via
        // object so the test needs no runtime capture.
        use object::ObjectSymbol;
        let sym = file
            .symbols()
            .find(|s| s.name() == Ok("main") && s.address() != 0);
        if let Some(sym) = sym {
            assert!(
                coverage.covers(sym.address()),
                "main@{:#x} should be FDE-covered",
                sym.address()
            );
            // The public checks take image-relative addresses; convert main's
            // svma back. A healthy, FDE-covered binary must not read as lacking
            // coverage.
            let rel = sym.address() - image_base(&file);
            assert!(!sampled_code_lacks_fde_coverage(&bytes, &[rel]));
        }
    }
}
