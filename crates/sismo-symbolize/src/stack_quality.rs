// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! DIA-0: the per-module stack-quality primitive every "why is my stack
//! truncated" diagnostic builds on. Two cheap, independent signals.
//!
//! 1. Observed stack shape. A frame-pointer-omitting module truncates to a
//!    single user frame — the sampled PC with no recoverable caller — because
//!    the kernel frame-pointer walker cannot step past a frame that saved no
//!    frame pointer. A genuine call stack always bottoms out at the thread
//!    entry (`_start` / `start_thread`), so it is never a single frame.
//!    Single-frame dominance is therefore an unambiguous truncation signal with
//!    no false positive on small programs. Measured on the matrix: fully
//!    FP-less C/Rust builds sample 60–99% single-frame; every frame-pointer
//!    build samples 0%. (Leaf-only FP omission — gcc/Go dropping just the hot
//!    leaf's frame pointer — keeps a deep stack minus one middle frame, so it
//!    is deliberately not flagged here; that "partial" case is a later item.)
//!
//! 2. Unwind capability. Whether the module ships `.eh_frame` CFI, probed from
//!    the `PT_GNU_EH_FRAME` program header so it works even when the section
//!    header table was stripped. This does not decide whether today's FP-only
//!    capture truncated — it tells a diagnostic which remedy to name (an
//!    offline DWARF unwinder can recover the stack vs. the user must rebuild
//!    with frame pointers).
//!
//! These are internal APIs; the DIA-1+ diagnostics consume them. Nothing
//! user-visible changes yet.

use std::os::unix::fs::FileExt;

// Program header type for the `.eh_frame_hdr` lookup table.
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;

// Section header type for PROGBITS (holds `.eh_frame`).
const SHT_PROGBITS: u32 = 1;

/// Below this many samples a module hasn't been observed enough to judge —
/// keeps a couple of stray single-frame samples from flagging a cold module.
const MIN_SAMPLES: u64 = 16;

/// Fraction of single-frame samples at or above which a module is called
/// truncated. The measured separation is wide — truncating builds sit at
/// 0.6–1.0, frame-pointer builds at 0.0 — so a half threshold clears both.
const TRUNCATED_FRAC: f64 = 0.5;

/// Verdict for the stacks observed under one module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackQuality {
    /// Stacks reach a real caller chain; no truncation signal.
    Healthy,
    /// Single-frame samples dominate — frame-pointer omission truncated the
    /// stacks to the sampled PC.
    LikelyTruncated,
    /// Too few samples to judge.
    Inconclusive,
}

/// Single-frame vs. total sample counts for the samples whose innermost frame
/// lands in one module. The caller tallies only that module's samples so the
/// verdict is per-module.
#[derive(Debug, Default, Clone, Copy)]
pub struct StackShape {
    pub total: u64,
    pub single_frame: u64,
}

impl StackShape {
    /// Tally per-sample user-frame counts. A sample with one (or zero) user
    /// frames is the truncation marker.
    pub fn from_frame_counts(counts: impl IntoIterator<Item = u32>) -> StackShape {
        let mut s = StackShape::default();
        for n in counts {
            s.total += 1;
            if n <= 1 {
                s.single_frame += 1;
            }
        }
        s
    }

    /// The truncation verdict for these samples.
    pub fn classify(&self) -> StackQuality {
        if self.total < MIN_SAMPLES {
            return StackQuality::Inconclusive;
        }
        if self.single_frame as f64 / self.total as f64 >= TRUNCATED_FRAC {
            StackQuality::LikelyTruncated
        } else {
            StackQuality::Healthy
        }
    }
}

/// A module's unwind metadata, probed from its ELF program headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwindCapability {
    /// `.eh_frame` CFI is present (via `PT_GNU_EH_FRAME` → `.eh_frame_hdr`), so
    /// an offline DWARF unwinder can recover FP-less stacks for this module.
    pub has_eh_frame: bool,
}

/// Probe the ELF at `path` for unwind metadata. `None` if it isn't a readable
/// 64-bit LE ELF. `has_eh_frame` reflects what the offline unwinder can actually
/// find: the `PT_GNU_EH_FRAME` program header (present even when the section
/// table was stripped) *or* a `.eh_frame` section. Checking only the phdr
/// under-reports for a binary linked with `--no-eh-frame-hdr` (the `.eh_frame`
/// section is still there and framehop indexes it directly).
pub fn probe_unwind_capability(path: &str) -> Option<UnwindCapability> {
    let f = std::fs::File::open(path).ok()?;
    let mut ehdr = [0u8; 64];
    f.read_exact_at(&mut ehdr, 0).ok()?;
    if &ehdr[0..4] != b"\x7fELF" || ehdr[4] != 2 {
        return None; // not ELFCLASS64
    }
    let e_phoff = u64::from_le_bytes(ehdr[32..40].try_into().unwrap());
    let e_phentsize = u16::from_le_bytes(ehdr[54..56].try_into().unwrap());
    let e_phnum = u16::from_le_bytes(ehdr[56..58].try_into().unwrap());
    if e_phentsize < 56 || e_phnum > 4096 {
        return None;
    }
    let mut has_eh_frame = false;
    for i in 0..e_phnum {
        // p_type is the first 4 bytes of the program header; that's all we need.
        let mut p_type = [0u8; 4];
        if f
            .read_exact_at(&mut p_type, e_phoff + i as u64 * e_phentsize as u64)
            .is_err()
        {
            return None;
        }
        if u32::from_le_bytes(p_type) == PT_GNU_EH_FRAME {
            has_eh_frame = true;
            break;
        }
    }
    // No PT_GNU_EH_FRAME (e.g. --no-eh-frame-hdr): look for a `.eh_frame`
    // section directly. Absent section headers just leave `has_eh_frame` as-is.
    if !has_eh_frame {
        has_eh_frame = has_eh_frame_section(&f, &ehdr).unwrap_or(false);
    }
    Some(UnwindCapability { has_eh_frame })
}

/// Whether the ELF carries a section literally named `.eh_frame`. Reads the
/// section header table and its name strings; `None` on any malformed field or a
/// stripped section table. `ehdr` is the already-read 64-byte ELF header.
fn has_eh_frame_section(f: &std::fs::File, ehdr: &[u8; 64]) -> Option<bool> {
    let e_shoff = u64::from_le_bytes(ehdr[40..48].try_into().unwrap());
    let e_shentsize = u16::from_le_bytes(ehdr[58..60].try_into().unwrap()) as u64;
    let e_shnum = u16::from_le_bytes(ehdr[60..62].try_into().unwrap());
    let e_shstrndx = u16::from_le_bytes(ehdr[62..64].try_into().unwrap());
    if e_shoff == 0 || e_shentsize < 64 || e_shnum == 0 || e_shstrndx >= e_shnum {
        return None;
    }
    // The shstrtab section header gives the offset/size of the name string pool.
    let mut sh = [0u8; 64];
    f.read_exact_at(&mut sh, e_shoff + e_shstrndx as u64 * e_shentsize)
        .ok()?;
    let str_off = u64::from_le_bytes(sh[24..32].try_into().unwrap());
    let str_sz = u64::from_le_bytes(sh[32..40].try_into().unwrap());
    if str_sz == 0 || str_sz > 16 * 1024 * 1024 {
        return None;
    }
    let mut strtab = vec![0u8; str_sz as usize];
    f.read_exact_at(&mut strtab, str_off).ok()?;
    for i in 0..e_shnum {
        f.read_exact_at(&mut sh, e_shoff + i as u64 * e_shentsize)
            .ok()?;
        let sh_name = u32::from_le_bytes(sh[0..4].try_into().unwrap()) as usize;
        let sh_type = u32::from_le_bytes(sh[4..8].try_into().unwrap());
        if sh_type != SHT_PROGBITS {
            continue;
        }
        let name = strtab.get(sh_name..)?;
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        if &name[..end] == b".eh_frame" {
            return Some(true);
        }
    }
    Some(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_flags_single_frame_dominance() {
        // Modeled on the measured rust-release split (~60% single-frame).
        let s = StackShape { total: 972, single_frame: 591 };
        assert_eq!(s.classify(), StackQuality::LikelyTruncated);
        // Fully truncated (c-gcc-O2 was ~99%).
        let s = StackShape { total: 1060, single_frame: 1058 };
        assert_eq!(s.classify(), StackQuality::LikelyTruncated);
    }

    #[test]
    fn classify_passes_deep_stacks() {
        // A frame-pointer build: no single-frame samples at all.
        let s = StackShape { total: 500, single_frame: 0 };
        assert_eq!(s.classify(), StackQuality::Healthy);
        // A handful of stray single-frame samples doesn't flag a healthy module.
        let s = StackShape { total: 500, single_frame: 20 };
        assert_eq!(s.classify(), StackQuality::Healthy);
    }

    #[test]
    fn classify_is_inconclusive_below_the_floor() {
        // Even 100% single-frame is inconclusive with too few samples — avoids
        // false-flagging a barely-sampled module.
        let s = StackShape { total: 4, single_frame: 4 };
        assert_eq!(s.classify(), StackQuality::Inconclusive);
        let s = StackShape::default();
        assert_eq!(s.classify(), StackQuality::Inconclusive);
    }

    #[test]
    fn classify_at_exactly_half_flags() {
        let s = StackShape { total: 100, single_frame: 50 };
        assert_eq!(s.classify(), StackQuality::LikelyTruncated);
        let s = StackShape { total: 100, single_frame: 49 };
        assert_eq!(s.classify(), StackQuality::Healthy);
    }

    #[test]
    fn from_frame_counts_tallies_single_frames() {
        // Counts: three single-frame (1, 0, 1) and two multi-frame (5, 12).
        let s = StackShape::from_frame_counts([1u32, 5, 0, 12, 1]);
        assert_eq!(s.total, 5);
        assert_eq!(s.single_frame, 3);
    }

    // The running test binary is an ordinary ELF and carries `.eh_frame`, so the
    // probe must find it. Exercises the real program-header read path.
    #[cfg(target_os = "linux")]
    #[test]
    fn probe_self_has_eh_frame() {
        let exe = std::fs::read_link("/proc/self/exe").expect("readlink");
        let cap = probe_unwind_capability(exe.to_str().unwrap()).expect("probe self");
        assert!(cap.has_eh_frame);
    }

    #[test]
    fn probe_non_elf_is_none() {
        // /etc/hostname exists and is not an ELF.
        assert!(probe_unwind_capability("/etc/hostname").is_none());
        assert!(probe_unwind_capability("/no/such/path").is_none());
    }

    // Finding B: with no PT_GNU_EH_FRAME (as `--no-eh-frame-hdr` produces) the
    // probe must fall back to the `.eh_frame` section rather than under-report.
    // Simulate it by neutralizing the phdr in a copy of the test binary and
    // confirming the section scan still finds `.eh_frame`.
    #[cfg(target_os = "linux")]
    #[test]
    fn probe_via_section_when_no_eh_frame_phdr() {
        let mut elf = std::fs::read("/proc/self/exe").expect("read exe");
        let e_phoff = u64::from_le_bytes(elf[32..40].try_into().unwrap()) as usize;
        let e_phentsize = u16::from_le_bytes(elf[54..56].try_into().unwrap()) as usize;
        let e_phnum = u16::from_le_bytes(elf[56..58].try_into().unwrap()) as usize;
        let mut neutralized = false;
        for i in 0..e_phnum {
            let off = e_phoff + i * e_phentsize;
            if u32::from_le_bytes(elf[off..off + 4].try_into().unwrap()) == PT_GNU_EH_FRAME {
                elf[off..off + 4].fill(0); // PT_NULL
                neutralized = true;
            }
        }
        assert!(neutralized, "test binary has no PT_GNU_EH_FRAME to neutralize");

        let path = std::env::temp_dir().join(format!("sismo-probe-{}", std::process::id()));
        std::fs::write(&path, &elf).expect("write temp elf");
        let cap = probe_unwind_capability(path.to_str().unwrap()).expect("probe");
        let _ = std::fs::remove_file(&path);
        assert!(cap.has_eh_frame, "should find .eh_frame via the section table");
    }
}
