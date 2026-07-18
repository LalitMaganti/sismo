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
/// 64-bit LE ELF. Reads only the program headers, so it works on binaries whose
/// section header table was stripped.
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
    Some(UnwindCapability { has_eh_frame })
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
}
