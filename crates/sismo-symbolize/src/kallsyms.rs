// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Kernel-symbol resolution from `/proc/kallsyms`.
//!
//! Kernel frames ship as raw PCs (see the BPF collector) and are rebased to
//! `[kernel.kallsyms]`-relative addresses at capture time — `rel = pc - kbase`,
//! where `kbase` is the kernel text base ([`kernel_text_base`]). The post-record
//! symbolize pass then resolves those relative addresses here, against the same
//! `/proc/kallsyms` (same boot, same process), so the two share one base and the
//! KASLR slide never reaches the trace.
//!
//! kallsyms is names-only — no line info, no inline frames — so this plugs in
//! as a [`SymbolSource`] (the same names-only fallback shape as `.gopclntab` /
//! `.dynsym`), not as a wholesym DWARF `SymbolMap`.
//!
//! Reading real addresses needs `/proc/kallsyms` unmasked (cap_syslog, or a
//! permissive `kptr_restrict`/`perf_event_paranoid` — `sismo doctor --fix`
//! arranges it). When masked, every address reads as zero and loading fails;
//! kernel frames then stay `[kernel]`.

use crate::fallback::SymbolSource;

const KALLSYMS: &str = "/proc/kallsyms";

/// The running kernel's text base: the `_text` address (preferred, the ELF
/// image base wholesym-style) or `_stext`. 0 when kallsyms is masked. Both the
/// capture-side rebasing and [`Kallsyms::load`] use this, so their relative
/// address spaces coincide.
pub fn kernel_text_base() -> u64 {
    std::fs::read_to_string(KALLSYMS)
        .ok()
        .and_then(|t| text_base_of(&t))
        .unwrap_or(0)
}

/// A vmlinux debug image for the running kernel, if one is installed — the
/// preferred kernel symbol source (DWARF line info + inline frames, which
/// kallsyms lacks). Checks the usual debuginfo locations for this `uname -r`.
pub fn vmlinux_debug_path() -> Option<std::path::PathBuf> {
    let rel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()?
        .trim()
        .to_string();
    [
        format!("/usr/lib/debug/lib/modules/{rel}/vmlinux"),
        format!("/usr/lib/debug/boot/vmlinux-{rel}"),
        format!("/boot/vmlinux-{rel}"),
    ]
    .into_iter()
    .map(std::path::PathBuf::from)
    .find(|p| p.exists())
}

fn text_base_of(kallsyms: &str) -> Option<u64> {
    let mut text = 0u64;
    let mut stext = 0u64;
    for line in kallsyms.lines() {
        let mut it = line.split_whitespace();
        let (Some(addr), Some(_ty), Some(name)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        match name {
            "_text" => text = u64::from_str_radix(addr, 16).unwrap_or(0),
            "_stext" => stext = u64::from_str_radix(addr, 16).unwrap_or(0),
            _ => continue,
        }
        if text != 0 && stext != 0 {
            break;
        }
    }
    let base = if text != 0 { text } else { stext };
    (base != 0).then_some(base)
}

/// Kernel text symbols, sorted by base-relative address, resolved by
/// nearest-preceding lookup.
pub struct Kallsyms {
    // (rel_addr, name), sorted ascending by rel_addr, deduped.
    syms: Vec<(u64, String)>,
    // Relative address of `_etext` — the resolution bound, so a stray PC past
    // the kernel text doesn't attach to the last symbol with a wild offset.
    text_end: u64,
}

impl Kallsyms {
    /// Load kernel text symbols, or `None` when kallsyms is masked/empty.
    /// Boxed as a [`SymbolSource`] so it drops straight into the symbolizer's
    /// names-only fallback chain.
    pub fn load() -> Option<Box<dyn SymbolSource>> {
        let text = std::fs::read_to_string(KALLSYMS).ok()?;
        let base = text_base_of(&text)?;
        let mut syms: Vec<(u64, String)> = Vec::new();
        let mut text_end = u64::MAX;
        for line in text.lines() {
            let mut it = line.split_whitespace();
            let (Some(addr), Some(ty), Some(name)) = (it.next(), it.next(), it.next()) else {
                continue;
            };
            let addr = u64::from_str_radix(addr, 16).unwrap_or(0);
            if addr < base {
                continue;
            }
            if name == "_etext" {
                text_end = addr - base;
            }
            // Text symbols only (t/T = local/global code); data symbols never
            // hold a return address.
            if ty.eq_ignore_ascii_case("t") {
                syms.push((addr - base, name.to_string()));
            }
        }
        if syms.is_empty() {
            return None;
        }
        syms.sort_by_key(|&(a, _)| a);
        syms.dedup_by_key(|p| p.0);
        Some(Box::new(Kallsyms { syms, text_end }))
    }
}

impl SymbolSource for Kallsyms {
    fn len(&self) -> usize {
        self.syms.len()
    }

    fn resolve(&self, rel: u64) -> Option<(&str, u64)> {
        if rel >= self.text_end {
            return None;
        }
        // Largest symbol whose address is <= rel.
        let idx = match self.syms.binary_search_by_key(&rel, |&(a, _)| a) {
            Ok(i) => i,
            Err(0) => return None, // before the first symbol
            Err(i) => i - 1,
        };
        let (addr, name) = &self.syms[idx];
        Some((name.as_str(), rel - addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_text_over_stext() {
        let k = "ffffffff81000000 T _stext\nffffffff80e00000 T _text\n";
        assert_eq!(text_base_of(k), Some(0xffff_ffff_80e0_0000));
    }

    #[test]
    fn falls_back_to_stext() {
        assert_eq!(text_base_of("ffffffff81000000 T _stext\n"), Some(0xffff_ffff_8100_0000));
    }

    #[test]
    fn masked_kallsyms_has_no_base() {
        assert_eq!(text_base_of("0000000000000000 T _text\n"), None);
    }

    #[test]
    fn resolves_nearest_preceding() {
        let k = Kallsyms {
            syms: vec![(0x1000, "a".into()), (0x1100, "b".into()), (0x1200, "c".into())],
            text_end: 0x2000,
        };
        assert_eq!(k.resolve(0x1000), Some(("a", 0)));
        assert_eq!(k.resolve(0x1180), Some(("b", 0x80)));
        assert_eq!(k.resolve(0x0fff), None); // before first
        assert_eq!(k.resolve(0x2000), None); // past _etext
    }
}
