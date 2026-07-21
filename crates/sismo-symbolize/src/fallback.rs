// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! The names-only fallback symbol sources behind the wholesym primary, and the
//! ONE place platform-specific sources are chosen.
//!
//! wholesym carries DWARF (inline chains, line info) and is always tried
//! first. When it comes up empty — or answers with a synthesized placeholder —
//! a module falls back to whatever format-specific source can still name its
//! functions: `.gopclntab` for stripped Go, `.dynsym`-via-`PT_DYNAMIC` for
//! section-header-stripped ELF, the dyld shared cache for cache-only macOS
//! system dylibs. Each is a [`SymbolSource`]; [`load_fallbacks`] builds the
//! ordered chain for a module, and it is the only spot in the symbolizer that
//! knows which sources exist on which platform — everything downstream just
//! walks the chain.

use std::path::Path;

/// A names-only symbol source: resolve a module-relative address to
/// `(function name, offset within function)`. No inline frames, no line info —
/// that quality lives only in the wholesym primary.
pub trait SymbolSource {
    /// Number of symbols, reported as the module's count when wholesym had 0.
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn resolve(&self, rel: u64) -> Option<(&str, u64)>;
}

#[cfg(not(target_os = "windows"))]
impl SymbolSource for crate::gopclntab::GoPclntab {
    fn len(&self) -> usize {
        self.len()
    }
    fn resolve(&self, rel: u64) -> Option<(&str, u64)> {
        self.resolve(rel)
    }
}

#[cfg(not(target_os = "windows"))]
impl SymbolSource for crate::dynsym::DynSyms {
    fn len(&self) -> usize {
        self.len()
    }
    fn resolve(&self, rel: u64) -> Option<(&str, u64)> {
        self.resolve(rel)
    }
}

#[cfg(target_os = "macos")]
impl SymbolSource for sismo_macho::dyld_cache::DyldCacheSyms {
    fn len(&self) -> usize {
        self.len()
    }
    fn resolve(&self, rel: u64) -> Option<(&str, u64)> {
        self.resolve(rel)
    }
}

/// Build the fallback chain for the module at `path`, in resolution order.
/// `wholesym_count` is the primary's symbol count — most sources are only
/// worth loading when it found nothing. Quality order: format-aware sources
/// (`.gopclntab`) before generic symbol tables.
#[allow(unused_variables)]
pub fn load_fallbacks(
    path: &Path,
    uuid: Option<[u8; 16]>,
    wholesym_count: u64,
) -> Vec<Box<dyn SymbolSource>> {
    let mut chain: Vec<Box<dyn SymbolSource>> = Vec::new();

    #[cfg(not(target_os = "windows"))]
    {
        // A stripped Go binary keeps `.gopclntab`. Loaded even when wholesym
        // found symbols: what it found may be synthesized placeholders, and a
        // real Go name must win over `fun_1234`. Cheap to skip: non-Go
        // binaries have no `.gopclntab` and `from_path` bails.
        if let Some(g) = path.to_str().and_then(crate::gopclntab::GoPclntab::from_path) {
            chain.push(Box::new(g));
        }
        // A section-header-stripped ELF hides its names from wholesym, but the
        // dynamic segment still reaches them.
        if wholesym_count == 0 {
            if let Some(d) = path.to_str().and_then(crate::dynsym::DynSyms::from_path) {
                chain.push(Box::new(d));
            }
        }
    }

    // A cache-only macOS system dylib (no on-disk file since Big Sur): read
    // the member's nlist straight out of the dyld shared cache, matched by
    // the mapping's LC_UUID. Needed because wholesym's own cache reader
    // mis-probes the macOS 26 subcache file names and comes up empty.
    #[cfg(target_os = "macos")]
    if wholesym_count == 0 && (path.starts_with("/usr/") || path.starts_with("/System/")) {
        let cache_syms = uuid.filter(|u| *u != [0u8; 16]).and_then(|u| {
            path.to_str()
                .and_then(|p| sismo_macho::dyld_cache::DyldCacheSyms::for_dylib(p, u))
        });
        if let Some(c) = cache_syms {
            chain.push(Box::new(c));
        }
    }

    chain
}
