// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Symbol resolver for dylibs that live only in the dyld shared cache.
//!
//! Since Big Sur, macOS system dylibs have no on-disk file — their bytes exist
//! only inside `dyld_shared_cache_<arch>`. wholesym knows this and consults
//! the cache, but samply-symbols 0.24 discovers the cache's subcache files by
//! *probing* names (`.1`/`.01`, `.2`/`.02`, …) and stops at the first miss.
//! macOS 26 names them `.01`, `.02.dylddata`, `.03.dyldreadonly`,
//! `.04.dyldlinkedit`, … — the probe finds only `.01` and `DyldCache::parse`
//! rejects the incomplete set ("Incorrect number of SubCaches"), so every
//! cache-only dylib silently loses its symbols. `object` itself reads the true
//! suffix list from the main cache header (`DyldCache::subcache_suffixes`);
//! this resolver does exactly that and pulls the member's nlist symbols out
//! directly.
//!
//! Scope: names only (cache dylibs carry no DWARF — line info for system
//! frames would need the separate .symbols/dSYM story). Tried only when
//! wholesym loaded zero symbols for a `/usr/` / `/System/` module, matched by
//! LC_UUID so a stale cache from another OS build can't mislabel frames.
//! macOS-only; gated in lib.rs.

use object::read::macho::DyldCache;
use object::read::ReadCache;
use object::{Object, ObjectSegment, ObjectSymbol};
use std::fs::File;

/// The cache directories, newest layout first (macOS 13+ cryptex, then the
/// pre-13 location).
const CACHE_DIRS: &[&str] = &[
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld",
    "/System/Library/dyld",
];

/// Cache flavors within a directory. Every candidate is tried and the LC_UUID
/// decides, so ordering is a fast-path preference, not a correctness choice:
/// native first (arm64e on Apple silicon), then the Rosetta / Intel caches.
#[cfg(target_arch = "aarch64")]
const CACHE_ARCHES: &[&str] = &["arm64e", "x86_64h", "x86_64"];
#[cfg(not(target_arch = "aarch64"))]
const CACHE_ARCHES: &[&str] = &["x86_64h", "x86_64", "arm64e"];

/// One defined symbol: its offset from the dylib's `__TEXT` base, and its name.
struct Sym {
    rel: u64,
    name: String,
}

/// A cache member's symbol table, sorted by `rel` for binary-search lookup.
pub struct DyldCacheSyms {
    syms: Vec<Sym>,
}

impl DyldCacheSyms {
    /// Extract the symbols of `dylib_path` from the host's dyld shared cache.
    /// `uuid` must match the member's LC_UUID — the same identity the trace
    /// carries for the mapping. `None` when no cache candidate holds a
    /// matching member (wrong arch caches are skipped by that same check).
    pub fn for_dylib(dylib_path: &str, uuid: [u8; 16]) -> Option<DyldCacheSyms> {
        for dir in CACHE_DIRS {
            for arch in CACHE_ARCHES {
                let main = format!("{dir}/dyld_shared_cache_{arch}");
                if let Some(syms) = Self::from_cache_file(&main, dylib_path, uuid) {
                    return Some(syms);
                }
            }
        }
        None
    }

    /// Try one cache file. Best effort: any open/parse failure yields None and
    /// the caller moves to the next candidate. `ReadCache` keeps this frugal —
    /// only the headers, the image list, and the member's linkedit pages are
    /// actually read from these multi-GB files.
    fn from_cache_file(main_path: &str, dylib_path: &str, uuid: [u8; 16]) -> Option<DyldCacheSyms> {
        let main_file = File::open(main_path).ok()?;
        let main = ReadCache::new(main_file);
        let suffixes = DyldCache::<object::Endianness, _>::subcache_suffixes(&main).ok()?;
        let sub_files: Vec<ReadCache<File>> = suffixes
            .iter()
            .map(|s| File::open(format!("{main_path}{s}")).map(ReadCache::new))
            .collect::<Result<_, _>>()
            .ok()?;
        let sub_refs: Vec<&ReadCache<File>> = sub_files.iter().collect();
        let cache = DyldCache::<object::Endianness, _>::parse(&main, &sub_refs).ok()?;

        let image = cache.images().find(|i| i.path() == Ok(dylib_path))?;
        let obj = image.parse_object().ok()?;
        if obj.mach_uuid() != Ok(Some(uuid)) {
            return None;
        }

        // Symbol addresses are unslid vaddrs; the trace's rel space is "offset
        // from the mapped __TEXT base", and the cache slide cancels:
        // avma - base = vaddr - text_vmaddr.
        let text_base = obj
            .segments()
            .find(|s| s.name() == Ok(Some("__TEXT")))
            .map(|s| s.address())?;

        let mut syms: Vec<Sym> = obj
            .symbols()
            .filter(|s| s.is_definition() && s.address() >= text_base)
            .map(|s| Sym {
                rel: s.address() - text_base,
                // One leading underscore is the mach-o C decoration; strip it
                // (C++ names keep their remaining _Z… mangling, matching the
                // names-only quality of the other fallbacks).
                name: {
                    let n = s.name().unwrap_or("");
                    n.strip_prefix('_').unwrap_or(n).to_string()
                },
            })
            .filter(|s| !s.name.is_empty())
            .collect();
        if syms.is_empty() {
            return None;
        }
        syms.sort_by(|a, b| a.rel.cmp(&b.rel).then_with(|| a.name.cmp(&b.name)));
        syms.dedup_by(|a, b| a.rel == b.rel);
        Some(DyldCacheSyms { syms })
    }

    pub fn len(&self) -> usize {
        self.syms.len()
    }

    pub fn is_empty(&self) -> bool {
        self.syms.is_empty()
    }

    /// Resolve an offset-from-`__TEXT` to `(name, offset-within-function)`.
    /// nlist entries carry no size, so a symbol runs until the next one.
    pub fn resolve(&self, rel: u64) -> Option<(&str, u64)> {
        let idx = match self.syms.binary_search_by(|s| s.rel.cmp(&rel)) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let s = &self.syms[idx];
        let end = self.syms.get(idx + 1).map(|n| n.rel).unwrap_or(u64::MAX);
        if rel < end {
            Some((&s.name, rel - s.rel))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // libsystem_c has been cache-only since Big Sur, so on any modern macOS
    // this exercises the full path: suffix discovery, subcache loading, member
    // extraction, UUID matching, and lookup. The UUID comes from the cache
    // itself via a first pass, then a second pass must round-trip through the
    // match; a wrong UUID must yield nothing.
    #[test]
    fn libsystem_c_resolves_from_the_cache() {
        const PATH: &str = "/usr/lib/system/libsystem_c.dylib";
        // First pass: discover the real UUID by asking object directly.
        let mut real_uuid = None;
        for dir in CACHE_DIRS {
            for arch in CACHE_ARCHES {
                let main_path = format!("{dir}/dyld_shared_cache_{arch}");
                let Ok(f) = File::open(&main_path) else { continue };
                let main = ReadCache::new(f);
                let Ok(suffixes) = DyldCache::<object::Endianness, _>::subcache_suffixes(&main)
                else {
                    continue;
                };
                let Ok(subs) = suffixes
                    .iter()
                    .map(|s| File::open(format!("{main_path}{s}")).map(ReadCache::new))
                    .collect::<Result<Vec<_>, _>>()
                else {
                    continue;
                };
                let sub_refs: Vec<&ReadCache<File>> = subs.iter().collect();
                let Ok(cache) = DyldCache::<object::Endianness, _>::parse(&main, &sub_refs)
                else {
                    continue;
                };
                if let Some(img) = cache.images().find(|i| i.path() == Ok(PATH)) {
                    if let Ok(obj) = img.parse_object() {
                        if let Ok(Some(u)) = obj.mach_uuid() {
                            real_uuid = Some(u);
                        }
                    }
                }
                if real_uuid.is_some() {
                    break;
                }
            }
        }
        let Some(uuid) = real_uuid else {
            eprintln!("skipping: no dyld shared cache with libsystem_c on this host");
            return;
        };

        let syms = DyldCacheSyms::for_dylib(PATH, uuid).expect("cache member with symbols");
        assert!(syms.len() > 100, "expected a real symbol table, got {}", syms.len());
        // atoi is a stable libsystem_c export; find its rel and round-trip a
        // mid-function address through resolve.
        let atoi = syms.syms.iter().find(|s| s.name == "atoi").expect("atoi in symtab");
        let (name, off) = syms.resolve(atoi.rel + 4).expect("resolve inside atoi");
        assert_eq!(name, "atoi");
        assert_eq!(off, 4);

        // A wrong UUID must not match any candidate.
        assert!(DyldCacheSyms::for_dylib(PATH, [0xAB; 16]).is_none());
    }
}
