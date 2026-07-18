// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! wholesym FFI surface — resolves AVMA → demangled function name +
//! offset (and inline frame info where debug info is available).
//!
//! Lifecycle: [`Symbolizer::new`] bundles a current-thread tokio runtime and a
//! wholesym `SymbolManager`. Callers register modules by `(base_avma, end_avma,
//! path)` via [`Symbolizer::add_module`], then [`Symbolizer::resolve`] an AVMA
//! to a demangled name + source location.
//!
//! All symbol-map loads are synchronous from the caller's perspective —
//! the runtime `block_on`'s wholesym's async API internally. This is the
//! right shape for a sampler/post-processor that runs symbolication on a
//! single thread; for higher concurrency we'd switch to a multi-thread
//! runtime, but that's overkill for v0.

use std::path::{Path, PathBuf};

use wholesym::{
    debugid::DebugId, LookupAddress, MultiArchDisambiguator, SymbolManager, SymbolManagerConfig,
    SymbolMap,
};

pub struct Symbolizer {
    rt: tokio::runtime::Runtime,
    manager: SymbolManager,
    modules: Vec<SymModule>,
}

/// Outcome of [`Symbolizer::add_module`]. `symbol_count` is 0 when the symbol
/// map failed to load; `error` then carries the wholesym render. The avma range
/// is registered either way, so a failed load makes `resolve` return `None` for
/// that range instead of matching a neighbor module.
pub struct ModuleLoad {
    pub symbol_count: u64,
    pub error: Option<String>,
}

/// One frame at a resolved address: a demangled function name plus source
/// location when debug info is available (`line` 0 = unknown, `file` None =
/// unknown).
pub struct Frame {
    pub name: String,
    pub file: Option<String>,
    pub line: u32,
}

/// A resolved address. `frames` is the inline chain at the address, ordered
/// innermost inlinee first and the physical (outermost) function last — the
/// order Perfetto's `AddressSymbols.lines` expects. It always has at least one
/// entry. `offset` is the byte offset of the address from the start of the
/// physical function.
pub struct Resolved {
    pub frames: Vec<Frame>,
    pub offset: u64,
}

impl Resolved {
    /// The physical (outermost) function's frame — the one a caller that does
    /// not expand inline frames wants (heap display, disassembly labels).
    pub fn outer(&self) -> &Frame {
        self.frames.last().expect("resolve never returns empty frames")
    }

    /// The outer function's name with the byte offset suffix, e.g. `foo +12`.
    /// The single-line view for callers that don't expand inline frames.
    pub fn outer_display(&self) -> String {
        format!("{} +{}", self.outer().name, self.offset)
    }
}

struct SymModule {
    base_avma: u64,
    end_avma: u64,
    /// `None` if `load_symbol_map_for_binary_at_path` failed for this
    /// path (e.g. file missing, not a recognized binary, no debug info).
    /// We still keep the entry so the avma range is taken — `resolve`
    /// returns 0 (= no match) instead of falling through to a wrong
    /// neighbor module's range.
    map: Option<SymbolMap>,
    /// `.dynsym`-via-PT_DYNAMIC fallback, populated only when wholesym found
    /// zero symbols (a section-header-stripped ELF). Names only, no line info.
    #[cfg(not(target_os = "windows"))]
    dynsym: Option<crate::dynsym::DynSyms>,
}

/// Build the wholesym config. Debuginfod is opt-in (it does network I/O),
/// so only enable it when the standard `DEBUGINFOD_URLS` env var is set —
/// the same switch `debuginfod-find` and gdb honor. wholesym 0.8 still
/// needs an explicit cache dir even when the system debuginfod client is
/// installed, so point it at `$XDG_CACHE_HOME/sismo/debuginfod` (falling
/// back to a temp dir). This is what lets sismo symbolize *stripped*
/// system libraries whose debug info lives in a separate file/server.
fn build_config() -> SymbolManagerConfig {
    let mut cfg = SymbolManagerConfig::default();
    if std::env::var_os("DEBUGINFOD_URLS").is_some() {
        let cache = cache_dir().join("sismo").join("debuginfod");
        cfg = cfg
            .use_debuginfod(true)
            .debuginfod_cache_dir_if_not_installed(cache);
    }
    cfg
}

fn cache_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(d);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".cache");
    }
    std::env::temp_dir()
}

impl Symbolizer {
    /// Build a symbolizer: a current-thread tokio runtime plus a wholesym
    /// `SymbolManager`. `None` if the runtime can't be built.
    pub fn new() -> Option<Symbolizer> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()?;
        let manager = SymbolManager::with_config(build_config());
        Some(Symbolizer {
            rt,
            manager,
            modules: Vec::new(),
        })
    }

    /// Register a module by path so AVMAs in `[base_avma, end_avma)` resolve to
    /// symbols within it. `uuid` (when non-zero) is the preferred disambiguator;
    /// `arch` is the fallback when a UUID isn't available.
    ///
    /// The avma range is registered even when the symbol map fails to load (the
    /// returned `error` says why) — a load failure is sometimes expected
    /// (dyld_shared_cache-only macOS system dylibs) and sometimes actionable (a
    /// stripped Linux binary with no debug info); keeping the range means
    /// `resolve` returns `None` here instead of matching a neighbor module.
    pub fn add_module(
        &mut self,
        base_avma: u64,
        end_avma: u64,
        path: &Path,
        uuid: Option<[u8; 16]>,
        arch: Option<&str>,
    ) -> ModuleLoad {
        // Prefer UUID-based disambiguation. samply-symbols' fat-archive `arch`
        // field reports both arm64 and arm64e entries as "arm64", so an
        // Arch("arm64e") disambiguator never matches arm64e slices; UUID
        // matching is exact and bypasses the issue.
        let disambiguator = uuid
            .filter(|u| *u != [0u8; 16])
            // debugid takes the `uuid::Uuid` type, not raw bytes, and doesn't
            // re-export it — pull `uuid` in directly.
            .map(|u| MultiArchDisambiguator::DebugId(DebugId::from_uuid(uuid::Uuid::from_bytes(u))))
            .or_else(|| arch.map(|a| MultiArchDisambiguator::Arch(a.to_string())));

        let load = self.rt.block_on(
            self.manager
                .load_symbol_map_for_binary_at_path(path, disambiguator),
        );
        let (map, mut result) = match load {
            Ok(m) => {
                let symbol_count = m.symbol_count() as u64;
                (Some(m), ModuleLoad { symbol_count, error: None })
            }
            Err(e) => (None, ModuleLoad { symbol_count: 0, error: Some(format!("{e}")) }),
        };

        // When wholesym found no symbols, the ELF may have had its section
        // header table stripped — its names are still reachable through the
        // dynamic segment. Try that fallback and, if it works, report the
        // recovered count so the module status is honest rather than the
        // misleading "0 symbols / binary changed" it produced before.
        #[cfg(not(target_os = "windows"))]
        let dynsym = if result.symbol_count == 0 {
            let d = path.to_str().and_then(crate::dynsym::DynSyms::from_path);
            if let Some(d) = d.as_ref() {
                result = ModuleLoad { symbol_count: d.len() as u64, error: None };
            }
            d
        } else {
            None
        };

        self.modules.push(SymModule {
            base_avma,
            end_avma,
            map,
            #[cfg(not(target_os = "windows"))]
            dynsym,
        });
        result
    }

    /// Resolve `avma` to its inline chain (innermost inlinee first, physical
    /// function last) plus the byte offset from the physical function's start,
    /// or `None` if no registered module contains it (or nothing resolved).
    pub fn resolve(&self, avma: u64) -> Option<Resolved> {
        let module = self
            .modules
            .iter()
            .find(|m| avma >= m.base_avma && avma < m.end_avma)?;
        // wholesym's `Relative` form on macOS is "offset from __TEXT base"
        // — exactly `avma - base_avma` for a normally-loaded mach-o image; for
        // ELF the relative-address base is 0, so this is the link-time vaddr.
        let rel_u64 = avma - module.base_avma;

        // Primary: wholesym, which carries DWARF inline frames and line info.
        if let Some(map) = module.map.as_ref() {
            if let Ok(rel) = u32::try_from(rel_u64) {
                // Use the async `lookup` (block_on'd through our runtime), not
                // `lookup_sync`. The sync variant returns the nearest preceding
                // symbol regardless of whether the address falls within its body
                // — fine for full symbol tables, but for stripped
                // dyld_shared_cache members it produces bogus matches like
                // "vsprintf +41" hundreds of bytes past vsprintf's end. The
                // async path validates containment first.
                if let Some(info) = self.rt.block_on(map.lookup(LookupAddress::Relative(rel))) {
                    return Some(frames_from_lookup(&info, rel));
                }
            }
        }

        // Fallback: `.dynsym` via PT_DYNAMIC for a section-header-stripped ELF,
        // where wholesym found no symbols. Names only — no source location.
        #[cfg(not(target_os = "windows"))]
        if let Some(dynsym) = module.dynsym.as_ref() {
            if let Some((name, offset)) = dynsym.resolve(rel_u64) {
                return Some(Resolved {
                    frames: vec![Frame { name: name.to_owned(), file: None, line: 0 }],
                    offset,
                });
            }
        }

        None
    }
}

/// Turn a wholesym lookup into the resolved inline chain. `info.frames` carries
/// the DWARF inline records — innermost inlinee first, the physical function
/// last. Emit every frame so an inlined callee is its own frame instead of
/// being folded into its caller; keeping only the last one made inlined hot
/// functions invisible. The physical function's name comes from the symtab
/// (`info.symbol.name`) when its DWARF frame has no function.
fn frames_from_lookup(info: &wholesym::AddressInfo, rel: u32) -> Resolved {
    let frames: Vec<Frame> = match info.frames.as_ref().filter(|f| !f.is_empty()) {
        Some(dwarf) => {
            let last = dwarf.len() - 1;
            dwarf
                .iter()
                .enumerate()
                .map(|(i, f)| {
                    let name = f.function.clone().unwrap_or_else(|| {
                        if i == last { info.symbol.name.clone() } else { String::new() }
                    });
                    let file = f
                        .file_path
                        .as_ref()
                        .map(|p| String::from_utf8_lossy(p.raw_path().as_bytes()).into_owned());
                    Frame { name, file, line: f.line_number.unwrap_or(0) }
                })
                .filter(|f| !f.name.is_empty())
                .collect()
        }
        None => Vec::new(),
    };
    // Symtab-only modules (no DWARF) and the all-anonymous-frame edge fall back
    // to the single symbol name with no source location.
    let frames = if frames.is_empty() {
        vec![Frame { name: info.symbol.name.clone(), file: None, line: 0 }]
    } else {
        frames
    };
    let offset = rel.saturating_sub(info.symbol.address) as u64;
    Resolved { frames, offset }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add(s: &mut Symbolizer, path: &str) -> ModuleLoad {
        s.add_module(0, 0x300000, Path::new(path), None, None)
    }

    // A missing path must report a non-empty reason with no symbols; the bridge
    // used to swallow this, leaving the user with no clue why a module didn't
    // symbolize.
    #[test]
    fn missing_path_yields_reason() {
        let mut s = Symbolizer::new().unwrap();
        let r = add(&mut s, "/no/such/binary.so");
        assert_eq!(r.symbol_count, 0);
        assert!(r.error.is_some(), "expected a load-failure reason");
    }

    // The host libc should load with a positive symbol count (skipped if
    // the well-known path isn't present, e.g. non-glibc hosts).
    #[test]
    fn host_libc_reports_symbol_count() {
        let path = "/usr/lib64/libc.so.6";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let mut s = Symbolizer::new().unwrap();
        let r = add(&mut s, path);
        assert!(r.error.is_none());
        assert!(r.symbol_count > 0, "expected a positive symbol count");
    }
}
