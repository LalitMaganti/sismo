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
    /// Names-only fallback sources behind wholesym, in resolution order
    /// (`fallback::load_fallbacks` is the one place the per-platform set is
    /// chosen).
    fallbacks: Vec<Box<dyn crate::fallback::SymbolSource>>,
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

        // When wholesym found nothing, a fallback source may still be able to
        // name this module's functions. Report the first non-empty fallback's
        // count so the module status is honest rather than the misleading
        // "0 symbols / binary changed" it produced before.
        let fallbacks = crate::fallback::load_fallbacks(path, uuid, result.symbol_count);
        if result.symbol_count == 0 {
            if let Some(n) = fallbacks.iter().map(|f| f.len()).find(|&n| n > 0) {
                result = ModuleLoad { symbol_count: n as u64, error: None };
            }
        }

        self.modules.push(SymModule { base_avma, end_avma, map, fallbacks });
        result
    }

    /// Register `[base_avma, end_avma)` with no symbol source, so addresses inside
    /// resolve to `None` rather than matching a neighboring module. Used when the
    /// on-disk file was replaced since recording and must not be trusted for
    /// symbols.
    pub fn add_range_no_symbols(&mut self, base_avma: u64, end_avma: u64) {
        self.modules.push(SymModule { base_avma, end_avma, map: None, fallbacks: Vec::new() });
    }

    /// Register the kernel over `[base_avma, end_avma)`: a `vmlinux` debug image
    /// as the wholesym primary (DWARF — line info + inline frames) with the
    /// `/proc/kallsyms` names-only source as the fallback, exactly the
    /// primary+fallback shape user modules use. Either may be absent. Frames
    /// carry `[kernel.kallsyms]`-relative rel_pcs, which resolve against a
    /// vmlinux ELF too — the KASLR slide cancels in `runtime_pc - kbase`.
    /// Returns the symbol count (vmlinux's, or the fallback's when vmlinux gave
    /// nothing) and any vmlinux load error.
    pub fn add_kernel_module(
        &mut self,
        base_avma: u64,
        end_avma: u64,
        vmlinux: Option<&Path>,
        uuid: Option<[u8; 16]>,
        kallsyms: Option<Box<dyn crate::fallback::SymbolSource>>,
    ) -> ModuleLoad {
        let (map, mut result) = match vmlinux {
            Some(path) => {
                let disambiguator = uuid.filter(|u| *u != [0u8; 16]).map(|u| {
                    MultiArchDisambiguator::DebugId(DebugId::from_uuid(uuid::Uuid::from_bytes(u)))
                });
                match self
                    .rt
                    .block_on(self.manager.load_symbol_map_for_binary_at_path(path, disambiguator))
                {
                    Ok(m) => {
                        let symbol_count = m.symbol_count() as u64;
                        (Some(m), ModuleLoad { symbol_count, error: None })
                    }
                    Err(e) => (None, ModuleLoad { symbol_count: 0, error: Some(format!("{e}")) }),
                }
            }
            None => (None, ModuleLoad { symbol_count: 0, error: None }),
        };
        let fallbacks: Vec<Box<dyn crate::fallback::SymbolSource>> = kallsyms.into_iter().collect();
        // When vmlinux found nothing, report the kallsyms fallback's count so
        // the module status is honest.
        if result.symbol_count == 0 {
            if let Some(n) = fallbacks.iter().map(|f| f.len()).find(|&n| n > 0) {
                result = ModuleLoad { symbol_count: n as u64, error: None };
            }
        }
        self.modules.push(SymModule { base_avma, end_avma, map, fallbacks });
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
        // Use the async `lookup` (block_on'd through our runtime), not
        // `lookup_sync`. The sync variant returns the nearest preceding symbol
        // regardless of whether the address falls within its body — fine for
        // full symbol tables, but for stripped dyld_shared_cache members it
        // produces bogus matches like "vsprintf +41" hundreds of bytes past
        // vsprintf's end. The async path validates containment first.
        //
        // A wholesym result whose outer name is a synthesized placeholder
        // (fun_<hex> / EntryPoint) is not a real name — hold it as a last
        // resort and prefer a real name from `.gopclntab`/`.dynsym` if one
        // exists, so a stripped Go binary reports `main.foo`, not `fun_1234`.
        let mut placeholder: Option<Resolved> = None;
        if let Some(map) = module.map.as_ref() {
            if let Ok(rel) = u32::try_from(rel_u64) {
                if let Some(info) = self.rt.block_on(map.lookup(LookupAddress::Relative(rel))) {
                    let resolved = frames_from_lookup(&info, rel);
                    if is_synthetic_name(&resolved.outer().name) {
                        placeholder = Some(resolved);
                    } else {
                        return Some(resolved);
                    }
                }
            }
        }

        // The names-only fallback chain (gopclntab / dynsym / dyld cache — see
        // fallback::load_fallbacks), in quality order.
        for source in &module.fallbacks {
            if let Some((name, offset)) = source.resolve(rel_u64) {
                return Some(Resolved {
                    frames: vec![Frame { name: name.to_owned(), file: None, line: 0 }],
                    offset,
                });
            }
        }

        // Nothing better than wholesym's placeholder (if any) — a distinct
        // `fun_<hex>` per function still beats a bare hex address.
        placeholder
    }
}

/// Whether `name` is one of wholesym's synthesized placeholder names — `fun_<hex>`
/// (a function start found from unwind info with no name) or `EntryPoint` (the
/// ELF entry). These are not real symbol names; preferring a real name from
/// another source over one of these is the point of the `.gopclntab`/`.dynsym`
/// fallbacks.
pub fn is_synthetic_name(name: &str) -> bool {
    if name == "EntryPoint" {
        return true;
    }
    match name.strip_prefix("fun_") {
        Some(rest) => {
            !rest.is_empty()
                && rest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        None => false,
    }
}

/// Turn a wholesym lookup into the resolved inline chain. `info.frames` carries
/// the DWARF inline records — innermost inlinee first, the physical function
/// last. Emit every frame so an inlined callee is its own frame instead of
/// being folded into its caller; keeping only the last one made inlined hot
/// functions invisible. The physical function's name comes from the symtab
/// (`info.symbol.name`) when its DWARF frame has no function.
/// Strip GCC/LLVM clone and hot/cold-split suffixes so a sample in a specialized
/// clone or a function's cold half attributes to the base function instead of
/// showing as a separate symbol that splits its cost. gcc emits `foo.isra.0`,
/// `foo.constprop.1`, `foo.part.0` at plain `-O2`; hot/cold splitting emits
/// `foo.cold`; ThinLTO/LTO emit `foo.llvm.<hash>` / `foo.lto_priv.0`. Suffixes
/// chain (`foo.constprop.0.isra.1`), so cut at the first clone-tag segment. Only
/// exact `.`-delimited tag segments are stripped, so a real name like
/// `foo.israble` is untouched. These suffixes live on the symtab symbol, not the
/// DWARF `DW_AT_name`, but stripping is a no-op on an already-clean name.
fn strip_clone_suffix(name: &str) -> &str {
    const TAGS: [&str; 7] =
        ["isra", "constprop", "part", "cold", "llvm", "lto_priv", "clone"];
    let mut idx = 0;
    while let Some(dot) = name[idx..].find('.') {
        let seg_start = idx + dot + 1;
        let seg_end = name[seg_start..]
            .find('.')
            .map_or(name.len(), |p| seg_start + p);
        if TAGS.contains(&&name[seg_start..seg_end]) {
            return &name[..idx + dot];
        }
        idx = seg_start;
    }
    name
}

fn frames_from_lookup(info: &wholesym::AddressInfo, rel: u32) -> Resolved {
    let frames: Vec<Frame> = match info.frames.as_ref().filter(|f| !f.is_empty()) {
        Some(dwarf) => {
            let last = dwarf.len() - 1;
            dwarf
                .iter()
                .enumerate()
                .map(|(i, f)| {
                    let raw = f.function.clone().unwrap_or_else(|| {
                        if i == last { info.symbol.name.clone() } else { String::new() }
                    });
                    let name = strip_clone_suffix(&raw).to_string();
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
        vec![Frame {
            name: strip_clone_suffix(&info.symbol.name).to_string(),
            file: None,
            line: 0,
        }]
    } else {
        frames
    };
    let offset = rel.saturating_sub(info.symbol.address) as u64;
    Resolved { frames, offset }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_clone_suffix_merges_clones_and_splits() {
        // GCC IPA clones and hot/cold split, including chained suffixes.
        assert_eq!(strip_clone_suffix("sismo_wl_leaf.isra.0"), "sismo_wl_leaf");
        assert_eq!(strip_clone_suffix("foo.constprop.1"), "foo");
        assert_eq!(strip_clone_suffix("foo.part.0"), "foo");
        assert_eq!(strip_clone_suffix("foo.cold"), "foo");
        assert_eq!(strip_clone_suffix("foo.constprop.0.isra.1"), "foo");
        // LLVM ThinLTO / LTO promotion.
        assert_eq!(strip_clone_suffix("foo.llvm.12345678"), "foo");
        assert_eq!(strip_clone_suffix("foo.lto_priv.0"), "foo");
        // Plain names and names that merely contain a tag as a substring of a
        // larger segment are left untouched.
        assert_eq!(strip_clone_suffix("sismo_wl_leaf"), "sismo_wl_leaf");
        assert_eq!(strip_clone_suffix("israble"), "israble");
        assert_eq!(strip_clone_suffix("foo.israble"), "foo.israble");
        assert_eq!(strip_clone_suffix("coldstart"), "coldstart");
    }

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
