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

/// A resolved address: the demangled `<name> +<offset>`, plus source location
/// when debug info is available (`line` 0 = unknown).
pub struct Resolved {
    pub name: String,
    pub file: Option<String>,
    pub line: u32,
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
        let (map, result) = match load {
            Ok(m) => {
                let symbol_count = m.symbol_count() as u64;
                (Some(m), ModuleLoad { symbol_count, error: None })
            }
            Err(e) => (None, ModuleLoad { symbol_count: 0, error: Some(format!("{e}")) }),
        };
        self.modules.push(SymModule { base_avma, end_avma, map });
        result
    }

    /// Resolve `avma` to `<demangled_name> +<byte_offset>` plus source location,
    /// or `None` if no registered module contains it (or its map didn't load).
    pub fn resolve(&self, avma: u64) -> Option<Resolved> {
        let module = self
            .modules
            .iter()
            .find(|m| avma >= m.base_avma && avma < m.end_avma)?;
        let map = module.map.as_ref()?;
        // wholesym's `Relative` form on macOS is "offset from __TEXT base"
        // — exactly `avma - base_avma` for a normally-loaded mach-o image.
        let rel: u32 = (avma - module.base_avma).try_into().ok()?;
        // Use the async `lookup` (block_on'd through our runtime), not
        // `lookup_sync`. The sync variant returns the nearest preceding symbol
        // regardless of whether the address falls within its body — fine for
        // full symbol tables, but for stripped dyld_shared_cache members it
        // produces bogus matches like "vsprintf +41" hundreds of bytes past
        // vsprintf's end. The async path validates containment first.
        let info = self.rt.block_on(map.lookup(LookupAddress::Relative(rel)))?;

        // Source line info lives in `info.frames` (DWARF / inline records), not
        // `info.symbol`. The vec runs innermost inlinee first, so the last entry
        // is the outermost real function — the one `info.symbol.name` reports.
        let (mut file, mut line) = (None, 0u32);
        if let Some(frame) = info.frames.as_ref().and_then(|f| f.last()) {
            if let Some(l) = frame.line_number {
                line = l;
            }
            if let Some(path) = frame.file_path.as_ref() {
                file = Some(String::from_utf8_lossy(path.raw_path().as_bytes()).into_owned());
            }
        }

        let offset = rel.saturating_sub(info.symbol.address);
        Some(Resolved {
            name: format!("{} +{}", info.symbol.name, offset),
            file,
            line,
        })
    }
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
