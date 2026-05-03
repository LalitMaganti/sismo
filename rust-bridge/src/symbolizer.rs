// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! wholesym FFI surface — resolves AVMA → demangled function name +
//! offset (and inline frame info where debug info is available).
//!
//! Lifecycle: `sismo_symbolizer_create()` returns an opaque handle that
//! bundles a current-thread tokio runtime and a wholesym `SymbolManager`.
//! Callers register modules by `(base_avma, end_avma, path)` then resolve
//! AVMAs into a caller-provided UTF-8 buffer.
//!
//! All symbol-map loads are synchronous from the caller's perspective —
//! the runtime `block_on`'s wholesym's async API internally. This is the
//! right shape for a sampler/post-processor that runs symbolication on a
//! single thread; for higher concurrency we'd switch to a multi-thread
//! runtime, but that's overkill for v0.

use std::os::raw::c_int;
use std::path::PathBuf;
use std::slice;

use wholesym::{
    debugid::DebugId, LookupAddress, MultiArchDisambiguator, SymbolManager, SymbolManagerConfig,
    SymbolMap,
};

pub struct Symbolizer {
    rt: tokio::runtime::Runtime,
    manager: SymbolManager,
    modules: Vec<SymModule>,
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

#[unsafe(no_mangle)]
pub extern "C" fn sismo_symbolizer_create() -> *mut Symbolizer {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(_) => return std::ptr::null_mut(),
    };
    let manager = SymbolManager::with_config(SymbolManagerConfig::default());
    Box::into_raw(Box::new(Symbolizer {
        rt,
        manager,
        modules: Vec::new(),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_symbolizer_destroy(s: *mut Symbolizer) {
    if s.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(s) });
}

/// Register a module by path so AVMAs in [base_avma, end_avma) resolve
/// to symbols within it. Returns:
///    0  success (path opened, symbol map loaded)
///    1  partial — avma range registered, but symbol load failed (e.g.
///       wholesym couldn't find the binary on disk). resolve() returns
///       0 for AVMAs in this range.
///   -1  bad arguments.
/// `uuid_bytes` (optional, 16 bytes) is the preferred disambiguator.
/// `arch_utf8` / `arch_len` is a fallback when UUID isn't available.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_symbolizer_add_module(
    s: *mut Symbolizer,
    base_avma: u64,
    end_avma: u64,
    path_utf8: *const u8,
    path_len: usize,
    uuid_bytes: *const u8,
    arch_utf8: *const u8,
    arch_len: usize,
) -> c_int {
    if s.is_null() || path_utf8.is_null() || path_len == 0 || end_avma <= base_avma {
        return -1;
    }
    let symbolizer = unsafe { &mut *s };
    let path_bytes = unsafe { slice::from_raw_parts(path_utf8, path_len) };
    let path_str = match std::str::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let path = PathBuf::from(path_str);

    // Prefer UUID-based disambiguator. samply-symbols' fat-archive
    // `arch` field reports both arm64 and arm64e entries as "arm64", so
    // an Arch("arm64e") disambiguator never matches arm64e slices. UUID
    // matching is exact and bypasses the issue entirely.
    let disambiguator: Option<MultiArchDisambiguator> = if !uuid_bytes.is_null() {
        let uuid_arr: [u8; 16] = unsafe { *(uuid_bytes as *const [u8; 16]) };
        if uuid_arr != [0u8; 16] {
            // debugid takes the `uuid::Uuid` type (not raw bytes), and
            // doesn't re-export it publicly — pull `uuid` in directly.
            let uuid = uuid::Uuid::from_bytes(uuid_arr);
            Some(MultiArchDisambiguator::DebugId(DebugId::from_uuid(uuid)))
        } else {
            None
        }
    } else {
        None
    }
    .or_else(|| {
        if arch_utf8.is_null() || arch_len == 0 {
            None
        } else {
            let arch_bytes = unsafe { slice::from_raw_parts(arch_utf8, arch_len) };
            std::str::from_utf8(arch_bytes)
                .ok()
                .map(|a| MultiArchDisambiguator::Arch(a.to_string()))
        }
    });
    let load_result = symbolizer.rt.block_on(
        symbolizer
            .manager
            .load_symbol_map_for_binary_at_path(&path, disambiguator),
    );
    let (map, rc) = match load_result {
        Ok(m) => (Some(m), 0),
        // Failure is common on macOS for dyld_shared_cache-only system
        // dylibs (libsystem_c, libdispatch, …) and isn't actionable —
        // samply hits the same wall. Don't log; just register the avma
        // range and let resolve() return 0 for AVMAs in this module.
        Err(_) => (None, 1),
    };
    symbolizer.modules.push(SymModule {
        base_avma,
        end_avma,
        map,
    });
    rc
}

/// Resolve `avma` to `<demangled_name> +<byte_offset>`, written as UTF-8
/// into `out_utf8[..cap]`. Returns the number of bytes written (truncated
/// to `cap` without a NUL terminator), or 0 if no match is found in any
/// registered module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_symbolizer_resolve(
    s: *mut Symbolizer,
    avma: u64,
    out_utf8: *mut u8,
    cap: usize,
) -> usize {
    if s.is_null() || out_utf8.is_null() || cap == 0 {
        return 0;
    }
    let symbolizer = unsafe { &*s };
    let module = match symbolizer
        .modules
        .iter()
        .find(|m| avma >= m.base_avma && avma < m.end_avma)
    {
        Some(m) => m,
        None => return 0,
    };
    let map = match &module.map {
        Some(m) => m,
        None => return 0,
    };
    // wholesym's `Relative` form on macOS is "offset from __TEXT base"
    // — exactly `avma - base_avma` for a normally-loaded mach-o image.
    let rel: u32 = match (avma - module.base_avma).try_into() {
        Ok(v) => v,
        Err(_) => return 0,
    };
    // Use the async `lookup` (block_on'd through our runtime), not
    // `lookup_sync`. The sync variant returns the nearest preceding
    // symbol regardless of whether the address actually falls within
    // its body — fine when symbol tables are full, but for stripped
    // dyld_shared_cache members it produces bogus matches like
    // "vsprintf +41" for an address that's hundreds of bytes past
    // vsprintf's actual end. The async path validates containment via
    // debug info / inline records before returning Some.
    let info = match symbolizer
        .rt
        .block_on(map.lookup(LookupAddress::Relative(rel)))
    {
        Some(i) => i,
        None => return 0,
    };
    let offset = rel.saturating_sub(info.symbol.address);
    let formatted = format!("{} +{}", info.symbol.name, offset);
    let bytes = formatted.as_bytes();
    let n = bytes.len().min(cap);
    let out = unsafe { slice::from_raw_parts_mut(out_utf8, n) };
    out.copy_from_slice(&bytes[..n]);
    n
}
