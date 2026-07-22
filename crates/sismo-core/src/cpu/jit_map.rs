// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! JIT-1: the target runtime's perf-map (`/tmp/perf-<pid>.map`), the
//! de-facto JIT symbol interchange every runtime speaks (V8's
//! `--perf-basic-prof`, HotSpot's `Compiler.perfmap`, CPython's perf
//! trampoline). OS-neutral: the same file and format exist wherever the
//! producer runs; only the temp-dir convention will differ on Windows.
//!
//! The runtime appends to the map as it compiles (V8 writes builtins at
//! startup, then each JS method as it tiers up), so [`JitMap::name`] reloads
//! whenever the file has grown — a load-once would cache a map taken before
//! the hot methods existed.
//!
//! Extracted from linux_bpf_capture's jit_name/load_perf_map for the macOS
//! kperf emitter; the Linux capture still carries its own copy until it can
//! be migrated (and verified) on a Linux machine.

/// Lazily-loaded, size-invalidated view of one process's perf-map.
pub struct JitMap {
    pid: u32,
    syms: Option<Vec<(u64, u64, String)>>, // (start, size, name), start-sorted
    file_size: u64,
}

impl Default for JitMap {
    fn default() -> Self {
        Self::new()
    }
}

impl JitMap {
    pub fn new() -> Self {
        JitMap { pid: 0, syms: None, file_size: 0 }
    }

    /// The runtime method name covering `pc` in `pid`'s perf-map, or None.
    pub fn name(&mut self, pid: u32, pc: u64) -> Option<String> {
        let size = std::fs::metadata(map_path(pid)).map(|m| m.len()).unwrap_or(0);
        if self.syms.is_none() || pid != self.pid || size != self.file_size {
            self.syms = Some(load_perf_map(pid));
            self.pid = pid;
            self.file_size = size;
        }
        let syms = self.syms.as_ref()?;
        // The last entry whose start is <= pc, if that entry still covers pc.
        let i = syms.partition_point(|&(start, _, _)| start <= pc);
        syms.get(i.checked_sub(1)?)
            .filter(|(start, size, _)| pc < start.wrapping_add(*size))
            .map(|(_, _, name)| name.clone())
    }
}

fn map_path(pid: u32) -> String {
    format!("/tmp/perf-{pid}.map")
}

fn load_perf_map(pid: u32) -> Vec<(u64, u64, String)> {
    let Ok(text) = std::fs::read_to_string(map_path(pid)) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let mut it = line.splitn(3, ' ');
        let (Some(a), Some(sz), Some(name)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        if let (Ok(start), Ok(size)) = (u64::from_str_radix(a, 16), u64::from_str_radix(sz, 16)) {
            out.push((start, size, name.to_string()));
        }
    }
    out.sort_by_key(|&(start, _, _)| start);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_resolves_and_reloads_on_growth() {
        let pid = std::process::id();
        let path = map_path(pid);
        std::fs::write(&path, "1000 20 hot_a\n2000 10 hot_b\n").unwrap();
        let mut m = JitMap::new();
        assert_eq!(m.name(pid, 0x1004).as_deref(), Some("hot_a"));
        assert_eq!(m.name(pid, 0x1020), None); // past hot_a's 0x20 bytes
        assert_eq!(m.name(pid, 0x2008).as_deref(), Some("hot_b"));
        // The runtime appends; the next lookup must see the new entry.
        std::fs::write(&path, "1000 20 hot_a\n2000 10 hot_b\n3000 8 hot_c\n").unwrap();
        assert_eq!(m.name(pid, 0x3004).as_deref(), Some("hot_c"));
        std::fs::remove_file(&path).ok();
    }
}
