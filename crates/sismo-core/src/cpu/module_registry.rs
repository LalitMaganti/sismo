// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! CAP-3(b): the registry of module files a recording sampled, so a binary
//! rebuilt or deleted mid-run still symbolizes.
//!
//! Two threads share it. A dedicated **capture thread** drains the `module_hints`
//! ringbuf and, promptly on first sight of a module — before the main sample
//! queue (which backlogs under load) has even reached that sample — parses its
//! build-id from the in-band page and pins an fd to its file per policy. The
//! **main drain** looks the build-id up when it interns the module's mapping.
//!
//! Whichever thread reaches a module first mints its trace build-id and both then
//! agree; only the capture thread pins fds. Because the capture thread is prompt
//! and the main drain backlogs, the capture thread wins under load and supplies
//! the in-band (replace-immune) id; under light load the main drain reaches the
//! module early — before any mid-run change — so its /proc read is correct too.
//!
//! Identity: the per-process `(pid, base)` the two threads share names a module's
//! mapping; fds are additionally deduped by `(dev, inode)` so one library mapped
//! by many processes is held once. That `(dev, inode)` dedup is what lets this
//! scale to system-wide unchanged — only the hint source grows, not the registry.

use std::collections::HashMap;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;

use crate::symbolize::proc_maps::{build_id_from_image_prefix, synthetic_build_id};

/// Which sampled module files to hold an fd open for, from `--keep-module-files`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeepPolicy {
    /// Hold nothing; open every module by path at symbolize time. A binary
    /// deleted or replaced before then does not resolve.
    None,
    /// Hold fds only for modules on unstable paths (the default).
    Auto,
    /// Hold an fd for every sampled module (bounded by RLIMIT_NOFILE).
    All,
}

impl KeepPolicy {
    /// Parse the `--keep-module-files` value; `None` on an unknown string.
    pub fn parse(s: &str) -> Option<KeepPolicy> {
        match s {
            "none" => Some(KeepPolicy::None),
            "auto" => Some(KeepPolicy::Auto),
            "all" => Some(KeepPolicy::All),
            _ => None,
        }
    }
}

/// Distro-managed prefixes whose files are replaced atomically by the package
/// manager and effectively never rewritten under a running process. `Auto`
/// treats everything else as unstable and worth holding open.
const STABLE_PREFIXES: &[&str] = &["/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/opt/"];

fn is_unstable(path: &str) -> bool {
    !STABLE_PREFIXES.iter().any(|p| path.starts_with(p))
}

struct Entry {
    // The build-id the trace carries for this module: a real GNU note when it has
    // one, else a synthetic magic+random id minted on first sight.
    build_id: Vec<u8>,
    // The (dev, inode) whose fd (in `fds`) backs this module, if one was held.
    inode: Option<(u64, u64)>,
}

/// Shared between the capture thread (writes) and the main drain (reads).
pub struct ModuleRegistry {
    policy: KeepPolicy,
    by_key: HashMap<(u32, u64), Entry>,        // (pid, base) -> module identity
    fds: HashMap<(u64, u64), File>,            // (dev, inode) -> held fd, deduped
    rng: u64,                                  // splitmix64 state for synthetic ids
}

impl ModuleRegistry {
    pub fn new(policy: KeepPolicy) -> ModuleRegistry {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        ModuleRegistry { policy, by_key: HashMap::new(), fds: HashMap::new(), rng: seed }
    }

    fn next_rand(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// The build-id to intern for the module at `(pid, base)`. Called by the main
    /// drain. Mints one from `host_hint` (the real GNU note it read, or empty →
    /// synthetic) only if this module has not been seen yet; otherwise returns the
    /// id the capture thread (or an earlier call) already settled on, so the two
    /// threads never disagree.
    pub fn id_for(&mut self, pid: u32, base: u64, host_hint: &[u8]) -> Vec<u8> {
        if let Some(e) = self.by_key.get(&(pid, base)) {
            return e.build_id.clone();
        }
        let build_id = self.mint(host_hint);
        self.by_key.insert((pid, base), Entry { build_id: build_id.clone(), inode: None });
        build_id
    }

    /// Record the module at `(pid, base)` from a `module_hints` record: settle its
    /// build-id from the in-band `page` (real GNU note, else synthetic) if unseen,
    /// and pin an fd to `path` per policy so a later deletion does not lose it.
    /// Called by the capture thread.
    pub fn record_module(&mut self, pid: u32, base: u64, page: &[u8], path: &str) {
        if !self.by_key.contains_key(&(pid, base)) {
            let hint = build_id_from_image_prefix(page).unwrap_or_default();
            let build_id = self.mint(&hint);
            self.by_key.insert((pid, base), Entry { build_id, inode: None });
        }
        // Pin the fd (deduped by inode) per policy, and point this module at it.
        let hold = match self.policy {
            KeepPolicy::All => true,
            KeepPolicy::Auto => is_unstable(path),
            KeepPolicy::None => false,
        };
        if !hold {
            return;
        }
        let Ok(meta) = std::fs::metadata(path) else {
            return; // already gone; the in-band build-id is all we get
        };
        let inode = (meta.dev(), meta.ino());
        if !self.fds.contains_key(&inode) {
            if let Ok(f) = File::open(path) {
                self.fds.insert(inode, f);
            } else {
                return;
            }
        }
        if let Some(e) = self.by_key.get_mut(&(pid, base)) {
            e.inode = Some(inode);
        }
    }

    fn mint(&mut self, hint: &[u8]) -> Vec<u8> {
        if hint.is_empty() {
            let r = self.next_rand();
            synthetic_build_id(r).to_vec()
        } else {
            hint.to_vec()
        }
    }

    /// Map each held module's build-id to a `/proc/self/fd/<n>` path a symbolizer
    /// can open. Valid only while `self` is alive (it owns the fds).
    pub fn held_fd_paths(&self) -> HashMap<Vec<u8>, String> {
        let mut out = HashMap::new();
        for e in self.by_key.values() {
            if e.build_id.is_empty() {
                continue;
            }
            if let Some(inode) = e.inode {
                if let Some(f) = self.fds.get(&inode) {
                    out.insert(e.build_id.clone(), format!("/proc/self/fd/{}", f.as_raw_fd()));
                }
            }
        }
        out
    }

    /// Number of distinct files whose fd is held (for stats/logging).
    pub fn held_count(&self) -> usize {
        self.fds.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbolize::proc_maps::is_synthetic;

    #[test]
    fn auto_holds_unstable_and_skips_system_paths() {
        assert!(is_unstable("/home/user/build/a.out"));
        assert!(is_unstable("/tmp/prog"));
        assert!(!is_unstable("/usr/lib/libc.so.6"));
        assert!(!is_unstable("/bin/bash"));
    }

    #[test]
    fn id_for_mints_once_and_agrees_across_calls() {
        let mut reg = ModuleRegistry::new(KeepPolicy::None);
        // A real note passes through and is stable.
        let real = [0xde, 0xad, 0xbe, 0xef];
        assert_eq!(reg.id_for(7, 0x400000, &real), real);
        assert_eq!(reg.id_for(7, 0x400000, &[]), real); // second call agrees, ignores new hint
        // A note-less module gets a synthetic id, distinct per (pid, base).
        let a = reg.id_for(7, 0x500000, &[]);
        let b = reg.id_for(8, 0x500000, &[]);
        assert!(is_synthetic(&a) && is_synthetic(&b));
        assert_ne!(a, b);
        assert_eq!(reg.id_for(7, 0x500000, &[]), a); // stable
    }

    #[test]
    fn record_module_pins_fd_and_survives_deletion() {
        let dir = std::env::temp_dir().join(format!("sismo-reg2-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("prog"); // unstable path → auto holds it
        std::fs::write(&p, b"\x7fELF-bytes").unwrap();

        let mut reg = ModuleRegistry::new(KeepPolicy::Auto);
        // No GNU note in these bytes → synthetic id, and a held fd.
        reg.record_module(42, 0x400000, b"not-an-elf", p.to_str().unwrap());
        assert_eq!(reg.held_count(), 1);
        let id = reg.id_for(42, 0x400000, &[]); // main drain agrees with the minted id
        assert!(is_synthetic(&id));

        std::fs::remove_file(&p).unwrap(); // deleted; held fd keeps the bytes readable
        let paths = reg.held_fd_paths();
        let fd_path = paths.get(&id).expect("held by build-id");
        assert_eq!(std::fs::read(fd_path).unwrap(), b"\x7fELF-bytes");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn none_policy_ids_but_holds_no_fd() {
        let dir = std::env::temp_dir().join(format!("sismo-reg2-none-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("prog");
        std::fs::write(&p, b"x").unwrap();
        let mut reg = ModuleRegistry::new(KeepPolicy::None);
        reg.record_module(1, 0x1000, b"x", p.to_str().unwrap());
        assert_eq!(reg.held_count(), 0);
        assert!(is_synthetic(&reg.id_for(1, 0x1000, &[])));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
