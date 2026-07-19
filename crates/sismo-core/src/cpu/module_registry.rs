// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! CAP-3(b): a registry of the module files sampled during a recording, so a
//! binary rebuilt or deleted mid-run still symbolizes.
//!
//! An open fd keeps a file's inode readable even after it is unlinked, so if we
//! hold one from the first time a module is sampled until the post-record
//! symbolize pass, we can read a since-deleted binary's bytes via
//! `/proc/self/fd/<n>` — no copy, no on-disk cache.
//!
//! Holding an fd per file does not come free, so which files we hold is a
//! policy ([`KeepPolicy`]). The default (`Auto`) holds fds only for files on
//! *unstable* paths — a fresh build under a home/tmp/work directory is the case
//! that actually gets rebuilt or removed mid-profile — and leaves distro-managed
//! system files (`/usr`, `/lib*`, `/bin`, `/sbin`) to be opened by path at the
//! end, since they rarely change under a running process.
//!
//! Identity is `(dev, inode)`, deduplicated globally: a shared library mapped by
//! a thousand processes is held once. That is the key that lets this scale to
//! system-wide profiling unchanged — only the source that feeds [`observe`] has
//! to grow, not the registry.

use std::collections::HashMap;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;

use crate::symbolize::proc_maps::synthetic_build_id;

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

/// FNV-1a of a path, the dedup key for a file we could not stat (already gone).
fn path_key(path: &str) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &b in path.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

struct Entry {
    // The build-id the trace carries for this module: the real GNU note when it
    // has one, else a synthetic magic+random id minted here and memoized so every
    // frame of the module groups under it and a rebuild (new inode) gets a fresh
    // one.
    build_id: Vec<u8>,
    // Held only when the policy decided this file was worth pinning; a None here
    // is a module we saw but chose to reopen by path at the end.
    fd: Option<File>,
}

/// The set of module files a recording sampled, one entry per `(dev, inode)`.
pub struct ModuleRegistry {
    policy: KeepPolicy,
    by_inode: HashMap<(u64, u64), Entry>,
    // splitmix64 state for minting synthetic ids: a bijection over the sequence,
    // so distinct draws never collide within a recording. Seeded per registry so
    // ids differ across runs without needing a system RNG.
    rng: u64,
}

impl ModuleRegistry {
    pub fn new(policy: KeepPolicy) -> ModuleRegistry {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        ModuleRegistry { policy, by_inode: HashMap::new(), rng: seed }
    }

    fn next_rand(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Note that `path` was sampled, carrying `real_id` (its real GNU build-id, or
    /// empty). Returns the build-id the trace should use: `real_id` when present,
    /// else a synthetic id minted once per `(dev, inode)`. Holds an fd per the
    /// policy so a since-deleted file still symbolizes. Idempotent per module —
    /// re-observing the same inode returns the same id, so map re-parses don't
    /// split a module across ids.
    pub fn observe(&mut self, path: &str, real_id: &[u8]) -> Vec<u8> {
        // Key by (dev, inode) when the file is on disk; fall back to a path key
        // when it is already gone (its real id then comes from CAP-2 in-band, and
        // no fd can be held anyway).
        let meta = std::fs::metadata(path).ok();
        let key = match &meta {
            Some(m) => (m.dev(), m.ino()),
            None => (0, path_key(path)),
        };
        if let Some(e) = self.by_inode.get(&key) {
            return e.build_id.clone();
        }
        let build_id = if real_id.is_empty() {
            let r = self.next_rand();
            synthetic_build_id(r).to_vec()
        } else {
            real_id.to_vec()
        };
        let hold = meta.is_some()
            && match self.policy {
                KeepPolicy::All => true,
                KeepPolicy::Auto => is_unstable(path),
                KeepPolicy::None => false,
            };
        let fd = if hold { File::open(path).ok() } else { None };
        self.by_inode.insert(key, Entry { build_id: build_id.clone(), fd });
        build_id
    }

    /// Map each held module's build-id to a `/proc/self/fd/<n>` path a symbolizer
    /// can open. The returned paths are valid only while `self` is alive, since it
    /// owns the backing fds — keep the registry until symbolization finishes.
    pub fn held_fd_paths(&self) -> HashMap<Vec<u8>, String> {
        self.by_inode
            .values()
            .filter(|e| !e.build_id.is_empty())
            .filter_map(|e| {
                e.fd
                    .as_ref()
                    .map(|f| (e.build_id.clone(), format!("/proc/self/fd/{}", f.as_raw_fd())))
            })
            .collect()
    }

    /// Number of fds currently held (for stats/logging).
    pub fn held_count(&self) -> usize {
        self.by_inode.values().filter(|e| e.fd.is_some()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_holds_unstable_and_skips_system_paths() {
        assert!(is_unstable("/home/user/build/a.out"));
        assert!(is_unstable("/tmp/prog"));
        assert!(!is_unstable("/usr/lib/libc.so.6"));
        assert!(!is_unstable("/bin/bash"));
    }

    #[test]
    fn holds_a_real_file_and_survives_deletion() {
        let dir = std::env::temp_dir().join(format!("sismo-reg-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("prog"); // not under a stable prefix → auto holds it
        std::fs::write(&p, b"\x7fELF...").unwrap();
        let real = [1u8, 2, 3, 4]; // pretend a real GNU note

        let mut reg = ModuleRegistry::new(KeepPolicy::Auto);
        let id = reg.observe(p.to_str().unwrap(), &real);
        assert_eq!(id, real); // a real id passes through unchanged
        assert_eq!(reg.held_count(), 1);
        // Re-observing the same inode returns the same id and adds no second fd.
        assert_eq!(reg.observe(p.to_str().unwrap(), &real), real);
        assert_eq!(reg.held_count(), 1);

        std::fs::remove_file(&p).unwrap(); // deleted, but the held fd keeps it readable
        let paths = reg.held_fd_paths();
        let fd_path = paths.get(&real[..].to_vec()).expect("held by build-id");
        assert_eq!(std::fs::read(fd_path).unwrap(), b"\x7fELF...");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mints_a_synthetic_id_when_the_note_is_missing() {
        use crate::symbolize::proc_maps::is_synthetic;
        let dir = std::env::temp_dir().join(format!("sismo-reg-syn-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let (a, b) = (dir.join("a"), dir.join("b"));
        std::fs::write(&a, b"aaaa").unwrap();
        std::fs::write(&b, b"bbbb").unwrap();

        let mut reg = ModuleRegistry::new(KeepPolicy::None);
        let ida = reg.observe(a.to_str().unwrap(), &[]); // no real note
        let idb = reg.observe(b.to_str().unwrap(), &[]);
        assert!(is_synthetic(&ida) && is_synthetic(&idb));
        assert_ne!(ida, idb); // distinct files → distinct ids (no path collision)
        assert_eq!(reg.observe(a.to_str().unwrap(), &[]), ida); // stable per inode
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn none_policy_ids_but_holds_nothing() {
        let mut reg = ModuleRegistry::new(KeepPolicy::None);
        let id = reg.observe("/tmp/whatever-nonexistent", &[9, 9]);
        assert_eq!(id, vec![9, 9]); // still assigns the id
        assert_eq!(reg.held_count(), 0); // but holds no fd
        assert!(reg.held_fd_paths().is_empty());
    }
}
