// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! CAP-3(b): the registry of module files a recording sampled, so a binary
//! rebuilt or deleted mid-run still symbolizes.
//!
//! The registry is platform-neutral: it settles each sampled module's trace
//! build-id exactly once (the real identity when the capture read one, else a
//! synthetic magic+random id), and pins an fd to the module's file per the
//! `--keep-module-files` policy so a since-deleted binary's bytes stay
//! readable until the post-record symbolize pass. How a capture *names* a
//! module is the capture's business, expressed as a [`ModuleKey`]:
//!
//! - The Linux bpf capture keys by mapping (`pid`, `base`), because identity
//!   arrives from two threads that only share those coordinates: a dedicated
//!   capture thread drains the `module_hints` ringbuf and registers each
//!   module promptly (in-band build-id, fd pinned), while the main drain —
//!   which backlogs under load — looks the id up when it interns the mapping.
//!   Whichever thread reaches a module first mints the id and both then agree.
//! - The macOS kperf snapshotter keys by file ([`ModuleKey::for_file`]),
//!   registering each dyld image with the LC_UUID it read from the task.
//!
//! Held fds are deduped by `(dev, inode)` across keys, so one library mapped
//! by a thousand processes is held once — the property that lets this scale to
//! system-wide profiling unchanged. An fd keeps its inode readable after an
//! unlink; the symbolizer opens held fds via self-fd paths (see
//! [`ModuleRegistry::held_fd_paths`]) — no copy, no on-disk cache.

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

/// Distro/installer-managed prefixes whose files are replaced atomically and
/// effectively never rewritten under a running process. `Auto` treats
/// everything else as unstable and worth holding open. The macOS list adds the
/// SIP-protected system trees (whose dylibs mostly live in the dyld shared
/// cache and have no on-disk file to hold anyway) and application bundles.
#[cfg(not(target_os = "macos"))]
const STABLE_PREFIXES: &[&str] = &["/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/opt/"];
#[cfg(target_os = "macos")]
const STABLE_PREFIXES: &[&str] = &[
    "/usr/", "/bin/", "/sbin/", "/opt/", "/System/", "/Library/", "/Applications/",
];

fn is_unstable(path: &str) -> bool {
    !STABLE_PREFIXES.iter().any(|p| path.starts_with(p))
}

/// FNV-1a of a path, the key fallback for a file we could not stat.
fn path_hash(path: &str) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &b in path.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// How a capture names a module. Identity settling is memoized per key, so a
/// capture must use the same key every time it reaches the same module.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ModuleKey {
    /// A per-process mapping, for captures whose events carry `(pid, base)`.
    Mapping { pid: u32, base: u64 },
    /// A file identity, for captures that enumerate images by path.
    File { dev: u64, ino: u64 },
}

impl ModuleKey {
    /// Key a module by its file: `(dev, inode)` when the file is on disk, else
    /// a hash of the path (the file is already gone — no fd can be held for
    /// it, and a re-observation of the same path should still dedupe).
    pub fn for_file(path: &str) -> ModuleKey {
        match std::fs::metadata(path) {
            Ok(m) => ModuleKey::File { dev: m.dev(), ino: m.ino() },
            Err(_) => ModuleKey::File { dev: 0, ino: path_hash(path) },
        }
    }
}

struct Entry {
    // The build-id the trace carries for this module: the real identity when
    // the capture read one, else a synthetic magic+random id minted on first
    // sight.
    build_id: Vec<u8>,
    // The (dev, inode) whose fd (in `fds`) backs this module, if one was held.
    inode: Option<(u64, u64)>,
    // Whether a `register` call already decided the pin for this module, so
    // re-registrations don't re-stat or re-open the file.
    pin_done: bool,
}

/// One registry per recording, shared by however many threads the platform's
/// capture uses (behind a mutex at the call sites).
pub struct ModuleRegistry {
    policy: KeepPolicy,
    entries: HashMap<ModuleKey, Entry>,
    fds: HashMap<(u64, u64), File>, // (dev, inode) -> held fd, deduped
    rng: u64,                       // splitmix64 state for synthetic ids
}

impl ModuleRegistry {
    pub fn new(policy: KeepPolicy) -> ModuleRegistry {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        ModuleRegistry { policy, entries: HashMap::new(), fds: HashMap::new(), rng: seed }
    }

    fn next_rand(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// The build-id the trace should use for the module at `key`. Mints one
    /// from `id_hint` (the real identity the caller read, or empty →
    /// synthetic) only if this module has not been seen yet; otherwise returns
    /// the id already settled — so every observer of a module agrees, however
    /// many threads race to reach it first.
    pub fn id_for(&mut self, key: ModuleKey, id_hint: &[u8]) -> Vec<u8> {
        if let Some(e) = self.entries.get(&key) {
            return e.build_id.clone();
        }
        let build_id = self.mint(id_hint);
        self.entries.insert(key, Entry { build_id: build_id.clone(), inode: None, pin_done: false });
        build_id
    }

    /// Register a sampled module: settle its build-id (as [`id_for`]) and pin
    /// an fd to `path` per the policy, so a later deletion or rebuild does not
    /// lose its bytes. Idempotent — the pin is decided once per key.
    ///
    /// [`id_for`]: ModuleRegistry::id_for
    pub fn register(&mut self, key: ModuleKey, id_hint: &[u8], path: &str) -> Vec<u8> {
        let build_id = self.id_for(key, id_hint);
        let e = self.entries.get(&key).expect("id_for interned it");
        if !e.pin_done {
            let inode = self.pin_fd(path);
            let e = self.entries.get_mut(&key).expect("id_for interned it");
            e.inode = inode;
            e.pin_done = true;
        }
        build_id
    }

    fn mint(&mut self, hint: &[u8]) -> Vec<u8> {
        if hint.is_empty() {
            let r = self.next_rand();
            synthetic_build_id(r).to_vec()
        } else {
            hint.to_vec()
        }
    }

    /// Pin an fd for `path` per the policy, deduped by `(dev, inode)`. Returns
    /// the key the fd is held under, or `None` when the policy declined, the
    /// file is already gone, or the open failed.
    fn pin_fd(&mut self, path: &str) -> Option<(u64, u64)> {
        let hold = match self.policy {
            KeepPolicy::All => true,
            KeepPolicy::Auto => is_unstable(path),
            KeepPolicy::None => false,
        };
        if !hold {
            return None;
        }
        let meta = std::fs::metadata(path).ok()?;
        let key = (meta.dev(), meta.ino());
        if !self.fds.contains_key(&key) {
            self.fds.insert(key, File::open(path).ok()?);
        }
        Some(key)
    }

    /// Map each held module's build-id to a self-fd path a symbolizer can open
    /// (`/proc/self/fd/<n>` on Linux, `/dev/fd/<n>` on macOS — the latter has
    /// dup semantics, sharing the held fd's offset, which is fine for the
    /// seek/mmap reads symbolization does). Valid only while `self` is alive
    /// (it owns the fds).
    pub fn held_fd_paths(&self) -> HashMap<Vec<u8>, String> {
        #[cfg(target_os = "macos")]
        const FD_DIR: &str = "/dev/fd";
        #[cfg(not(target_os = "macos"))]
        const FD_DIR: &str = "/proc/self/fd";
        let mut out = HashMap::new();
        for e in self.entries.values() {
            if e.build_id.is_empty() {
                continue;
            }
            if let Some(inode) = e.inode {
                if let Some(f) = self.fds.get(&inode) {
                    out.insert(e.build_id.clone(), format!("{FD_DIR}/{}", f.as_raw_fd()));
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
        let key = |pid, base| ModuleKey::Mapping { pid, base };
        // A real id passes through and is stable.
        let real = [0xde, 0xad, 0xbe, 0xef];
        assert_eq!(reg.id_for(key(7, 0x400000), &real), real);
        assert_eq!(reg.id_for(key(7, 0x400000), &[]), real); // second call agrees, ignores new hint
        // An id-less module gets a synthetic id, distinct per key.
        let a = reg.id_for(key(7, 0x500000), &[]);
        let b = reg.id_for(key(8, 0x500000), &[]);
        assert!(is_synthetic(&a) && is_synthetic(&b));
        assert_ne!(a, b);
        assert_eq!(reg.id_for(key(7, 0x500000), &[]), a); // stable
    }

    #[test]
    fn register_pins_fd_and_survives_deletion() {
        let dir = std::env::temp_dir().join(format!("sismo-reg-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("prog"); // unstable path → auto holds it
        std::fs::write(&p, b"\x7fELF-bytes").unwrap();

        let mut reg = ModuleRegistry::new(KeepPolicy::Auto);
        let key = ModuleKey::Mapping { pid: 42, base: 0x400000 };
        // No identity in the hint → synthetic id, and a held fd.
        let id = reg.register(key, &[], p.to_str().unwrap());
        assert!(is_synthetic(&id));
        assert_eq!(reg.held_count(), 1);
        assert_eq!(reg.id_for(key, &[]), id); // any later observer agrees
        // Re-registration adds no second fd.
        assert_eq!(reg.register(key, &[], p.to_str().unwrap()), id);
        assert_eq!(reg.held_count(), 1);

        std::fs::remove_file(&p).unwrap(); // deleted; held fd keeps the bytes readable
        let paths = reg.held_fd_paths();
        let fd_path = paths.get(&id).expect("held by build-id");
        assert_eq!(std::fs::read(fd_path).unwrap(), b"\x7fELF-bytes");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_keys_dedupe_by_inode_and_survive_deletion() {
        let dir = std::env::temp_dir().join(format!("sismo-reg-file-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("prog"); // unstable path → auto holds it
        std::fs::write(&p, b"MH-bytes").unwrap();
        let path = p.to_str().unwrap();
        let real = [1u8, 2, 3, 4]; // pretend a real identity (e.g. an LC_UUID)

        let mut reg = ModuleRegistry::new(KeepPolicy::Auto);
        let id = reg.register(ModuleKey::for_file(path), &real, path);
        assert_eq!(id, real); // a real id passes through unchanged
        assert_eq!(reg.held_count(), 1);
        // Re-observing the same file dedupes: same key, same id, no second fd.
        assert_eq!(reg.register(ModuleKey::for_file(path), &real, path), real);
        assert_eq!(reg.held_count(), 1);

        std::fs::remove_file(&p).unwrap(); // deleted, but the held fd keeps it readable
        let paths = reg.held_fd_paths();
        let fd_path = paths.get(&real[..].to_vec()).expect("held by build-id");
        assert_eq!(std::fs::read(fd_path).unwrap(), b"MH-bytes");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn distinct_files_get_distinct_synthetic_ids() {
        let dir = std::env::temp_dir().join(format!("sismo-reg-syn-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let (a, b) = (dir.join("a"), dir.join("b"));
        std::fs::write(&a, b"aaaa").unwrap();
        std::fs::write(&b, b"bbbb").unwrap();
        let (pa, pb) = (a.to_str().unwrap(), b.to_str().unwrap());

        let mut reg = ModuleRegistry::new(KeepPolicy::None);
        let ida = reg.register(ModuleKey::for_file(pa), &[], pa); // no real identity
        let idb = reg.register(ModuleKey::for_file(pb), &[], pb);
        assert!(is_synthetic(&ida) && is_synthetic(&idb));
        assert_ne!(ida, idb); // distinct files → distinct ids
        assert_eq!(reg.register(ModuleKey::for_file(pa), &[], pa), ida); // stable per inode
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn none_policy_ids_but_holds_nothing() {
        let mut reg = ModuleRegistry::new(KeepPolicy::None);
        let path = "/tmp/whatever-nonexistent";
        let id = reg.register(ModuleKey::for_file(path), &[9, 9], path);
        assert_eq!(id, vec![9, 9]); // still assigns the id
        assert_eq!(reg.held_count(), 0); // but holds no fd
        assert!(reg.held_fd_paths().is_empty());
    }
}
