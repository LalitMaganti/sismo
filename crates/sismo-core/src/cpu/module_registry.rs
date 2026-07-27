// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Userspace-only registry of module files a recording sampled, so a binary
//! rebuilt or deleted mid-run still symbolizes.
//!
//! The registry is platform-neutral: it settles each sampled module's trace
//! build-id exactly once (the real identity when the capture read one, else a
//! synthetic magic+random id), and pins an fd to the module's file per the
//! `--keep-module-files` policy so a since-deleted binary's bytes stay
//! readable until the post-record symbolize pass. How a capture *names* a
//! module is the capture's business, expressed as a [`ModuleKey`]:
//!
//! - After a module first appears in a CPU sample, the Linux capture resolves
//!   its executable mapping in userspace, keys it by `(pid, base, device,
//!   inode)`, and preferably transfers an already-open
//!   `/proc/<pid>/map_files/<start>-<end>` fd so it names the exact mapped inode
//!   rather than whatever a pathname names later.
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

use crate::symbolize::proc_maps::{file_build_id, synthetic_build_id};

/// Conservative per-recording limit. A miss only loses retained bytes; the
/// build-id/file-offset identity in the trace remains durable.
const DEFAULT_FD_CAP: usize = 1024;

/// Which sampled module files to hold an fd open for, from `--keep-module-files`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeepPolicy {
    /// Hold nothing; open every module by path at symbolize time. A binary
    /// deleted or replaced before then does not resolve.
    None,
    /// Hold fds only for modules on unstable paths (the default).
    Auto,
    /// Hold an fd for every sampled module (bounded by the registry fd cap).
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
    /// A per-process mapping plus its kernel-reported file identity. Including
    /// the inode prevents a later dlopen at a reused base from inheriting the
    /// previous module's synthetic id or pin state.
    Mapping {
        pid: u32,
        base: u64,
        dev_major: u32,
        dev_minor: u32,
        ino: u64,
    },
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
    // Additional real IDs verified against this held inode. This matters when
    // a first observation minted a synthetic ID and a retry later recovered
    // the ELF build ID used by kernel BuildIdOffset frames.
    aliases: Vec<Vec<u8>>,
    // The (dev, inode) whose fd (in `fds`) backs this module, if one was held.
    inode: Option<(u64, u64)>,
    // Whether pinning succeeded or policy permanently declined it. Transient
    // open/verification failures leave this false so a later maps refresh can retry.
    pin_done: bool,
}

/// One registry per recording, shared by however many threads the platform's
/// capture uses (behind a mutex at the call sites).
pub struct ModuleRegistry {
    policy: KeepPolicy,
    entries: HashMap<ModuleKey, Entry>,
    fds: HashMap<(u64, u64), File>, // (dev, inode) -> held fd, deduped
    rng: u64,                       // splitmix64 state for synthetic ids
    fd_cap: usize,
    paths_by_id: HashMap<Vec<u8>, String>,
}

impl ModuleRegistry {
    pub fn new(policy: KeepPolicy) -> ModuleRegistry {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        ModuleRegistry {
            policy,
            entries: HashMap::new(),
            fds: HashMap::new(),
            rng: seed,
            fd_cap: DEFAULT_FD_CAP,
            paths_by_id: HashMap::new(),
        }
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
        self.entries.insert(
            key,
            Entry {
                build_id: build_id.clone(),
                aliases: Vec::new(),
                inode: None,
                pin_done: false,
            },
        );
        build_id
    }

    /// Register a sampled module: settle its build-id (as [`id_for`]) and pin
    /// an fd to `path` per the policy, so a later deletion or rebuild does not
    /// lose its bytes. Idempotent — the pin is decided once per key.
    ///
    /// [`id_for`]: ModuleRegistry::id_for
    pub fn register(&mut self, key: ModuleKey, id_hint: &[u8], path: &str) -> Vec<u8> {
        self.register_open_path(key, id_hint, path, path, false)
    }

    /// Linux mapping registration. `open_path` may be a target `map_files`
    /// symlink; a non-empty real build ID is verified against the opened inode
    /// before it is retained.
    pub fn register_exact(
        &mut self,
        key: ModuleKey,
        id_hint: &[u8],
        display_path: &str,
        open_path: &str,
    ) -> Vec<u8> {
        self.register_open_path(key, id_hint, display_path, open_path, true)
    }

    /// Linux mapping registration using an fd the caller already opened from
    /// `map_files` (or from an inode-verified pathname). Ownership transfers
    /// directly into the registry, avoiding an unmap/reuse race between
    /// identity inspection and reopening the file for retention.
    pub fn register_exact_file(
        &mut self,
        key: ModuleKey,
        id_hint: &[u8],
        display_path: &str,
        file: File,
    ) -> Vec<u8> {
        let build_id = self.prepare_registration(key, id_hint, display_path, true);
        let need_alias = self.needs_alias(key, &build_id, id_hint, true);
        let pin_done = self.entries.get(&key).expect("id_for interned it").pin_done;
        if !pin_done || need_alias {
            let hold = self.should_hold(display_path);
            let inode = if hold {
                // `id_hint` was read through this same fd by the capture; only
                // the mapping identity must be rechecked before ownership moves.
                self.pin_open_file(key, file, id_hint, true, false)
            } else {
                None
            };
            self.finish_registration(key, id_hint, need_alias, hold, inode);
        }
        build_id
    }

    fn register_open_path(
        &mut self,
        key: ModuleKey,
        id_hint: &[u8],
        display_path: &str,
        open_path: &str,
        verify_elf_id: bool,
    ) -> Vec<u8> {
        let build_id = self.prepare_registration(key, id_hint, display_path, verify_elf_id);
        let need_alias = self.needs_alias(key, &build_id, id_hint, verify_elf_id);
        let pin_done = self.entries.get(&key).expect("id_for interned it").pin_done;
        if !pin_done || need_alias {
            let hold = self.should_hold(display_path);
            let inode = if hold {
                self.pin_fd(key, open_path, id_hint, verify_elf_id)
            } else {
                None
            };
            self.finish_registration(key, id_hint, need_alias, hold, inode);
        }
        build_id
    }

    fn prepare_registration(
        &mut self,
        key: ModuleKey,
        id_hint: &[u8],
        display_path: &str,
        verify_elf_id: bool,
    ) -> Vec<u8> {
        let build_id = self.id_for(key, id_hint);
        if !display_path.is_empty() {
            self.paths_by_id
                .entry(build_id.clone())
                .or_insert_with(|| display_path.to_string());
            if verify_elf_id && !id_hint.is_empty() {
                self.paths_by_id
                    .entry(id_hint.to_vec())
                    .or_insert_with(|| display_path.to_string());
            }
        }
        build_id
    }

    fn needs_alias(
        &self,
        key: ModuleKey,
        build_id: &[u8],
        id_hint: &[u8],
        verify_elf_id: bool,
    ) -> bool {
        let e = self.entries.get(&key).expect("id_for interned it");
        verify_elf_id
            && !id_hint.is_empty()
            && id_hint != build_id
            && !e.aliases.iter().any(|alias| alias == id_hint)
    }

    fn finish_registration(
        &mut self,
        key: ModuleKey,
        id_hint: &[u8],
        need_alias: bool,
        hold: bool,
        inode: Option<(u64, u64)>,
    ) {
        let e = self.entries.get_mut(&key).expect("id_for interned it");
        // Keep an already verified fd if an alias-verification retry is
        // transiently unable to reopen the module.
        e.inode = inode.or(e.inode);
        if inode.is_some() && need_alias {
            e.aliases.push(id_hint.to_vec());
        }
        // A policy refusal is permanent; an open/identity failure is not.
        e.pin_done = e.pin_done || !hold || inode.is_some();
    }

    fn mint(&mut self, hint: &[u8]) -> Vec<u8> {
        if hint.is_empty() {
            let r = self.next_rand();
            synthetic_build_id(r).to_vec()
        } else {
            hint.to_vec()
        }
    }

    fn should_hold(&self, display_path: &str) -> bool {
        match self.policy {
            KeepPolicy::All => true,
            KeepPolicy::Auto => is_unstable(display_path),
            KeepPolicy::None => false,
        }
    }

    /// Whether another exact open could still add a retained fd or a verified
    /// real-ID alias. Capture-side cooldowns may use this without replacing
    /// the registry's authority over transient versus permanent outcomes.
    pub fn needs_exact_retry(
        &self,
        key: ModuleKey,
        id_hint: &[u8],
        display_path: &str,
    ) -> bool {
        if !self.should_hold(display_path) {
            return false;
        }
        let Some(e) = self.entries.get(&key) else { return true };
        let need_alias = !id_hint.is_empty()
            && id_hint != e.build_id
            && !e.aliases.iter().any(|alias| alias == id_hint);
        !e.pin_done || need_alias
    }

    /// Pin an fd, deduped by `(dev, inode)`. For a Linux mapping, reject a
    /// pathname fallback that no longer names the inode reported by `/proc/maps`.
    fn pin_fd(
        &mut self,
        module_key: ModuleKey,
        open_path: &str,
        id_hint: &[u8],
        verify_elf_id: bool,
    ) -> Option<(u64, u64)> {
        let file = File::open(open_path).ok()?;
        self.pin_open_file(
            module_key,
            file,
            id_hint,
            verify_elf_id,
            verify_elf_id,
        )
    }

    fn pin_open_file(
        &mut self,
        module_key: ModuleKey,
        file: File,
        id_hint: &[u8],
        verify_mapping: bool,
        verify_elf_id: bool,
    ) -> Option<(u64, u64)> {
        let meta = file.metadata().ok()?;
        #[cfg(not(target_os = "linux"))]
        let _ = module_key;
        #[cfg(target_os = "linux")]
        if verify_mapping {
            if let ModuleKey::Mapping { dev_major, dev_minor, ino, .. } = module_key {
                if libc::major(meta.dev()) as u32 != dev_major
                    || libc::minor(meta.dev()) as u32 != dev_minor
                    || meta.ino() != ino
                {
                    return None;
                }
            }
        }
        let key = (meta.dev(), meta.ino());
        if verify_elf_id && !id_hint.is_empty() {
            let fd_path = format!("/proc/self/fd/{}", file.as_raw_fd());
            if file_build_id(&fd_path).as_deref() != Some(id_hint) {
                return None;
            }
        }
        if self.fds.contains_key(&key) {
            return Some(key);
        }
        if self.fds.len() >= self.fd_cap {
            return None;
        }
        self.fds.insert(key, file);
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
                    let fd_path = format!("{FD_DIR}/{}", f.as_raw_fd());
                    out.insert(e.build_id.clone(), fd_path.clone());
                    for alias in &e.aliases {
                        out.insert(alias.clone(), fd_path.clone());
                    }
                }
            }
        }
        out
    }

    /// Best known original display path for a real build ID.
    pub fn display_path(&self, build_id: &[u8]) -> Option<&str> {
        self.paths_by_id.get(build_id).map(String::as_str)
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
        let key = |pid, base| ModuleKey::Mapping {
            pid,
            base,
            dev_major: 0,
            dev_minor: 0,
            ino: 0,
        };
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
        let reused_base = ModuleKey::Mapping {
            pid: 7,
            base: 0x500000,
            dev_major: 0,
            dev_minor: 0,
            ino: 1,
        };
        assert_ne!(reg.id_for(reused_base, &[]), a); // a new inode at the same base is new
    }

    #[test]
    fn register_pins_fd_and_survives_deletion() {
        let dir = std::env::temp_dir().join(format!("sismo-reg-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("prog"); // unstable path → auto holds it
        std::fs::write(&p, b"\x7fELF-bytes").unwrap();

        let mut reg = ModuleRegistry::new(KeepPolicy::Auto);
        let key = ModuleKey::Mapping {
            pid: 42,
            base: 0x400000,
            dev_major: 0,
            dev_minor: 0,
            ino: 0,
        };
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
        let fd_path = paths.get(&real[..]).expect("held by build-id");
        assert_eq!(std::fs::read(fd_path).unwrap(), b"MH-bytes");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn transient_pin_failure_retries_on_later_registration() {
        let dir = std::env::temp_dir().join(format!("sismo-reg-retry-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("late");
        let path = p.to_str().unwrap();
        let key = ModuleKey::File { dev: 0, ino: 42 };
        let mut reg = ModuleRegistry::new(KeepPolicy::Auto);
        let id = reg.register(key, &[], path);
        assert_eq!(reg.held_count(), 0);
        assert!(reg.needs_exact_retry(key, &[], path));
        std::fs::write(&p, b"arrived").unwrap();
        assert_eq!(reg.register(key, &[], path), id);
        assert_eq!(reg.held_count(), 1);
        assert!(!reg.needs_exact_retry(key, &[], path));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retry_aliases_a_late_real_build_id_to_the_retained_fd() {
        let dir = std::env::temp_dir().join(format!(
            "sismo-reg-late-build-id-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("late-elf");
        let path = path.to_str().unwrap();
        let key = ModuleKey::File { dev: 0, ino: 84 };
        let mut reg = ModuleRegistry::new(KeepPolicy::All);
        let synthetic = reg.register_exact(key, &[], path, path);
        assert!(is_synthetic(&synthetic));
        assert_eq!(reg.held_count(), 0);

        std::fs::copy("/proc/self/exe", path).unwrap();
        let real = file_build_id(path).unwrap();
        assert_eq!(reg.register_exact(key, &real, path, path), synthetic);
        let held = reg.held_fd_paths();
        assert_eq!(held.get(&synthetic), held.get(&real));
        assert!(held.get(&real).is_some(), "kernel build-id must find the retained fd");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn held_inode_survives_atomic_path_replacement() {
        let dir = std::env::temp_dir().join(format!("sismo-reg-replace-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("prog");
        let new = dir.join("prog.new");
        std::fs::write(&p, b"original").unwrap();
        std::fs::write(&new, b"replacement").unwrap();
        let path = p.to_str().unwrap();
        let mut reg = ModuleRegistry::new(KeepPolicy::Auto);
        let id = reg.register(ModuleKey::for_file(path), &[], path);
        std::fs::rename(&new, &p).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"replacement");
        let fd_path = reg.held_fd_paths().remove(&id).unwrap();
        assert_eq!(std::fs::read(fd_path).unwrap(), b"original");
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

    #[cfg(target_os = "linux")]
    #[test]
    fn exact_open_file_transfers_ownership_after_path_deletion() {
        let dir = std::env::temp_dir().join(format!(
            "sismo-reg-open-transfer-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("module");
        std::fs::copy("/proc/self/exe", &path).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        let real = file_build_id(path.to_str().unwrap()).unwrap();
        let file = File::open(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        let key = ModuleKey::Mapping {
            pid: std::process::id(),
            base: 0x2800,
            dev_major: libc::major(meta.dev()) as u32,
            dev_minor: libc::minor(meta.dev()) as u32,
            ino: meta.ino(),
        };
        let mut reg = ModuleRegistry::new(KeepPolicy::All);
        reg.register_exact_file(key, &real, path.to_str().unwrap(), file);
        assert_eq!(reg.held_count(), 1);
        let fd_path = reg.held_fd_paths().remove(&real).expect("real ID alias");
        assert!(file_build_id(&fd_path).is_some_and(|id| id == real));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn exact_registration_rejects_a_replacement_with_the_same_build_id() {
        let dir = std::env::temp_dir().join(format!(
            "sismo-reg-replaced-same-id-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("module");
        let replacement = dir.join("replacement");
        std::fs::copy("/proc/self/exe", &path).unwrap();
        let expected = std::fs::metadata(&path).unwrap();
        std::fs::copy("/proc/self/exe", &replacement).unwrap();
        std::fs::rename(&replacement, &path).unwrap();

        let real = file_build_id(path.to_str().unwrap()).unwrap();
        let key = ModuleKey::Mapping {
            pid: std::process::id(),
            base: 0x3000,
            dev_major: libc::major(expected.dev()) as u32,
            dev_minor: libc::minor(expected.dev()) as u32,
            ino: expected.ino(),
        };
        let mut reg = ModuleRegistry::new(KeepPolicy::All);
        reg.register_exact(key, &real, path.to_str().unwrap(), path.to_str().unwrap());
        assert_eq!(reg.held_count(), 0, "replacement inode must not be retained");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn exact_registration_verifies_real_build_id() {
        let path = "/proc/self/exe";
        let real = file_build_id(path).expect("test binary has a build id");
        let mut reg = ModuleRegistry::new(KeepPolicy::All);
        let meta = std::fs::metadata(path).unwrap();
        let mapping_key = |base| ModuleKey::Mapping {
            pid: std::process::id(),
            base,
            dev_major: libc::major(meta.dev()) as u32,
            dev_minor: libc::minor(meta.dev()) as u32,
            ino: meta.ino(),
        };
        let key = mapping_key(0x1000);
        reg.register_exact(key, &real, path, path);
        assert_eq!(reg.held_count(), 1);
        assert_eq!(reg.display_path(&real), Some(path));

        let mut wrong = real.clone();
        wrong[0] ^= 0xff;
        let key2 = mapping_key(0x2000);
        reg.register_exact(key2, &wrong, path, path);
        // Same inode was already retained; identity verification is required
        // before aliases can attach to it, so the wrong id gets no fd path.
        assert!(!reg.held_fd_paths().contains_key(&wrong));
    }

    #[test]
    fn fd_cap_is_explicit_and_deterministic() {
        let dir = std::env::temp_dir().join(format!("sismo-reg-cap-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let a = dir.join("a");
        let b = dir.join("b");
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        let mut reg = ModuleRegistry::new(KeepPolicy::All);
        reg.fd_cap = 1;
        reg.register(ModuleKey::for_file(a.to_str().unwrap()), &[], a.to_str().unwrap());
        reg.register(ModuleKey::for_file(b.to_str().unwrap()), &[], b.to_str().unwrap());
        assert_eq!(reg.held_count(), 1);
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
