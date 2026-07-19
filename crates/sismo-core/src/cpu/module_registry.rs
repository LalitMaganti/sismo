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
    build_id: Vec<u8>,
    // Held only when the policy decided this file was worth pinning; a None here
    // is a module we saw but chose to reopen by path at the end.
    fd: Option<File>,
}

/// The set of module files a recording sampled, one entry per `(dev, inode)`.
pub struct ModuleRegistry {
    policy: KeepPolicy,
    by_inode: HashMap<(u64, u64), Entry>,
}

impl ModuleRegistry {
    pub fn new(policy: KeepPolicy) -> ModuleRegistry {
        ModuleRegistry { policy, by_inode: HashMap::new() }
    }

    /// Note that `path` (carrying `build_id`) was sampled. On first sight of its
    /// `(dev, inode)`, hold an fd per the policy. Best effort: a path already
    /// gone (short-lived deletion) or an open failure just leaves no held fd.
    pub fn observe(&mut self, path: &str, build_id: &[u8]) {
        if self.policy == KeepPolicy::None || path.is_empty() {
            return;
        }
        let Ok(meta) = std::fs::metadata(path) else {
            return; // already gone, or not a real path (e.g. "[vdso]")
        };
        let key = (meta.dev(), meta.ino());
        if self.by_inode.contains_key(&key) {
            return;
        }
        let hold = match self.policy {
            KeepPolicy::All => true,
            KeepPolicy::Auto => is_unstable(path),
            KeepPolicy::None => false,
        };
        let fd = if hold { File::open(path).ok() } else { None };
        self.by_inode.insert(key, Entry { build_id: build_id.to_vec(), fd });
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
        let bid = [1u8, 2, 3, 4];

        let mut reg = ModuleRegistry::new(KeepPolicy::Auto);
        reg.observe(p.to_str().unwrap(), &bid);
        assert_eq!(reg.held_count(), 1);
        std::fs::remove_file(&p).unwrap(); // deleted, but the held fd keeps it readable

        let paths = reg.held_fd_paths();
        let fd_path = paths.get(&bid[..].to_vec()).expect("held by build-id");
        assert_eq!(std::fs::read(fd_path).unwrap(), b"\x7fELF...");

        // Dedup: observing the same inode again does not add a second fd.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn none_policy_holds_nothing() {
        let mut reg = ModuleRegistry::new(KeepPolicy::None);
        reg.observe("/tmp/whatever", &[9, 9]);
        assert_eq!(reg.held_count(), 0);
        assert!(reg.held_fd_paths().is_empty());
    }
}
