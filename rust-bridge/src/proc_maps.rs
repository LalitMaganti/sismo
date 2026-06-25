// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `/proc/<pid>/maps` reader: turns a sampled absolute user PC into
//! (module, file-offset). Only executable, file-backed mappings are kept —
//! those are the ones a PC can land in and that a symbolizer can resolve.
//!
//! Port of the former src/linux_proc_maps.zig. The file-offset convention is
//! unchanged: for a PC inside mapping `m`, `pc - m.start + m.offset` is the
//! byte offset into the backing file, and `base_avma` is the avma of the
//! file's lowest mapping (the image base), so `pc - base_avma` is the
//! image-relative address symbol lookup wants for PIE and non-PIE alike.
//!
//! C ABI: `sismo_proc_maps_parse(pid)` -> opaque handle; `..._find(addr)`
//! fills a [`SismoMapping`] whose `path`/`build_id` pointers borrow the
//! handle and stay valid until `..._destroy`.

use std::collections::HashMap;
use std::os::raw::c_int;
use std::os::unix::fs::FileExt;

/// One parsed maps line. Non-exec lines are retained (flagged) because a
/// file's base avma must consider every mapping, not just executable ones.
struct Line<'a> {
    start: u64,
    end: u64,
    offset: u64,
    exec: bool,
    path: &'a str,
}

/// A kept (executable, file-backed) mapping with its file's resolved
/// build-id and base avma. Owns its `path`/`build_id` so the handle can hand
/// out borrowed pointers over FFI.
struct Mapping {
    start: u64,
    end: u64,
    offset: u64,
    base_avma: u64,
    path: String,
    build_id: Vec<u8>,
}

/// Opaque handle. `mappings` stays in ascending `start` order (the kernel
/// emits /proc/maps sorted, and the parse preserves that order), so [`find`]
/// can binary-search.
pub struct ProcMaps {
    mappings: Vec<Mapping>,
}

impl ProcMaps {
    fn find(&self, addr: u64) -> Option<&Mapping> {
        let mut lo = 0usize;
        let mut hi = self.mappings.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let m = &self.mappings[mid];
            if addr < m.start {
                hi = mid;
            } else if addr >= m.end {
                lo = mid + 1;
            } else {
                return Some(m);
            }
        }
        None
    }
}

/// Parse one maps line: `start-end perms offset dev inode  pathname`. Keeps
/// only absolute-path-backed mappings (skips `[vdso]`/`[heap]`/anon). Like
/// the Zig original, the pathname is the single whitespace-delimited token
/// after the inode (paths with embedded spaces are truncated — unchanged).
fn parse_line(line: &str) -> Option<Line<'_>> {
    let mut it = line.split([' ', '\t']).filter(|t| !t.is_empty());
    let range = it.next()?;
    let perms = it.next()?;
    let offset_s = it.next()?;
    it.next()?; // dev
    it.next()?; // inode
    let path = it.next()?; // pathname (absent -> skip)

    if perms.len() < 3 {
        return None;
    }
    if path.is_empty() || !path.starts_with('/') {
        return None;
    }

    let (start_s, end_s) = range.split_once('-')?;
    let start = u64::from_str_radix(start_s, 16).ok()?;
    let end = u64::from_str_radix(end_s, 16).ok()?;
    let offset = u64::from_str_radix(offset_s, 16).ok()?;
    Some(Line {
        start,
        end,
        offset,
        exec: perms.as_bytes()[2] == b'x',
        path,
    })
}

struct FileInfo {
    build_id: Vec<u8>,
    base_avma: u64,
}

/// Two-pass assembly shared by the live parse and the tests. `build_id_for`
/// resolves a file's build-id the first time the file is seen (real ELF read
/// in production, a stub in tests).
fn parse_text(raw: &str, mut build_id_for: impl FnMut(&str) -> Vec<u8>) -> Vec<Mapping> {
    // Pass 1: every file-backed line updates its file's base avma (the header
    // mapping is usually non-executable, so this must see all lines).
    let mut files: HashMap<&str, FileInfo> = HashMap::new();
    for line in raw.split('\n') {
        let Some(m) = parse_line(line) else { continue };
        match files.get_mut(m.path) {
            None => {
                files.insert(
                    m.path,
                    FileInfo {
                        build_id: build_id_for(m.path),
                        base_avma: m.start,
                    },
                );
            }
            Some(fi) => {
                if m.start < fi.base_avma {
                    fi.base_avma = m.start;
                }
            }
        }
    }

    // Pass 2: keep the executable, file-backed mappings, attaching their
    // file's build-id and base avma.
    let mut out = Vec::new();
    for line in raw.split('\n') {
        let Some(m) = parse_line(line) else { continue };
        if !m.exec {
            continue;
        }
        let fi = &files[m.path];
        out.push(Mapping {
            start: m.start,
            end: m.end,
            offset: m.offset,
            base_avma: fi.base_avma,
            path: m.path.to_owned(),
            build_id: fi.build_id.clone(),
        });
    }
    out
}

/// Live parse of `/proc/<pid>/maps`.
fn from_pid(pid: u32) -> Option<ProcMaps> {
    // /proc files report size 0; read_to_end handles that.
    let raw = std::fs::read(format!("/proc/{pid}/maps")).ok()?;
    let raw = String::from_utf8_lossy(&raw);
    let mappings = parse_text(&raw, |path| {
        read_build_id(path).unwrap_or_else(|| synth_build_id(path).to_vec())
    });
    Some(ProcMaps { mappings })
}

const PT_NOTE: u32 = 4;
const NT_GNU_BUILD_ID: u32 = 3;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Read the GNU build-id (raw bytes) from the ELF at `path`. Best effort:
/// returns None on any read/parse problem. Assumes a 64-bit LE ELF
/// (x86-64 / aarch64); other classes yield None.
fn read_build_id(path: &str) -> Option<Vec<u8>> {
    let f = std::fs::File::open(path).ok()?;

    let mut ehdr = [0u8; 64];
    f.read_exact_at(&mut ehdr, 0).ok()?;
    if &ehdr[0..4] != b"\x7fELF" {
        return None;
    }
    if ehdr[4] != 2 {
        return None; // ELFCLASS64
    }
    let e_phoff = u64::from_le_bytes(ehdr[32..40].try_into().unwrap());
    let e_phentsize = u16::from_le_bytes(ehdr[54..56].try_into().unwrap());
    let e_phnum = u16::from_le_bytes(ehdr[56..58].try_into().unwrap());
    if e_phentsize < 56 {
        return None;
    }

    for i in 0..e_phnum {
        let mut phdr = [0u8; 56];
        if f
            .read_exact_at(&mut phdr, e_phoff + i as u64 * e_phentsize as u64)
            .is_err()
        {
            return None;
        }
        let p_type = u32::from_le_bytes(phdr[0..4].try_into().unwrap());
        if p_type != PT_NOTE {
            continue;
        }
        let p_offset = u64::from_le_bytes(phdr[8..16].try_into().unwrap());
        let p_filesz = u64::from_le_bytes(phdr[32..40].try_into().unwrap());
        if p_filesz == 0 || p_filesz > 64 * 1024 {
            continue;
        }
        let mut notes = vec![0u8; p_filesz as usize];
        if f.read_exact_at(&mut notes, p_offset).is_err() {
            continue;
        }
        if let Some(id) = build_id_from_notes(&notes) {
            return Some(id.to_vec());
        }
    }
    None
}

/// Walk an ELF note section, returning the NT_GNU_BUILD_ID descriptor bytes.
fn build_id_from_notes(notes: &[u8]) -> Option<&[u8]> {
    let mut off = 0usize;
    while off + 12 <= notes.len() {
        let namesz = u32::from_le_bytes(notes[off..off + 4].try_into().unwrap()) as usize;
        let descsz = u32::from_le_bytes(notes[off + 4..off + 8].try_into().unwrap()) as usize;
        let ntype = u32::from_le_bytes(notes[off + 8..off + 12].try_into().unwrap());
        let name_off = off + 12;
        let desc_off = name_off + align4(namesz);
        let next = desc_off + align4(descsz);
        if next > notes.len() {
            break;
        }
        if ntype == NT_GNU_BUILD_ID && namesz >= 4 && &notes[name_off..name_off + 3] == b"GNU" {
            return Some(&notes[desc_off..desc_off + descsz]);
        }
        off = next;
    }
    None
}

/// A 16-byte synthetic build-id for binaries without a GNU build-id note.
/// Only needs to be stable within a recording and distinct in length from a
/// real (20-byte sha1) id — the bytes themselves are never compared across
/// runs, so this need not match any external value.
fn synth_build_id(path: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&fnv1a64(path.as_bytes(), 0xcbf2_9ce4_8422_2325).to_le_bytes());
    out[8..16].copy_from_slice(&fnv1a64(path.as_bytes(), 0x9e37_79b9_7f4a_7c15).to_le_bytes());
    out
}

fn fnv1a64(bytes: &[u8], basis: u64) -> u64 {
    let mut h = basis;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Mapping view handed across FFI. `path`/`build_id` borrow the handle and
/// are valid until `sismo_proc_maps_destroy`.
#[repr(C)]
pub struct SismoMapping {
    pub start: u64,
    pub end: u64,
    pub offset: u64,
    pub base_avma: u64,
    pub path: *const u8,
    pub path_len: usize,
    pub build_id: *const u8,
    pub build_id_len: usize,
}

/// Parse `/proc/<pid>/maps`. Returns an opaque handle, or null on failure.
#[unsafe(no_mangle)]
pub extern "C" fn sismo_proc_maps_parse(pid: u32) -> *mut ProcMaps {
    match from_pid(pid) {
        Some(m) => Box::into_raw(Box::new(m)),
        None => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_proc_maps_destroy(p: *mut ProcMaps) {
    if p.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(p) });
}

/// Fill `*out` with the executable file-backed mapping containing `addr`.
/// Returns 1 if found, 0 otherwise (`*out` untouched on 0).
///
/// # Safety
/// `p` must be a handle from `sismo_proc_maps_parse`; `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_proc_maps_find(
    p: *const ProcMaps,
    addr: u64,
    out: *mut SismoMapping,
) -> c_int {
    if p.is_null() || out.is_null() {
        return 0;
    }
    let maps = unsafe { &*p };
    match maps.find(addr) {
        Some(m) => {
            unsafe {
                *out = SismoMapping {
                    start: m.start,
                    end: m.end,
                    offset: m.offset,
                    base_avma: m.base_avma,
                    path: m.path.as_ptr(),
                    path_len: m.path.len(),
                    build_id: m.build_id.as_ptr(),
                    build_id_len: m.build_id.len(),
                };
            }
            1
        }
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_line_executable_file_mapping() {
        let l = parse_line(
            "7f1234500000-7f1234600000 r-xp 00012000 fd:01 1234  /usr/lib/libc.so.6",
        )
        .unwrap();
        assert_eq!(l.start, 0x7f1234500000);
        assert_eq!(l.end, 0x7f1234600000);
        assert_eq!(l.offset, 0x12000);
        assert!(l.exec);
        assert_eq!(l.path, "/usr/lib/libc.so.6");
    }

    #[test]
    fn parse_line_keeps_non_exec_but_flags() {
        let l = parse_line(
            "7f1234500000-7f1234600000 r--p 00000000 fd:01 1234  /usr/lib/libc.so.6",
        )
        .unwrap();
        assert!(!l.exec);
        assert_eq!(l.offset, 0);
    }

    #[test]
    fn parse_line_skips_anon_and_special() {
        assert!(parse_line("7f1234500000-7f1234600000 r-xp 00000000 00:00 0 ").is_none());
        assert!(parse_line("7ffd00000000-7ffd00021000 r-xp 00000000 00:00 0  [vdso]").is_none());
    }

    #[test]
    fn parse_text_base_avma_is_lowest_mapping() {
        // A header (non-exec, lowest start) + a text segment for one file.
        // base_avma must be the header's start, attached to the exec mapping.
        let raw = "\
400000-401000 r--p 00000000 fd:01 1  /bin/app\n\
401000-402000 r-xp 00001000 fd:01 1  /bin/app\n";
        let maps = parse_text(raw, |_| vec![0xaa, 0xbb]);
        assert_eq!(maps.len(), 1); // only the exec mapping is kept
        let m = &maps[0];
        assert_eq!(m.start, 0x401000);
        assert_eq!(m.base_avma, 0x400000);
        assert_eq!(m.offset, 0x1000);
        assert_eq!(m.build_id, vec![0xaa, 0xbb]);
    }

    #[test]
    fn build_id_for_called_once_per_file() {
        let raw = "\
400000-401000 r--p 00000000 fd:01 1  /bin/app\n\
401000-402000 r-xp 00001000 fd:01 1  /bin/app\n\
402000-403000 r-xp 00002000 fd:01 1  /bin/app\n";
        let mut calls = 0;
        let maps = parse_text(raw, |_| {
            calls += 1;
            vec![1]
        });
        assert_eq!(calls, 1);
        assert_eq!(maps.len(), 2); // two exec segments of the same file
    }

    #[test]
    fn build_id_from_notes_extracts_gnu_note() {
        // namesz=4 ("GNU\0"), descsz=4, type=NT_GNU_BUILD_ID, desc=DEADBEEF.
        let mut notes = Vec::new();
        notes.extend_from_slice(&4u32.to_le_bytes());
        notes.extend_from_slice(&4u32.to_le_bytes());
        notes.extend_from_slice(&NT_GNU_BUILD_ID.to_le_bytes());
        notes.extend_from_slice(b"GNU\0");
        notes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(build_id_from_notes(&notes), Some(&[0xde, 0xad, 0xbe, 0xef][..]));
    }

    #[test]
    fn build_id_from_notes_none_when_absent() {
        let mut notes = Vec::new();
        notes.extend_from_slice(&4u32.to_le_bytes());
        notes.extend_from_slice(&4u32.to_le_bytes());
        notes.extend_from_slice(&1u32.to_le_bytes()); // not NT_GNU_BUILD_ID
        notes.extend_from_slice(b"GNU\0");
        notes.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(build_id_from_notes(&notes), None);
    }

    #[test]
    fn synth_build_id_is_stable_16_bytes() {
        let a = synth_build_id("/bin/app");
        let b = synth_build_id("/bin/app");
        let c = synth_build_id("/bin/other");
        assert_eq!(a.len(), 16);
        assert_eq!(a, b); // stable
        assert_ne!(a, c); // path-distinct
    }

    // Exercises the real path end to end (live /proc read + ELF build-id
    // extraction against on-disk binaries), which the fixture tests can't.
    #[cfg(target_os = "linux")]
    #[test]
    fn from_pid_self_is_sane() {
        let maps = from_pid(std::process::id()).expect("parse self maps");
        assert!(!maps.mappings.is_empty());
        // Kernel emits /proc/maps sorted; the parse preserves it, so find()'s
        // binary search is valid.
        for w in maps.mappings.windows(2) {
            assert!(w[0].start <= w[1].start);
        }
        for m in &maps.mappings {
            assert!(!m.build_id.is_empty()); // real id or synth fallback
            assert!(m.base_avma <= m.start);
            // The mapping must be findable at its own start address.
            assert_eq!(maps.find(m.start).map(|f| f.start), Some(m.start));
        }
    }

    #[test]
    fn find_binary_searches_ranges() {
        let maps = ProcMaps {
            mappings: vec![
                Mapping { start: 0x1000, end: 0x2000, offset: 0, base_avma: 0x1000,
                          path: "a".into(), build_id: vec![] },
                Mapping { start: 0x3000, end: 0x4000, offset: 0, base_avma: 0x3000,
                          path: "b".into(), build_id: vec![] },
            ],
        };
        assert_eq!(maps.find(0x1500).map(|m| m.path.as_str()), Some("a"));
        assert_eq!(maps.find(0x3000).map(|m| m.path.as_str()), Some("b"));
        assert!(maps.find(0x2500).is_none()); // gap between mappings
        assert!(maps.find(0x4000).is_none()); // end is exclusive
    }
}
