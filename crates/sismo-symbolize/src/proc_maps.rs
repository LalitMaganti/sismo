// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `/proc/<pid>/maps` reader: turns a sampled absolute user PC into
//! (module, file-offset). Only executable, file-backed mappings are kept —
//! those are the ones a PC can land in and that a symbolizer can resolve.
//!
//! The file-offset convention: for a PC inside mapping `m`, `pc - m.start +
//! m.offset` is the byte offset into the backing file, and `base_avma` is the
//! avma of the file's lowest mapping (the image base), so `pc - base_avma` is
//! the image-relative address symbol lookup wants for PIE and non-PIE alike.
//!
//! [`ProcMaps::parse`] returns an owned handle; [`ProcMaps::find`] borrows a
//! [`Mapping`] out of it.

use std::collections::HashMap;
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
/// build-id and base avma.
pub struct Mapping {
    pub start: u64,
    pub end: u64,
    pub offset: u64,
    pub base_avma: u64,
    pub path: String,
    pub build_id: Vec<u8>,
}

/// Parsed `/proc/<pid>/maps`. `mappings` stays in ascending `start` order (the
/// kernel emits /proc/maps sorted, and the parse preserves that order), so
/// [`ProcMaps::find`] can binary-search.
pub struct ProcMaps {
    mappings: Vec<Mapping>,
}

impl ProcMaps {
    /// Parse `/proc/<pid>/maps`, or None on failure.
    pub fn parse(pid: u32) -> Option<ProcMaps> {
        from_pid(pid)
    }

    /// The executable file-backed mapping containing `addr`, if any.
    pub fn find(&self, addr: u64) -> Option<&Mapping> {
        crate::maps_common::find_range(&self.mappings, addr, |m| (m.start, m.end))
    }
}

// ---- DIA-6: residual (unresolvable) frame classification --------------------
//
// A sampled PC that lands in no file-backed executable mapping resolves to
// nothing and, today, is dropped in the capture path. These are not all the
// same thing: an anonymous executable page in a JIT runtime is a JIT method, a
// bare anonymous executable page is unknown generated code, a non-executable
// page is a bad walk, and an address in no mapping at all is stale/freed. This
// classifier — built from the target's full /proc/<pid>/maps (every region,
// including the anon/[vdso]/[heap] ones the file-backed parse drops) — labels a
// residual PC by kind so it can be surfaced instead of vanishing.
//
// Pure and self-contained; the capture-side wiring that records residual frames
// against these labels is a separate, capture-path change.

/// What an unresolvable (residual) address is, from the target's maps.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Residual {
    /// Anonymous executable page in a process running a recognized JIT runtime —
    /// almost certainly a JIT-compiled method (the runtime's own symbol map,
    /// JIT-1, is what names it).
    Jit,
    /// Anonymous executable page with no recognized runtime — unknown generated
    /// code (a hand-rolled trampoline, an unrecognized JIT).
    AnonExec,
    /// A non-executable page — an instruction pointer here means a bad unwind.
    Anon,
    /// The address is in no mapping at all — stale/freed code (e.g. a JIT page
    /// unmapped before the post-record maps read).
    Unmapped,
}

/// The target's full address-space map for residual classification: every
/// region with its executable bit, plus which JIT runtime (if any) is loaded.
struct Region {
    start: u64,
    end: u64,
    exec: bool,
    /// A named region (a file path, or `[vdso]`/`[heap]`/`[stack]`). Truly
    /// anonymous regions — the ones JIT engines mmap for code — have no name.
    named: bool,
}

pub struct ResidualMap {
    /// Every region, sorted by start for binary search.
    regions: Vec<Region>,
    /// The recognized JIT/interpreter runtime present in the process, if any.
    runtime: Option<&'static str>,
}

impl ResidualMap {
    /// Build from a live `/proc/<pid>/maps`, or None if it can't be read.
    pub fn parse(pid: u32) -> Option<ResidualMap> {
        Some(Self::from_text(&crate::maps_common::read_maps_text(pid)?))
    }

    fn from_text(raw: &str) -> ResidualMap {
        let mut regions = Vec::new();
        let mut runtime = None;
        for line in raw.split('\n') {
            let mut it = line.split([' ', '\t']).filter(|t| !t.is_empty());
            // start-end perms offset dev inode [pathname]
            let (Some(range), Some(perms), Some(_off), Some(_dev), Some(_ino)) =
                (it.next(), it.next(), it.next(), it.next(), it.next())
            else {
                continue;
            };
            let Some((s, e)) = range.split_once('-') else { continue };
            let (Some(start), Some(end)) = (
                u64::from_str_radix(s, 16).ok(),
                u64::from_str_radix(e, 16).ok(),
            ) else {
                continue;
            };
            let path = it.next(); // present iff the region is named
            let exec = perms.as_bytes().get(2) == Some(&b'x');
            regions.push(Region { start, end, exec, named: path.is_some() });
            if runtime.is_none() {
                if let Some(p) = path {
                    runtime = runtime_from_path(p);
                }
            }
        }
        regions.sort_by_key(|r| r.start);
        ResidualMap { regions, runtime }
    }

    /// The region containing `addr`, if any (binary search).
    fn region(&self, addr: u64) -> Option<&Region> {
        let i = self.regions.partition_point(|r| r.start <= addr);
        (i > 0 && addr < self.regions[i - 1].end).then(|| &self.regions[i - 1])
    }

    /// Classify a residual address into one of the four residual kinds. Assumes
    /// the address is a genuine residual (no file-backed symbol); a named region
    /// is treated as anonymous-of-that-permission for classification purposes —
    /// callers that must not surface named regions check [`Self::residual_label`].
    pub fn classify(&self, addr: u64) -> Residual {
        match self.region(addr) {
            None => Residual::Unmapped,
            Some(r) if !r.exec => Residual::Anon,
            Some(_) if self.runtime.is_some() => Residual::Jit,
            Some(_) => Residual::AnonExec,
        }
    }

    /// The label to record for a residual PC, or None to leave it dropped.
    ///
    /// None when no JIT runtime is present — so a native capture is byte-for-byte
    /// unchanged — or when the PC falls in a *named* region ([vdso], [heap], a
    /// mapped file's non-exec page): those aren't anonymous JIT/residual code and
    /// mislabeling them as `[jit:…]` would be wrong. Otherwise an anonymous
    /// executable page is the runtime's JIT code, an anonymous non-exec page is
    /// `[anon]`, and an address in no mapping is `[unmapped]`.
    pub fn residual_label(&self, addr: u64) -> Option<String> {
        let rt = self.runtime?;
        match self.region(addr) {
            None => Some("[unmapped]".to_string()),
            Some(r) if r.named => None,
            Some(r) if r.exec => Some(format!("[jit:{rt}]")),
            Some(_) => Some("[anon]".to_string()),
        }
    }

    pub fn runtime(&self) -> Option<&'static str> {
        self.runtime
    }
}

/// Recognize a JIT/interpreter runtime from a loaded image's path, by real
/// filename (not a loose prefix): the JIT method label names this runtime.
fn runtime_from_path(path: &str) -> Option<&'static str> {
    let base = path.rsplit('/').next().unwrap_or(path);
    if path.contains("libnode") || path.contains("libv8") || base == "node" {
        Some("node")
    } else if path.contains("libjvm") {
        Some("jvm")
    } else if path.contains("libpython") || base == "python" || base.starts_with("python3") {
        Some("python")
    } else {
        None
    }
}

/// Parse one maps line: `start-end perms offset dev inode  pathname`. Keeps
/// only absolute-path-backed mappings (skips `[vdso]`/`[heap]`/anon). The
/// pathname is the single whitespace-delimited token
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
    let raw = crate::maps_common::read_maps_text(pid)?;
    let mappings = parse_text(&raw, |path| {
        read_build_id(path).unwrap_or_else(|| synth_build_id(path).to_vec())
    });
    Some(ProcMaps { mappings })
}

/// Whether the ELF at `path` carries a real GNU build-id note. `false` means
/// sismo had to synthesize a per-run id, so cross-run correlation and
/// symbol-server / offline symbolization can't match this binary.
pub fn has_gnu_build_id(path: &str) -> bool {
    read_build_id(path).is_some()
}

const PT_NOTE: u32 = 4;
const SHT_NOTE: u32 = 7;
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

    // Go puts `.note.gnu.build-id` in a section that no PT_NOTE segment covers,
    // so the program-header scan above misses it and sismo would synthesize a
    // per-run id — silently breaking cross-run matching for every Go binary.
    // Fall back to scanning SHT_NOTE sections.
    read_build_id_from_sections(&f, &ehdr)
}

/// Fallback build-id lookup that scans `SHT_NOTE` sections via the section
/// header table, for GNU build-id notes not reachable through a PT_NOTE segment.
fn read_build_id_from_sections(f: &std::fs::File, ehdr: &[u8; 64]) -> Option<Vec<u8>> {
    let e_shoff = u64::from_le_bytes(ehdr[40..48].try_into().unwrap());
    let e_shentsize = u16::from_le_bytes(ehdr[58..60].try_into().unwrap());
    let e_shnum = u16::from_le_bytes(ehdr[60..62].try_into().unwrap());
    if e_shoff == 0 || e_shnum == 0 || e_shentsize < 64 {
        return None; // no (usable) section header table
    }
    for i in 0..e_shnum {
        let mut shdr = [0u8; 64];
        if f
            .read_exact_at(&mut shdr, e_shoff + i as u64 * e_shentsize as u64)
            .is_err()
        {
            return None;
        }
        if u32::from_le_bytes(shdr[4..8].try_into().unwrap()) != SHT_NOTE {
            continue;
        }
        let sh_offset = u64::from_le_bytes(shdr[24..32].try_into().unwrap());
        let sh_size = u64::from_le_bytes(shdr[32..40].try_into().unwrap());
        if sh_size == 0 || sh_size > 64 * 1024 {
            continue;
        }
        let mut notes = vec![0u8; sh_size as usize];
        if f.read_exact_at(&mut notes, sh_offset).is_err() {
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

    // A JIT process: node image, an anon-exec (JIT) page, a non-exec anon page,
    // and a named [vdso] exec region — exercises every residual case.
    const JIT_MAPS: &str = "\
400000-401000 r-xp 00000000 fd:01 1  /usr/bin/node\n\
7f0000000000-7f0000010000 rwxp 00000000 00:00 0 \n\
7f0000020000-7f0000030000 rw-p 00000000 00:00 0 \n\
7ffff7ffd000-7ffff7fff000 r-xp 00000000 00:00 0  [vdso]\n";

    #[test]
    fn residual_label_in_jit_process() {
        let m = ResidualMap::from_text(JIT_MAPS);
        assert_eq!(m.runtime(), Some("node"));
        // Anon exec page in a JIT process → jit method.
        assert_eq!(m.residual_label(0x7f0000000100).as_deref(), Some("[jit:node]"));
        assert_eq!(m.classify(0x7f0000000100), Residual::Jit);
        // Anon non-exec page → anon.
        assert_eq!(m.residual_label(0x7f0000020100).as_deref(), Some("[anon]"));
        // A gap between regions → unmapped.
        assert_eq!(m.residual_label(0x7f0000015000).as_deref(), Some("[unmapped]"));
        // A named [vdso] exec region must NOT be mislabeled as jit — left dropped.
        assert_eq!(m.residual_label(0x7ffff7ffd100), None);
    }

    #[test]
    fn residual_label_none_without_runtime() {
        // No recognized runtime → never surface a residual, so a native capture
        // is byte-identical to before. classify still reports the raw kind.
        let maps = "\
400000-401000 r-xp 00000000 fd:01 1  /home/me/mytool\n\
7f0000000000-7f0000010000 rwxp 00000000 00:00 0 \n";
        let m = ResidualMap::from_text(maps);
        assert_eq!(m.runtime(), None);
        assert_eq!(m.residual_label(0x7f0000000100), None);
        assert_eq!(m.residual_label(0xdeadbeef0000), None); // unmapped, still None
        assert_eq!(m.classify(0x7f0000000100), Residual::AnonExec);
    }

    #[test]
    fn runtime_from_path_matches_real_images() {
        assert_eq!(runtime_from_path("/usr/lib64/libpython3.14.so.1.0"), Some("python"));
        assert_eq!(runtime_from_path("/opt/node/bin/node"), Some("node"));
        assert_eq!(runtime_from_path("/usr/lib/jvm/lib/server/libjvm.so"), Some("jvm"));
        assert_eq!(runtime_from_path("/usr/lib64/libc.so.6"), None);
        assert_eq!(runtime_from_path("/opt/node/bin/npm"), None);
    }

    #[test]
    fn has_gnu_build_id_false_for_non_elf_and_missing() {
        assert!(!has_gnu_build_id("/no/such/binary"));
        assert!(!has_gnu_build_id("/etc/hostname")); // present but not an ELF
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
