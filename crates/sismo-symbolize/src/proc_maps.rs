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

    /// Every executable file-backed mapping, ascending by start — for callers
    /// that need the raw segments (e.g. registering unwind-table ranges).
    pub fn mappings(&self) -> &[Mapping] {
        &self.mappings
    }

    /// Distinct loaded modules as `(image base avma, file path)`, one entry per
    /// unique base — the inputs a per-module unwinder or symbolizer wants to
    /// register once. Order follows ascending mapping start.
    pub fn modules(&self) -> Vec<(u64, &str)> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for m in &self.mappings {
            if seen.insert(m.base_avma) {
                out.push((m.base_avma, m.path.as_str()));
            }
        }
        out
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

/// Live parse of `/proc/<pid>/maps`. `build_id` is the real GNU note or empty —
/// a module with no note is given a synthetic id later, by the module registry,
/// where it can be memoized per `(dev, inode)` and marked with [`SYNTH_MAGIC`].
fn from_pid(pid: u32) -> Option<ProcMaps> {
    let raw = crate::maps_common::read_maps_text(pid)?;
    let mappings = parse_text(&raw, |path| read_build_id(path).unwrap_or_default());
    Some(ProcMaps { mappings })
}

/// The 8-byte prefix that marks a build-id as sismo-synthesized rather than a
/// real GNU note: readable in a hexdump, and vanishingly unlikely (2⁻⁶⁴) to
/// prefix a real build-id. The trailing 8 bytes are a random per-module value.
/// Any consumer can recognize a fabricated id — and skip debuginfod, staleness
/// checks, or cross-machine correlation for it — with a cheap prefix check.
pub const SYNTH_MAGIC: [u8; 8] = *b"SISMOSYN";

/// Whether `build_id` is a sismo-synthesized id (carries [`SYNTH_MAGIC`]).
pub fn is_synthetic(build_id: &[u8]) -> bool {
    build_id.len() >= SYNTH_MAGIC.len() && build_id[..SYNTH_MAGIC.len()] == SYNTH_MAGIC
}

/// Build a synthetic build-id: the magic prefix plus `rand` (a per-module random
/// value). 16 bytes, matching a GNU md5 note's width.
pub fn synthetic_build_id(rand: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&SYNTH_MAGIC);
    out[8..].copy_from_slice(&rand.to_le_bytes());
    out
}

/// Whether the ELF at `path` carries a real GNU build-id note. `false` means
/// sismo had to synthesize a per-run id, so cross-run correlation and
/// symbol-server / offline symbolization can't match this binary.
pub fn has_gnu_build_id(path: &str) -> bool {
    read_build_id(path).is_some()
}

/// The GNU build-id note the file at `path` carries right now, or None. Used at
/// symbolize time to detect that a file was replaced since recording.
pub fn file_build_id(path: &str) -> Option<Vec<u8>> {
    read_build_id(path)
}

const NT_GNU_BUILD_ID: u32 = 3;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Read the GNU build-id (raw bytes) from the ELF at `path`. Best effort:
/// returns None on any read/parse problem. 64-bit ELF only (x86-64 / aarch64);
/// other classes yield None. Reads only the note ranges off disk.
fn read_build_id(path: &str) -> Option<Vec<u8>> {
    // The closure is load-bearing: passing `build_id_from_elf` directly fails
    // higher-ranked lifetime inference ("FnOnce is not general enough").
    #[allow(clippy::redundant_closure)]
    crate::elf::with_elf_at_path(path, |elf| build_id_from_elf(elf)).flatten()
}

/// The GNU build-id from an ELF's notes: `PT_NOTE` segments first, then a
/// fallback scan of `SHT_NOTE` sections. Go puts `.note.gnu.build-id` in a
/// section no `PT_NOTE` segment covers, so without the fallback sismo would
/// synthesize a per-run id and silently break cross-run matching for every Go
/// binary. A note blob over 64 KiB is skipped as implausible.
fn build_id_from_elf<'d, R: object::ReadRef<'d>>(elf: &crate::elf::Elf<'d, R>) -> Option<Vec<u8>> {
    for seg in elf.segments().filter(|s| s.p_type == crate::elf::PT_NOTE) {
        if seg.filesz == 0 || seg.filesz > 64 * 1024 {
            continue;
        }
        if let Some(id) = elf.read(seg.offset, seg.filesz).and_then(build_id_from_notes) {
            return Some(id.to_vec());
        }
    }
    for sec in elf.sections().into_iter().filter(|s| s.sh_type == crate::elf::SHT_NOTE) {
        if sec.size == 0 || sec.size > 64 * 1024 {
            continue;
        }
        if let Some(id) = elf.read(sec.offset, sec.size).and_then(build_id_from_notes) {
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

/// Parse the GNU build-id from the *mapped image prefix* of an ELF — the leading
/// bytes of the module as they sit in the target's address space, which is what
/// BPF copies from mapped memory at sample time (CAP-2). Unlike
/// `build_id_from_elf` it needs no section table and no complete file: it reads
/// the ELF header, walks the program headers, and reads each `PT_NOTE` at its
/// vaddr offset within the prefix. `prefix` starts at the image base (the first
/// `PT_LOAD`'s mapping). `None` if the note isn't within the prefix.
pub fn build_id_from_image_prefix(prefix: &[u8]) -> Option<Vec<u8>> {
    let ehdr = prefix.get(..64)?;
    if &ehdr[0..4] != b"\x7fELF" || ehdr[4] != 2 {
        return None; // not ELFCLASS64
    }
    let e_phoff = u64::from_le_bytes(ehdr[32..40].try_into().unwrap());
    let e_phentsize = u16::from_le_bytes(ehdr[54..56].try_into().unwrap()) as u64;
    let e_phnum = u16::from_le_bytes(ehdr[56..58].try_into().unwrap());
    if e_phentsize < 56 || e_phnum == 0 || e_phnum > 4096 {
        return None;
    }
    // The prefix is indexed by vaddr from the image base (min PT_LOAD vaddr, 0
    // for a PIE), matching how it sits mapped in the target. Read each PT_NOTE
    // at `p_vaddr - image_base` — which equals p_offset for a note in the first
    // load segment, so this also works on a whole-file prefix.
    let phdr = |i: u64| -> Option<(u32, u64, u64)> {
        let off = (e_phoff + i * e_phentsize) as usize;
        let ph = prefix.get(off..off.checked_add(56)?)?;
        Some((
            u32::from_le_bytes(ph[0..4].try_into().unwrap()),   // p_type
            u64::from_le_bytes(ph[16..24].try_into().unwrap()), // p_vaddr
            u64::from_le_bytes(ph[32..40].try_into().unwrap()), // p_filesz
        ))
    };
    let mut image_base = u64::MAX;
    for i in 0..e_phnum as u64 {
        let (p_type, p_vaddr, _) = phdr(i)?;
        if p_type == crate::elf::PT_LOAD {
            image_base = image_base.min(p_vaddr);
        }
    }
    let image_base = if image_base == u64::MAX { 0 } else { image_base };
    for i in 0..e_phnum as u64 {
        let (p_type, p_vaddr, p_filesz) = phdr(i)?;
        if p_type != crate::elf::PT_NOTE {
            continue;
        }
        let start = p_vaddr.checked_sub(image_base)? as usize;
        let end = start.checked_add(p_filesz as usize)?;
        if let Some(id) = prefix.get(start..end).and_then(build_id_from_notes) {
            return Some(id.to_vec());
        }
    }
    None
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
    fn synthetic_id_is_magic_tagged_and_recognized() {
        let a = synthetic_build_id(0x1122_3344_5566_7788);
        assert_eq!(a.len(), 16);
        assert_eq!(&a[..8], &SYNTH_MAGIC); // self-identifying prefix
        assert!(is_synthetic(&a));
        // Distinct random tails give distinct ids; the prefix stays constant.
        assert_ne!(synthetic_build_id(1), synthetic_build_id(2));
        // A real (non-magic) id is not mistaken for synthetic.
        assert!(!is_synthetic(&[0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0]));
        assert!(!is_synthetic(b"SISMO")); // too short to carry the magic
    }

    // CAP-2: the build-id parsed from a *mapped image prefix* (what BPF copies
    // from the target's memory) must equal the build-id read from the whole
    // file. For a PIE the first PT_LOAD maps at file offset 0, so the file's
    // leading bytes equal the mapped prefix — read the running test binary and
    // compare the two paths.
    #[cfg(target_os = "linux")]
    #[test]
    fn build_id_from_image_prefix_matches_whole_file() {
        let exe = std::fs::read_link("/proc/self/exe").expect("readlink");
        let path = exe.to_str().unwrap();
        let whole = read_build_id(path);
        assert!(whole.is_some(), "test binary should carry a GNU build-id");
        let bytes = std::fs::read(path).unwrap();
        let prefix = &bytes[..bytes.len().min(64 * 1024)];
        assert_eq!(
            build_id_from_image_prefix(prefix),
            whole,
            "prefix build-id must match the whole-file build-id"
        );
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
            // build_id is the real GNU note or empty now (the registry supplies a
            // synthetic id for note-less modules); a real one must be a real note.
            if !m.build_id.is_empty() {
                assert!(!is_synthetic(&m.build_id)); // proc_maps never fabricates
            }
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
