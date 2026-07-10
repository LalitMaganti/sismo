// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `/proc/<pid>/maps` reader for turning a sampled *data* address into the
//! memory region it landed in — the cache focus's data-side attribution.
//!
//! Unlike proc_maps (which keeps only executable file-backed mappings), this
//! keeps *every* mapping and labels it:
//!   - file-backed → the file's basename ("libc.so.6")
//!   - "[heap]"/"[stack]"/"[vdso]"/… → kept verbatim
//!   - anonymous → "[anon]"
//!
//! [`DataRegions::parse`] returns an owned handle; [`DataRegions::find`]
//! borrows a [`Region`] out of it.

pub struct Region {
    pub start: u64,
    pub end: u64,
    pub label: String,
}

/// Parsed `/proc/<pid>/maps`. `regions` stays in ascending `start` order
/// (kernel emits /proc/maps sorted; the parse preserves it), so
/// [`DataRegions::find`] can binary-search.
pub struct DataRegions {
    regions: Vec<Region>,
}

impl DataRegions {
    /// Parse `/proc/<pid>/maps`, or None on failure.
    pub fn parse(pid: u32) -> Option<DataRegions> {
        from_pid(pid)
    }

    /// The region containing `addr`, if any.
    pub fn find(&self, addr: u64) -> Option<&Region> {
        let mut lo = 0usize;
        let mut hi = self.regions.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let r = &self.regions[mid];
            if addr < r.start {
                hi = mid;
            } else if addr >= r.end {
                lo = mid + 1;
            } else {
                return Some(r);
            }
        }
        None
    }
}

/// One maps line: `start-end perms offset dev inode  pathname`. The label is
/// the file's basename for a file-backed mapping, the bracketed name for a
/// special region, "[anon]" for an anonymous mapping, or a non-path token
/// (e.g. "anon_inode:…") verbatim. The label borrows `line`.
fn parse_line(line: &str) -> Option<(u64, u64, &str)> {
    let mut it = line.split([' ', '\t']).filter(|t| !t.is_empty());
    let range = it.next()?;
    it.next()?; // perms
    it.next()?; // offset
    it.next()?; // dev
    it.next()?; // inode
    let path = it.next(); // pathname (absent for anonymous mappings)

    let (start_s, end_s) = range.split_once('-')?;
    let start = u64::from_str_radix(start_s, 16).ok()?;
    let end = u64::from_str_radix(end_s, 16).ok()?;

    let label = match path {
        None => "[anon]",
        Some(p) if p.is_empty() => "[anon]",
        Some(p) if p.starts_with('[') => p, // [heap]/[stack]/[vdso]/…
        Some(p) if !p.starts_with('/') => p, // "anon_inode:…" — verbatim
        Some(p) => p.rsplit_once('/').map(|(_, base)| base).unwrap_or(p),
    };
    Some((start, end, label))
}

fn parse_text(raw: &str) -> Vec<Region> {
    let mut out = Vec::new();
    for line in raw.split('\n') {
        if let Some((start, end, label)) = parse_line(line) {
            out.push(Region { start, end, label: label.to_owned() });
        }
    }
    out
}

fn from_pid(pid: u32) -> Option<DataRegions> {
    let raw = std::fs::read(format!("/proc/{pid}/maps")).ok()?;
    let raw = String::from_utf8_lossy(&raw);
    Some(DataRegions { regions: parse_text(&raw) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label_of(line: &str) -> &str {
        parse_line(line).unwrap().2
    }

    #[test]
    fn file_backed_labeled_by_basename() {
        let (start, end, label) =
            parse_line("7f1234500000-7f1234600000 rw-p 00012000 fd:01 1234  /usr/lib/libc.so.6")
                .unwrap();
        assert_eq!(start, 0x7f1234500000);
        assert_eq!(end, 0x7f1234600000);
        assert_eq!(label, "libc.so.6");
    }

    #[test]
    fn bracketed_regions_kept_verbatim() {
        assert_eq!(label_of("01d8c000-01dad000 rw-p 00000000 00:00 0  [heap]"), "[heap]");
        assert_eq!(
            label_of("7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0  [stack]"),
            "[stack]"
        );
    }

    #[test]
    fn anonymous_mapping_labeled_anon() {
        assert_eq!(label_of("7f0000000000-7f0000021000 rw-p 00000000 00:00 0 "), "[anon]");
        assert_eq!(label_of("7f0000000000-7f0000021000 rw-p 00000000 00:00 0"), "[anon]");
    }

    #[test]
    fn non_path_token_kept_verbatim() {
        assert_eq!(
            label_of("7f0000000000-7f0000021000 rw-s 00000000 00:05 1  anon_inode:[io_uring]"),
            "anon_inode:[io_uring]"
        );
    }


    #[test]
    fn find_locates_containing_region() {
        let regions = DataRegions {
            regions: vec![
                Region { start: 0x1000, end: 0x2000, label: "[heap]".into() },
                Region { start: 0x5000, end: 0x6000, label: "libc.so.6".into() },
            ],
        };
        assert_eq!(regions.find(0x1500).map(|r| r.label.as_str()), Some("[heap]"));
        assert_eq!(regions.find(0x5fff).map(|r| r.label.as_str()), Some("libc.so.6"));
        assert!(regions.find(0x3000).is_none()); // hole
        assert!(regions.find(0x6000).is_none()); // end exclusive
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn from_pid_self_is_sane() {
        let regions = from_pid(std::process::id()).expect("parse self maps");
        assert!(!regions.regions.is_empty());
        for w in regions.regions.windows(2) {
            assert!(w[0].start <= w[1].start); // sorted -> find() valid
        }
        for r in &regions.regions {
            assert!(!r.label.is_empty());
            assert_eq!(regions.find(r.start).map(|f| f.start), Some(r.start));
        }
    }
}
