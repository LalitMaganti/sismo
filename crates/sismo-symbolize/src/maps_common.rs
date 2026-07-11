// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Shared plumbing for the two `/proc/<pid>/maps` readers (proc_maps and
//! data_regions): reading the file and binary-searching the parsed,
//! ascending-by-start ranges. The line parsing differs between them (executable
//! file-backed mappings with build-ids vs. every mapping labelled) and stays in
//! each module.

/// Read `/proc/<pid>/maps` as text, or None on failure. /proc files report size
/// 0, so this reads to end rather than trusting the stat size.
pub fn read_maps_text(pid: u32) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{pid}/maps")).ok()?;
    Some(String::from_utf8_lossy(&raw).into_owned())
}

/// The item in `items` whose `[start, end)` range contains `addr`, if any.
/// `items` must be sorted ascending by start with non-overlapping ranges (the
/// kernel emits /proc/maps sorted and the parses preserve that), so this is a
/// binary search. `range` extracts `(start, end)` from an item.
pub fn find_range<T>(items: &[T], addr: u64, range: impl Fn(&T) -> (u64, u64)) -> Option<&T> {
    let mut lo = 0usize;
    let mut hi = items.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let (start, end) = range(&items[mid]);
        if addr < start {
            hi = mid;
        } else if addr >= end {
            lo = mid + 1;
        } else {
            return Some(&items[mid]);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_range_binary_searches() {
        let items = [(0x1000u64, 0x2000u64), (0x3000, 0x4000)];
        let range = |t: &(u64, u64)| *t;
        assert_eq!(find_range(&items, 0x1500, range), Some(&items[0]));
        assert_eq!(find_range(&items, 0x3000, range), Some(&items[1]));
        assert!(find_range(&items, 0x2500, range).is_none()); // gap
        assert!(find_range(&items, 0x4000, range).is_none()); // end exclusive
    }
}
