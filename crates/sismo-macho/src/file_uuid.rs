// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! LC_UUID identity of an on-disk mach-o, for verifying that a file still is
//! the binary a trace sampled (macOS traces carry the raw 16-byte UUID as the
//! mapping's build-id).

use object::read::macho::FatArch;
use object::Object;

/// Whether the mach-o at `path` carries LC_UUID `want` — in any slice, for a
/// fat container (wholesym's disambiguator then picks the matching one). False
/// for non-mach-o files or on any open/parse problem.
pub fn file_carries_uuid(path: &str, want: [u8; 16]) -> bool {
    let Ok(f) = std::fs::File::open(path) else {
        return false;
    };
    let data = object::read::ReadCache::new(f);
    if let Ok(obj) = object::File::parse(&data) {
        return obj.mach_uuid() == Ok(Some(want));
    }
    let slice_matches = |(off, size): (u64, u64)| {
        object::File::parse(data.range(off, size))
            .is_ok_and(|o| o.mach_uuid() == Ok(Some(want)))
    };
    if let Ok(fat) = object::read::macho::MachOFatFile32::parse(&data) {
        return fat.arches().iter().any(|a| slice_matches(a.file_range()));
    }
    if let Ok(fat) = object::read::macho::MachOFatFile64::parse(&data) {
        return fat.arches().iter().any(|a| slice_matches(a.file_range()));
    }
    false
}
