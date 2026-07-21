// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Trust decisions about on-disk byte sources: the one place that knows how a
//! trace build-id maps onto a file's identity on each platform (ELF GNU
//! build-id note vs mach-o LC_UUID). Callers ask the questions —
//! "is this file still the binary the trace sampled?", "what disambiguator
//! should the symbolizer get?" — and never see the format dispatch.

use crate::proc_maps::{file_build_id, is_synthetic};

/// Whether the file at `path` is safe to symbolize as the module the trace
/// recorded with `trace_bid`. Safe when there is no real id to verify (empty
/// or synthetic — an id-less binary opened by path can't be checked) or the
/// file's current identity still matches the trace's. A mismatch means the
/// on-disk file was rebuilt or replaced since recording, so its symbols would
/// be wrong for this trace.
pub fn matches(path: &str, trace_bid: &[u8]) -> bool {
    if trace_bid.is_empty() || is_synthetic(trace_bid) {
        return true;
    }
    if file_build_id(path).as_deref() == Some(trace_bid) {
        return true;
    }
    match <[u8; 16]>::try_from(trace_bid) {
        Ok(uuid) => macho_uuid_matches(path, uuid),
        Err(_) => false,
    }
}

/// The multi-arch disambiguator to hand the symbolizer for a module recorded
/// with `trace_bid`, or `None` when the id carries no binary identity.
///
/// A 16-byte id is a mach-o LC_UUID (macOS traces put the raw UUID in the
/// mapping's build-id) — passing it through lets wholesym pick the matching
/// slice of a fat binary and the matching dSYM. ELF GNU build-ids are 20 bytes
/// (sha1) so they never take this path, and a 16-byte md5 build-id passed as a
/// bogus UUID is harmless: the disambiguator is only consulted for multi-arch
/// containers. Synthetic sismo ids are also 16 bytes but are per-run
/// inventions, not the binary's identity — never pass those.
pub fn uuid_disambiguator(trace_bid: &[u8]) -> Option<[u8; 16]> {
    if is_synthetic(trace_bid) {
        return None;
    }
    trace_bid.try_into().ok()
}

// The mach-o side of the identity check lives in sismo-macho (which compiles
// to nothing off macOS, where an on-disk mach-o cannot be the sampled binary).
#[cfg(target_os = "macos")]
use sismo_macho::file_uuid::file_carries_uuid as macho_uuid_matches;
#[cfg(not(target_os = "macos"))]
fn macho_uuid_matches(_path: &str, _uuid: [u8; 16]) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proc_maps::synthetic_build_id;

    #[test]
    fn empty_and_synthetic_ids_always_match() {
        // No verifiable identity → always "matches".
        assert!(matches("/no/such/path", &[]));
        assert!(matches("/no/such/path", &synthetic_build_id(7)));
        // A real id against a file that can't be read (gone) is a mismatch.
        assert!(!matches("/no/such/path", &[0xde, 0xad, 0xbe, 0xef]));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gnu_note_verifies_the_recorded_file() {
        // Against the file it actually came from, a real id matches; a wrong
        // id doesn't.
        let exe = std::fs::read_link("/proc/self/exe").unwrap();
        let path = exe.to_str().unwrap();
        let real = file_build_id(path).expect("test binary carries a GNU note");
        assert!(matches(path, &real));
        assert!(!matches(path, &[0xaau8; 20]));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn lc_uuid_verifies_the_recorded_file() {
        // The running test binary carries an LC_UUID; its raw bytes are what a
        // macOS trace would record as the build-id.
        let exe = std::env::current_exe().unwrap();
        let path = exe.to_str().unwrap();
        let mut want: Option<[u8; 16]> = None;
        for candidate in [path] {
            if let Ok(f) = std::fs::File::open(candidate) {
                use object::Object;
                let data = object::read::ReadCache::new(f);
                if let Ok(obj) = object::File::parse(&data) {
                    want = obj.mach_uuid().ok().flatten();
                }
            }
        }
        let uuid = want.expect("test binary carries an LC_UUID");
        assert!(matches(path, &uuid));
        let mut wrong = uuid;
        wrong[0] ^= 0xff;
        assert!(!matches(path, &wrong));
    }

    #[test]
    fn disambiguator_only_for_real_16_byte_ids() {
        assert_eq!(uuid_disambiguator(&[7u8; 16]), Some([7u8; 16]));
        assert_eq!(uuid_disambiguator(&[7u8; 20]), None); // ELF sha1 width
        assert_eq!(uuid_disambiguator(&synthetic_build_id(3)), None);
    }
}
