// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Parser for CPython's `_Py_DebugOffsets` table (PY-1): a self-describing
//! struct CPython 3.13+ embeds at the start of `_PyRuntime` so an external
//! profiler can recover interpreter/thread/frame layout without matching the
//! running interpreter's headers. Every field of the table is itself the byte
//! offset of the corresponding field within the real (private, ABI-unstable)
//! CPython struct — read the table once, then use its values as offsets when
//! walking `_PyRuntime` in the target's memory.
//!
//! Only CPython 3.14's table layout is supported (the meta-offsets below are
//! specific to that header version); [`parse`] rejects any other minor
//! version rather than guess at a compatible-but-different layout.

/// Byte offset, within `_Py_DebugOffsets`, of each field this walk needs
/// (CPython 3.14's `pycore_debug_offsets.h`). The u64 stored at each position
/// is itself the offset of that field within the live CPython struct.
mod meta {
    pub const COOKIE: usize = 0;
    pub const VERSION: usize = 8;
    pub const FREE_THREADED: usize = 16;
    pub const INTERPRETERS_HEAD: usize = 40;
    pub const THREADS_HEAD: usize = 72;
    pub const GIL_RUNTIME_STATE: usize = 128;
    pub const GIL_RUNTIME_STATE_HOLDER: usize = 152;
    pub const CURRENT_FRAME: usize = 208;
    pub const FRAME_PREVIOUS: usize = 256;
    pub const FRAME_EXECUTABLE: usize = 264;
    pub const FRAME_INSTR_PTR: usize = 272;
    pub const CODE_FILENAME: usize = 320;
    pub const CODE_QUALNAME: usize = 336;
    pub const CODE_FIRSTLINENO: usize = 352;
    pub const UNICODE_LENGTH: usize = 632;
    pub const UNICODE_ASCIIOBJECT_SIZE: usize = 640;
    // The blob must cover the last field read (8 bytes at 640).
    pub const MIN_LEN: usize = UNICODE_ASCIIOBJECT_SIZE + 8;
}

const COOKIE: &[u8; 8] = b"xdebugpy";
const SUPPORTED_MAJOR: u64 = 3;
const SUPPORTED_MINOR: u64 = 14;

/// The runtime offsets recovered from a target's `_Py_DebugOffsets` table.
/// Each field is a byte offset into the corresponding live CPython struct,
/// to be added to a base pointer read from the target's memory.
#[derive(Clone, Copy, Debug)]
pub struct PyDebugOffsets {
    pub free_threaded: u64,
    pub interpreters_head: u64,
    pub threads_head: u64,
    pub gil_runtime_state: u64,
    pub gil_runtime_state_holder: u64,
    pub current_frame: u64,
    pub frame_previous: u64,
    pub frame_executable: u64,
    pub frame_instr_ptr: u64,
    pub code_filename: u64,
    pub code_qualname: u64,
    pub code_firstlineno: u64,
    pub unicode_length: u64,
    pub unicode_asciiobject_size: u64,
}

fn ru64(blob: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(blob[off..off + 8].try_into().unwrap())
}

/// Parse a `_Py_DebugOffsets` blob (the bytes at `_PyRuntime + 0`, at least
/// [`meta::MIN_LEN`] bytes). Validates the `"xdebugpy"` cookie and that the
/// embedded `PY_VERSION_HEX` is CPython 3.14; any other cookie, version, or a
/// too-short blob yields `None` rather than a mis-offset walk.
pub fn parse(blob: &[u8]) -> Option<PyDebugOffsets> {
    if blob.len() < meta::MIN_LEN {
        return None;
    }
    if &blob[meta::COOKIE..meta::COOKIE + 8] != COOKIE {
        return None;
    }
    let version = ru64(blob, meta::VERSION);
    let major = (version >> 24) & 0xFF;
    let minor = (version >> 16) & 0xFF;
    if major != SUPPORTED_MAJOR || minor != SUPPORTED_MINOR {
        return None;
    }
    Some(PyDebugOffsets {
        free_threaded: ru64(blob, meta::FREE_THREADED),
        interpreters_head: ru64(blob, meta::INTERPRETERS_HEAD),
        threads_head: ru64(blob, meta::THREADS_HEAD),
        gil_runtime_state: ru64(blob, meta::GIL_RUNTIME_STATE),
        gil_runtime_state_holder: ru64(blob, meta::GIL_RUNTIME_STATE_HOLDER),
        current_frame: ru64(blob, meta::CURRENT_FRAME),
        frame_previous: ru64(blob, meta::FRAME_PREVIOUS),
        frame_executable: ru64(blob, meta::FRAME_EXECUTABLE),
        frame_instr_ptr: ru64(blob, meta::FRAME_INSTR_PTR),
        code_filename: ru64(blob, meta::CODE_FILENAME),
        code_qualname: ru64(blob, meta::CODE_QUALNAME),
        code_firstlineno: ru64(blob, meta::CODE_FIRSTLINENO),
        unicode_length: ru64(blob, meta::UNICODE_LENGTH),
        unicode_asciiobject_size: ru64(blob, meta::UNICODE_ASCIIOBJECT_SIZE),
    })
}

/// Bytes of the table this parser reads (used by the live blob read).
pub const BLOB_LEN: usize = meta::MIN_LEN;

#[cfg(test)]
mod tests {
    use super::*;

    fn synth_blob(cookie: &[u8; 8], version: u64) -> Vec<u8> {
        let mut b = vec![0u8; meta::MIN_LEN];
        b[meta::COOKIE..meta::COOKIE + 8].copy_from_slice(cookie);
        b[meta::VERSION..meta::VERSION + 8].copy_from_slice(&version.to_le_bytes());
        // A distinct, recognizable value at every field this parser extracts,
        // so the test can assert each landed at the right struct field.
        let fields = [
            meta::FREE_THREADED,
            meta::INTERPRETERS_HEAD,
            meta::THREADS_HEAD,
            meta::GIL_RUNTIME_STATE,
            meta::GIL_RUNTIME_STATE_HOLDER,
            meta::CURRENT_FRAME,
            meta::FRAME_PREVIOUS,
            meta::FRAME_EXECUTABLE,
            meta::FRAME_INSTR_PTR,
            meta::CODE_FILENAME,
            meta::CODE_QUALNAME,
            meta::CODE_FIRSTLINENO,
            meta::UNICODE_LENGTH,
            meta::UNICODE_ASCIIOBJECT_SIZE,
        ];
        for (i, &off) in fields.iter().enumerate() {
            let v = 0x1000u64 + i as u64 * 8;
            b[off..off + 8].copy_from_slice(&v.to_le_bytes());
        }
        b
    }

    // PY_VERSION_HEX for CPython 3.14.0 final: major=0x03, minor=0x0E.
    const PY314_VERSION_HEX: u64 = 0x030E_00F0;
    const PY312_VERSION_HEX: u64 = 0x030C_00F0;

    #[test]
    fn parse_extracts_fields_at_the_documented_offsets() {
        let blob = synth_blob(COOKIE, PY314_VERSION_HEX);
        let offs = parse(&blob).expect("valid 3.14 blob must parse");
        assert_eq!(offs.free_threaded, 0x1000);
        assert_eq!(offs.interpreters_head, 0x1008);
        assert_eq!(offs.threads_head, 0x1010);
        assert_eq!(offs.gil_runtime_state, 0x1018);
        assert_eq!(offs.gil_runtime_state_holder, 0x1020);
        assert_eq!(offs.current_frame, 0x1028);
        assert_eq!(offs.frame_previous, 0x1030);
        assert_eq!(offs.frame_executable, 0x1038);
        assert_eq!(offs.frame_instr_ptr, 0x1040);
        assert_eq!(offs.code_filename, 0x1048);
        assert_eq!(offs.code_qualname, 0x1050);
        assert_eq!(offs.code_firstlineno, 0x1058);
        assert_eq!(offs.unicode_length, 0x1060);
        assert_eq!(offs.unicode_asciiobject_size, 0x1068);
    }

    #[test]
    fn parse_rejects_bad_cookie() {
        let blob = synth_blob(b"notacook", PY314_VERSION_HEX);
        assert!(parse(&blob).is_none());
    }

    #[test]
    fn parse_rejects_wrong_version() {
        let blob = synth_blob(COOKIE, PY312_VERSION_HEX);
        assert!(parse(&blob).is_none());
    }

    #[test]
    fn parse_rejects_short_blob() {
        let mut blob = synth_blob(COOKIE, PY314_VERSION_HEX);
        blob.truncate(meta::MIN_LEN - 1);
        assert!(parse(&blob).is_none());
    }
}
