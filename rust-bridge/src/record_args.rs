// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Value-parsing helpers for `sismo record`'s argument parser (migrated from the
//! pure leaves of cmd_record.zig — parseScaled / parseBufferKb /
//! parseDurationSeconds). These convert `--buffer 256MB` and `--duration 5m`
//! style strings to their scalar values; the Zig parser calls them over the C
//! ABI. They're the self-contained, OS-independent, byte-testable part of the
//! record parser — the rest (RecordArgs assembly, the consumer-session runner)
//! is entangled with the C++ shim + focus_presets and migrates with the runner.
//!
//! This module is the seed of the eventual full Rust `sismo record` parser.

/// Parse `s` as a base-10 integer, scale by `multiplier`, and fit into u64.
/// Returns None on non-numeric input, overflow, a zero result, or exceeding
/// `max` (the target integer's max).
fn parse_scaled(s: &[u8], multiplier: u64, max: u64) -> Option<u64> {
    let text = std::str::from_utf8(s).ok()?;
    let n: u64 = text.parse().ok()?;
    let total = n.checked_mul(multiplier)?;
    if total == 0 || total > max {
        return None;
    }
    Some(total)
}

/// Parse a buffer-size argument like "256MB" / "1GB" / "512KB" into KB
/// (build_config takes uint32 buffer_size_kb). The suffix is required — bare
/// integers are rejected to avoid the bytes-vs-KB ambiguity.
fn parse_buffer_kb(s: &[u8]) -> Option<u32> {
    if s.len() < 3 {
        return None;
    }
    let (num, suffix) = s.split_at(s.len() - 2);
    let multiplier_kb: u64 = match suffix {
        b if b.eq_ignore_ascii_case(b"kb") => 1,
        b if b.eq_ignore_ascii_case(b"mb") => 1024,
        b if b.eq_ignore_ascii_case(b"gb") => 1024 * 1024,
        _ => return None,
    };
    parse_scaled(num, multiplier_kb, u32::MAX as u64).map(|v| v as u32)
}

/// Parse a duration argument: a bare integer (seconds) or an integer with a
/// single-letter 's' / 'm' / 'h' suffix. Returns total seconds (fits u32).
fn parse_duration_seconds(s: &[u8]) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    let last = s[s.len() - 1];
    let (num, multiplier): (&[u8], u64) = match last {
        b's' => (&s[..s.len() - 1], 1),
        b'm' => (&s[..s.len() - 1], 60),
        b'h' => (&s[..s.len() - 1], 3600),
        b'0'..=b'9' => (s, 1),
        _ => return None,
    };
    parse_scaled(num, multiplier, u32::MAX as u64).map(|v| v as u32)
}

// ---- C ABI (called by the Zig record parser) -------------------------------

/// Parse a `--buffer` value into KB. Returns true and writes `*out` on success;
/// false (out untouched) on any invalid input.
///
/// # Safety
/// `s` must be valid for `s_len` bytes; `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_parse_buffer_kb(s: *const u8, s_len: usize, out: *mut u32) -> bool {
    let bytes = unsafe { std::slice::from_raw_parts(s, s_len) };
    match parse_buffer_kb(bytes) {
        Some(v) => {
            unsafe { *out = v };
            true
        }
        None => false,
    }
}

/// Parse a `--duration` value into seconds. Returns true and writes `*out` on
/// success; false (out untouched) on any invalid input.
///
/// # Safety
/// `s` must be valid for `s_len` bytes; `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_parse_duration_seconds(s: *const u8, s_len: usize, out: *mut u32) -> bool {
    let bytes = unsafe { std::slice::from_raw_parts(s, s_len) };
    match parse_duration_seconds(bytes) {
        Some(v) => {
            unsafe { *out = v };
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_kb_suffixes() {
        assert_eq!(parse_buffer_kb(b"512KB"), Some(512));
        assert_eq!(parse_buffer_kb(b"256MB"), Some(256 * 1024));
        assert_eq!(parse_buffer_kb(b"1GB"), Some(1024 * 1024));
        assert_eq!(parse_buffer_kb(b"2gb"), Some(2 * 1024 * 1024)); // case-insensitive
    }

    #[test]
    fn buffer_kb_rejects_bare_and_bad() {
        assert_eq!(parse_buffer_kb(b"256"), None); // no suffix
        assert_eq!(parse_buffer_kb(b"MB"), None); // too short / no number
        assert_eq!(parse_buffer_kb(b"0KB"), None); // zero rejected
        assert_eq!(parse_buffer_kb(b"xxMB"), None); // non-numeric
    }

    #[test]
    fn buffer_kb_overflow_rejected() {
        // 5 GB in KB = 5*1024*1024 = 5_242_880 (fits u32), but 5000GB overflows.
        assert_eq!(parse_buffer_kb(b"5000GB"), None);
        // exactly at the u32 boundary in KB is fine; wildly over is not.
        assert_eq!(parse_buffer_kb(b"99999999999999999999GB"), None);
    }

    #[test]
    fn duration_suffixes_and_bare() {
        assert_eq!(parse_duration_seconds(b"30"), Some(30)); // bare int = seconds
        assert_eq!(parse_duration_seconds(b"30s"), Some(30));
        assert_eq!(parse_duration_seconds(b"5m"), Some(300));
        assert_eq!(parse_duration_seconds(b"1h"), Some(3600));
    }

    #[test]
    fn duration_rejects_bad() {
        assert_eq!(parse_duration_seconds(b""), None);
        assert_eq!(parse_duration_seconds(b"0"), None); // zero rejected
        assert_eq!(parse_duration_seconds(b"5d"), None); // unsupported suffix
        assert_eq!(parse_duration_seconds(b"abc"), None);
        assert_eq!(parse_duration_seconds(b"h"), None); // suffix, no number
    }

    #[test]
    fn c_abi_writes_out_only_on_success() {
        let mut out: u32 = 12345;
        assert!(unsafe { sismo_parse_buffer_kb(b"256MB".as_ptr(), 5, &mut out) });
        assert_eq!(out, 256 * 1024);
        // failure leaves out untouched.
        assert!(!unsafe { sismo_parse_buffer_kb(b"256".as_ptr(), 3, &mut out) });
        assert_eq!(out, 256 * 1024);

        let mut d: u32 = 0;
        assert!(unsafe { sismo_parse_duration_seconds(b"5m".as_ptr(), 2, &mut d) });
        assert_eq!(d, 300);
    }
}
