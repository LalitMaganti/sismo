// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Sismo data-source config wire format. One encode + decode per producer
//! (macos_cpu_samples, heap, macos_sched), plus extraction of the config
//! bytes from Perfetto's `DataSourceConfig`.
//!
//! All configs ride at vendor-extension field 2000 of `DataSourceConfig`.
//! See protos/sismo_config.proto.

use crate::proto::ProtoWriter;
use std::slice;

/// Field on Perfetto's `DataSourceConfig` carrying sismo's config bytes.
const DSC_SISMO_CONFIG_FIELD: u64 = 2000;

const WIRE_VARINT: u64 = 0;
const WIRE_LEN: u64 = 2;

// ---- Wire-format read primitives -------------------------------------------

/// Decode a base-128 varint. Returns (value, bytes_consumed), or None on
/// truncation / overflow.
fn read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        value |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None; // overflow
        }
    }
    None // truncated
}

/// Bytes to skip for a field of `wire_type` at the start of `bytes`, or None
/// if malformed / truncated.
fn skip_field(wire_type: u64, bytes: &[u8]) -> Option<usize> {
    match wire_type {
        0 => read_varint(bytes).map(|(_, c)| c),
        1 => (bytes.len() >= 8).then_some(8),
        2 => {
            let (len, consumed) = read_varint(bytes)?;
            let total = consumed.checked_add(len as usize)?;
            (total <= bytes.len()).then_some(total)
        }
        5 => (bytes.len() >= 4).then_some(4),
        _ => None,
    }
}

// ---- DataSourceConfig extraction -------------------------------------------

/// Find `DataSourceConfig.sismo_config` (field 2000, length-delimited) inside a
/// serialized DataSourceConfig. On success writes the byte offset + length of
/// the sub-slice (relative to `dsc`) to the out-params and returns true;
/// returns false if absent or malformed.
///
/// # Safety
/// `dsc` valid for `dsc_len` bytes or null; out-params writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_config_extract(
    dsc: *const u8,
    dsc_len: usize,
    out_offset: *mut usize,
    out_len: *mut usize,
) -> bool {
    let bytes: &[u8] = if dsc.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(dsc, dsc_len) }
    };
    let mut i = 0usize;
    while i < bytes.len() {
        let (tag, consumed) = match read_varint(&bytes[i..]) {
            Some(v) => v,
            None => return false,
        };
        i += consumed;
        let field_num = tag >> 3;
        let wire_type = tag & 0x07;
        if field_num == DSC_SISMO_CONFIG_FIELD && wire_type == WIRE_LEN {
            let (len, c) = match read_varint(&bytes[i..]) {
                Some(v) => v,
                None => return false,
            };
            i += c;
            let end = match i.checked_add(len as usize) {
                Some(e) if e <= bytes.len() => e,
                _ => return false,
            };
            unsafe {
                *out_offset = i;
                *out_len = end - i;
            }
            return true;
        }
        match skip_field(wire_type, &bytes[i..]) {
            Some(s) => i += s,
            None => return false,
        }
    }
    false
}

// ---- Generic single-message varint decode ----------------------------------

/// Walk a config message, invoking `f(field_num, value)` for each varint field
/// and skipping others. Returns false on malformed input.
fn decode_varint_fields(bytes: &[u8], mut f: impl FnMut(u64, u64)) -> bool {
    let mut i = 0usize;
    while i < bytes.len() {
        let (tag, consumed) = match read_varint(&bytes[i..]) {
            Some(v) => v,
            None => return false,
        };
        i += consumed;
        let field_num = tag >> 3;
        let wire_type = tag & 0x07;
        if wire_type == WIRE_VARINT {
            let (val, c) = match read_varint(&bytes[i..]) {
                Some(v) => v,
                None => return false,
            };
            i += c;
            f(field_num, val);
        } else {
            match skip_field(wire_type, &bytes[i..]) {
                Some(s) => i += s,
                None => return false,
            }
        }
    }
    true
}

unsafe fn config_slice<'a>(bytes: *const u8, len: usize) -> &'a [u8] {
    if bytes.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(bytes, len) }
    }
}

/// Copy `bytes` into `out[..cap]`; return length or 0 if too small.
///
/// # Safety
/// `out` writable for `cap`.
unsafe fn emit(bytes: &[u8], out: *mut u8, cap: usize) -> usize {
    if bytes.len() > cap {
        return 0;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
    }
    bytes.len()
}

// ---- sismo.macos_cpu_samples -----------------------------------------------
// Fields: target_pid = 1, interval_us = 2 (both uint32 varint, omitted if 0).

/// # Safety
/// `out` writable for `cap`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_config_cpu_encode(
    target_pid: u32,
    interval_us: u32,
    out: *mut u8,
    cap: usize,
) -> usize {
    let mut w = ProtoWriter::new();
    if target_pid != 0 {
        w.write_uint32(1, target_pid);
    }
    if interval_us != 0 {
        w.write_uint32(2, interval_us);
    }
    unsafe { emit(w.bytes(), out, cap) }
}

/// # Safety
/// `bytes` valid for `len` or null; out-params writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_config_cpu_decode(
    bytes: *const u8,
    len: usize,
    out_target_pid: *mut u32,
    out_interval_us: *mut u32,
) -> bool {
    let (mut target_pid, mut interval_us) = (0u32, 0u32);
    let ok = decode_varint_fields(unsafe { config_slice(bytes, len) }, |field, val| match field {
        1 => target_pid = val as u32,
        2 => interval_us = val as u32,
        _ => {}
    });
    unsafe {
        *out_target_pid = target_pid;
        *out_interval_us = interval_us;
    }
    ok
}

// ---- sismo.heap ------------------------------------------------------------
// Fields: target_pid = 1 (u32), ring_size_bytes = 2 (u64), sample_interval = 3 (u64).

/// # Safety
/// `out` writable for `cap`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_config_heap_encode(
    target_pid: u32,
    ring_size_bytes: u64,
    sample_interval_bytes: u64,
    out: *mut u8,
    cap: usize,
) -> usize {
    let mut w = ProtoWriter::new();
    if target_pid != 0 {
        w.write_uint32(1, target_pid);
    }
    if ring_size_bytes != 0 {
        w.write_uint64(2, ring_size_bytes);
    }
    if sample_interval_bytes != 0 {
        w.write_uint64(3, sample_interval_bytes);
    }
    unsafe { emit(w.bytes(), out, cap) }
}

/// # Safety
/// `bytes` valid for `len` or null; out-params writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_config_heap_decode(
    bytes: *const u8,
    len: usize,
    out_target_pid: *mut u32,
    out_ring_size_bytes: *mut u64,
    out_sample_interval_bytes: *mut u64,
) -> bool {
    let (mut target_pid, mut ring_size, mut sample_interval) = (0u32, 0u64, 0u64);
    let ok = decode_varint_fields(unsafe { config_slice(bytes, len) }, |field, val| match field {
        1 => target_pid = val as u32,
        2 => ring_size = val,
        3 => sample_interval = val,
        _ => {}
    });
    unsafe {
        *out_target_pid = target_pid;
        *out_ring_size_bytes = ring_size;
        *out_sample_interval_bytes = sample_interval;
    }
    ok
}

// ---- sismo.macos_sched -----------------------------------------------------
// Field: kernel_buffer_events = 1 (int32, encoded as the i64 sign-extension so
// negatives round-trip).

/// # Safety
/// `out` writable for `cap`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_config_sched_encode(
    kernel_buffer_events: i32,
    out: *mut u8,
    cap: usize,
) -> usize {
    let mut w = ProtoWriter::new();
    if kernel_buffer_events != 0 {
        // int32 sign-extended to i64 then bit-cast to u64, so negatives round-trip.
        w.write_uint64(1, (kernel_buffer_events as i64) as u64);
    }
    unsafe { emit(w.bytes(), out, cap) }
}

/// # Safety
/// `bytes` valid for `len` or null; out-param writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_config_sched_decode(
    bytes: *const u8,
    len: usize,
    out_kernel_buffer_events: *mut i32,
) -> bool {
    let mut kernel_buffer_events = 0i32;
    let ok = decode_varint_fields(unsafe { config_slice(bytes, len) }, |field, val| {
        if field == 1 {
            kernel_buffer_events = (val as i64) as i32; // truncate back to i32
        }
    });
    unsafe {
        *out_kernel_buffer_events = kernel_buffer_events;
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpu_roundtrip(target_pid: u32, interval_us: u32) -> (u32, u32) {
        let mut out = [0u8; 64];
        let n = unsafe { sismo_config_cpu_encode(target_pid, interval_us, out.as_mut_ptr(), out.len()) };
        let (mut p, mut iv) = (0u32, 0u32);
        assert!(unsafe { sismo_config_cpu_decode(out.as_ptr(), n, &mut p, &mut iv) });
        (p, iv)
    }

    #[test]
    fn cpu_roundtrips() {
        assert_eq!(cpu_roundtrip(12345, 1000), (12345, 1000));
    }

    #[test]
    fn heap_roundtrips() {
        let mut out = [0u8; 64];
        let n = unsafe { sismo_config_heap_encode(777, 16 * 1024 * 1024, 4096, out.as_mut_ptr(), out.len()) };
        let (mut p, mut r, mut s) = (0u32, 0u64, 0u64);
        assert!(unsafe { sismo_config_heap_decode(out.as_ptr(), n, &mut p, &mut r, &mut s) });
        assert_eq!((p, r, s), (777, 16 * 1024 * 1024, 4096));
    }

    #[test]
    fn sched_roundtrips_including_negative() {
        for v in [256 * 1024i32, -5, 0] {
            let mut out = [0u8; 64];
            let n = unsafe { sismo_config_sched_encode(v, out.as_mut_ptr(), out.len()) };
            let mut got = 0i32;
            assert!(unsafe { sismo_config_sched_decode(out.as_ptr(), n, &mut got) });
            assert_eq!(got, v);
        }
    }

    #[test]
    fn cpu_encode_omits_zero_fields() {
        let mut out = [0u8; 64];
        let n = unsafe { sismo_config_cpu_encode(42, 0, out.as_mut_ptr(), out.len()) };
        // tag (1<<3|0)=0x08, varint 42 = 0x2A → 2 bytes only.
        assert_eq!(&out[..n], &[0x08, 0x2A]);
    }

    #[test]
    fn decode_skips_unknown_fields() {
        // Field 9 (varint 7), then field 1 (target_pid 42): 48 07 08 2A.
        let bytes = [0x48u8, 0x07, 0x08, 0x2A];
        let (mut p, mut iv) = (0u32, 0u32);
        assert!(unsafe { sismo_config_cpu_decode(bytes.as_ptr(), bytes.len(), &mut p, &mut iv) });
        assert_eq!(p, 42);
    }

    #[test]
    fn extract_finds_field_2000() {
        // DataSourceConfig: name(1)="x" then sismo_config(2000) = heap cfg.
        let mut inner = [0u8; 64];
        let inner_n = unsafe { sismo_config_heap_encode(99, 0, 0, inner.as_mut_ptr(), inner.len()) };
        let mut dsc = vec![0x0A, 0x01, b'x']; // name field 1, "x"
        // field 2000, wire 2: tag = 2000<<3|2 = 16002 = 0x3E82 -> varint 82 7D.
        dsc.extend_from_slice(&[0x82, 0x7D, inner_n as u8]);
        dsc.extend_from_slice(&inner[..inner_n]);

        let (mut off, mut len) = (0usize, 0usize);
        assert!(unsafe { sismo_config_extract(dsc.as_ptr(), dsc.len(), &mut off, &mut len) });
        let extracted = &dsc[off..off + len];
        let (mut p, mut r, mut s) = (0u32, 0u64, 0u64);
        assert!(unsafe { sismo_config_heap_decode(extracted.as_ptr(), extracted.len(), &mut p, &mut r, &mut s) });
        assert_eq!(p, 99);
    }

    #[test]
    fn extract_absent_returns_false() {
        let dsc = [0x0Au8, 0x01, b'x']; // only name, no field 2000
        let (mut off, mut len) = (0usize, 0usize);
        assert!(!unsafe { sismo_config_extract(dsc.as_ptr(), dsc.len(), &mut off, &mut len) });
    }
}
