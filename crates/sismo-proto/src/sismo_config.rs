// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Sismo data-source config wire format. One encode + decode per producer
//! (macos_cpu_samples, heap, macos_sched), plus extraction of the config
//! bytes from Perfetto's `DataSourceConfig`.
//!
//! All configs ride at vendor-extension field 2000 of `DataSourceConfig`.
//! See protos/sismo_config.proto.

use crate::ProtoWriter;

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

/// The `DataSourceConfig.sismo_config` sub-slice (field 2000, length-delimited)
/// inside a serialized DataSourceConfig, or `None` if absent or malformed.
pub fn config_extract(dsc: &[u8]) -> Option<&[u8]> {
    let mut i = 0usize;
    while i < dsc.len() {
        let (tag, consumed) = read_varint(&dsc[i..])?;
        i += consumed;
        let field_num = tag >> 3;
        let wire_type = tag & 0x07;
        if field_num == DSC_SISMO_CONFIG_FIELD && wire_type == WIRE_LEN {
            let (len, c) = read_varint(&dsc[i..])?;
            i += c;
            let end = i.checked_add(len as usize).filter(|&e| e <= dsc.len())?;
            return Some(&dsc[i..end]);
        }
        i += skip_field(wire_type, &dsc[i..])?;
    }
    None
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

// ---- sismo.macos_cpu_samples -----------------------------------------------
// Fields: target_pid = 1, interval_us = 2 (both uint32 varint, omitted if 0).

pub fn cpu_encode(target_pid: u32, interval_us: u32) -> Vec<u8> {
    let mut w = ProtoWriter::new();
    if target_pid != 0 {
        w.write_uint32(1, target_pid);
    }
    if interval_us != 0 {
        w.write_uint32(2, interval_us);
    }
    w.bytes().to_vec()
}

/// Returns `(target_pid, interval_us)`, or `None` on malformed input.
pub fn cpu_decode(bytes: &[u8]) -> Option<(u32, u32)> {
    let (mut target_pid, mut interval_us) = (0u32, 0u32);
    decode_varint_fields(bytes, |field, val| match field {
        1 => target_pid = val as u32,
        2 => interval_us = val as u32,
        _ => {}
    })
    .then_some((target_pid, interval_us))
}

// ---- sismo.heap ------------------------------------------------------------
// Fields: target_pid = 1 (u32), ring_size_bytes = 2 (u64), sample_interval = 3 (u64).

pub fn heap_encode(target_pid: u32, ring_size_bytes: u64, sample_interval_bytes: u64) -> Vec<u8> {
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
    w.bytes().to_vec()
}

/// Returns `(target_pid, ring_size_bytes, sample_interval_bytes)`, or `None` on
/// malformed input.
pub fn heap_decode(bytes: &[u8]) -> Option<(u32, u64, u64)> {
    let (mut target_pid, mut ring_size, mut sample_interval) = (0u32, 0u64, 0u64);
    decode_varint_fields(bytes, |field, val| match field {
        1 => target_pid = val as u32,
        2 => ring_size = val,
        3 => sample_interval = val,
        _ => {}
    })
    .then_some((target_pid, ring_size, sample_interval))
}

// ---- sismo.macos_sched -----------------------------------------------------
// Field: kernel_buffer_events = 1 (int32, encoded as the i64 sign-extension so
// negatives round-trip).

pub fn sched_encode(kernel_buffer_events: i32) -> Vec<u8> {
    let mut w = ProtoWriter::new();
    if kernel_buffer_events != 0 {
        // int32 sign-extended to i64 then bit-cast to u64, so negatives round-trip.
        w.write_uint64(1, (kernel_buffer_events as i64) as u64);
    }
    w.bytes().to_vec()
}

/// Returns `kernel_buffer_events`, or `None` on malformed input.
pub fn sched_decode(bytes: &[u8]) -> Option<i32> {
    let mut kernel_buffer_events = 0i32;
    decode_varint_fields(bytes, |field, val| {
        if field == 1 {
            kernel_buffer_events = (val as i64) as i32; // truncate back to i32
        }
    })
    .then_some(kernel_buffer_events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_roundtrips() {
        assert_eq!(cpu_decode(&cpu_encode(12345, 1000)), Some((12345, 1000)));
    }

    #[test]
    fn heap_roundtrips() {
        let bytes = heap_encode(777, 16 * 1024 * 1024, 4096);
        assert_eq!(heap_decode(&bytes), Some((777, 16 * 1024 * 1024, 4096)));
    }

    #[test]
    fn sched_roundtrips_including_negative() {
        for v in [256 * 1024i32, -5, 0] {
            assert_eq!(sched_decode(&sched_encode(v)), Some(v));
        }
    }

    #[test]
    fn cpu_encode_omits_zero_fields() {
        // tag (1<<3|0)=0x08, varint 42 = 0x2A → 2 bytes only.
        assert_eq!(cpu_encode(42, 0), &[0x08, 0x2A]);
    }

    #[test]
    fn decode_skips_unknown_fields() {
        // Field 9 (varint 7), then field 1 (target_pid 42): 48 07 08 2A.
        let (p, _) = cpu_decode(&[0x48, 0x07, 0x08, 0x2A]).unwrap();
        assert_eq!(p, 42);
    }

    #[test]
    fn extract_finds_field_2000() {
        // DataSourceConfig: name(1)="x" then sismo_config(2000) = heap cfg.
        let inner = heap_encode(99, 0, 0);
        let mut dsc = vec![0x0A, 0x01, b'x']; // name field 1, "x"
        // field 2000, wire 2: tag = 2000<<3|2 = 16002 = 0x3E82 -> varint 82 7D.
        dsc.extend_from_slice(&[0x82, 0x7D, inner.len() as u8]);
        dsc.extend_from_slice(&inner);

        let extracted = config_extract(&dsc).expect("field 2000");
        assert_eq!(heap_decode(extracted), Some((99, 0, 0)));
    }

    #[test]
    fn extract_absent_is_none() {
        let dsc = [0x0Au8, 0x01, b'x']; // only name, no field 2000
        assert!(config_extract(&dsc).is_none());
    }
}
