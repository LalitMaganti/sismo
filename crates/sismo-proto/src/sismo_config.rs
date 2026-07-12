// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Sismo data-source config wire format. One encode + decode per producer
//! (macos_cpu_samples, heap, macos_sched), plus extraction of the config
//! bytes from Perfetto's `DataSourceConfig`.
//!
//! All configs ride at vendor-extension field 2000 of `DataSourceConfig`.
//! See protos/sismo_config.proto.

use crate::{ProtoReader, ProtoWriter, WireValue};

/// Field on Perfetto's `DataSourceConfig` carrying sismo's config bytes.
const DSC_SISMO_CONFIG_FIELD: u32 = 2000;

/// The `DataSourceConfig.sismo_config` sub-slice (field 2000, length-delimited)
/// inside a serialized DataSourceConfig, or `None` if absent.
pub fn config_extract(dsc: &[u8]) -> Option<&[u8]> {
    ProtoReader::new(dsc).find_map(|(field, val)| match (field, val) {
        (DSC_SISMO_CONFIG_FIELD, WireValue::Len(bytes)) => Some(bytes),
        _ => None,
    })
}

/// Invoke `f(field_num, value)` for each varint field of a config message
/// (non-varint fields are skipped; a truncated tail just ends the walk).
fn each_varint_field(bytes: &[u8], mut f: impl FnMut(u32, u64)) {
    for (field, val) in ProtoReader::new(bytes) {
        if let WireValue::Varint(v) = val {
            f(field, v);
        }
    }
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

/// Decodes `(target_pid, interval_us)` (0 for absent fields).
pub fn cpu_decode(bytes: &[u8]) -> (u32, u32) {
    let (mut target_pid, mut interval_us) = (0u32, 0u32);
    each_varint_field(bytes, |field, val| match field {
        1 => target_pid = val as u32,
        2 => interval_us = val as u32,
        _ => {}
    });
    (target_pid, interval_us)
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

/// Decodes `(target_pid, ring_size_bytes, sample_interval_bytes)` (0 for absent).
pub fn heap_decode(bytes: &[u8]) -> (u32, u64, u64) {
    let (mut target_pid, mut ring_size, mut sample_interval) = (0u32, 0u64, 0u64);
    each_varint_field(bytes, |field, val| match field {
        1 => target_pid = val as u32,
        2 => ring_size = val,
        3 => sample_interval = val,
        _ => {}
    });
    (target_pid, ring_size, sample_interval)
}

// ---- sismo.macos_sched -----------------------------------------------------
// Fields: kernel_buffer_events = 1 (int32, encoded as the i64 sign-extension so
// negatives round-trip), target_pid = 2 (uint32), offcpu_wait_threshold_us = 3
// (uint32). A non-zero target_pid enables kperf lazy.wait off-CPU capture for
// that pid on the shared kdebug session; threshold 0 lets the worker default it.

pub fn sched_encode(kernel_buffer_events: i32, target_pid: u32, offcpu_wait_threshold_us: u32) -> Vec<u8> {
    let mut w = ProtoWriter::new();
    if kernel_buffer_events != 0 {
        // int32 sign-extended to i64 then bit-cast to u64, so negatives round-trip.
        w.write_uint64(1, (kernel_buffer_events as i64) as u64);
    }
    if target_pid != 0 {
        w.write_uint32(2, target_pid);
    }
    if offcpu_wait_threshold_us != 0 {
        w.write_uint32(3, offcpu_wait_threshold_us);
    }
    w.bytes().to_vec()
}

/// Decodes `(kernel_buffer_events, target_pid, offcpu_wait_threshold_us)`
/// (0 for absent fields).
pub fn sched_decode(bytes: &[u8]) -> (i32, u32, u32) {
    let (mut kbe, mut target_pid, mut threshold_us) = (0i32, 0u32, 0u32);
    each_varint_field(bytes, |field, val| match field {
        1 => kbe = (val as i64) as i32, // truncate back to i32
        2 => target_pid = val as u32,
        3 => threshold_us = val as u32,
        _ => {}
    });
    (kbe, target_pid, threshold_us)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_roundtrips() {
        assert_eq!(cpu_decode(&cpu_encode(12345, 1000)), (12345, 1000));
    }

    #[test]
    fn heap_roundtrips() {
        let bytes = heap_encode(777, 16 * 1024 * 1024, 4096);
        assert_eq!(heap_decode(&bytes), (777, 16 * 1024 * 1024, 4096));
    }

    #[test]
    fn sched_roundtrips_including_negative() {
        for v in [256 * 1024i32, -5, 0] {
            assert_eq!(sched_decode(&sched_encode(v, 0, 0)), (v, 0, 0));
        }
        // target_pid + threshold round-trip alongside the buffer size.
        assert_eq!(sched_decode(&sched_encode(-5, 4242, 500)), (-5, 4242, 500));
    }

    #[test]
    fn cpu_encode_omits_zero_fields() {
        // tag (1<<3|0)=0x08, varint 42 = 0x2A → 2 bytes only.
        assert_eq!(cpu_encode(42, 0), &[0x08, 0x2A]);
    }

    #[test]
    fn decode_skips_unknown_fields() {
        // Field 9 (varint 7), then field 1 (target_pid 42): 48 07 08 2A.
        let (p, _) = cpu_decode(&[0x48, 0x07, 0x08, 0x2A]);
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
        assert_eq!(heap_decode(extracted), (99, 0, 0));
    }

    #[test]
    fn extract_absent_is_none() {
        let dsc = [0x0Au8, 0x01, b'x']; // only name, no field 2000
        assert!(config_extract(&dsc).is_none());
    }
}
