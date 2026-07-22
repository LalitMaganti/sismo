// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! macOS memory-map snapshot as a Perfetto `SmapsPacket`.
//!
//! Walks the target's VM regions via `mach_vm_region_recurse` (the vmmap
//! primitive) and serializes one `SmapsEntry` per top-level region into a
//! Trace-wrapped packet, ready to be appended to a trace file verbatim.
//! trace_processor ingests it into the `profiler_smaps` table keyed by the
//! packet timestamp. Not wired to a data source yet: this is the building
//! block for the planned periodic smaps poll in `sismo record`.
//!
//! Fidelity notes vs Linux smaps: macOS has no PSS, so
//! `proportional_resident_kb` carries plain resident; dirty pages aren't split
//! private/shared by the kernel, so the whole dirty count lands on whichever
//! side `share_mode` assigns the region.

use crate::mach::{mach_port_deallocate, mach_task_self_, MachPort, KERN_SUCCESS};
use crate::proto::ProtoWriter;
use std::os::raw::{c_int, c_void};

// TracePacket framing (see privileged_marker for the same constants).
const TRACE_FIELD_PACKET: u32 = 1;
const TP_FIELD_TIMESTAMP: u32 = 8;
const TP_FIELD_TRUSTED_PACKET_SEQUENCE_ID: u32 = 10;
const TP_FIELD_TIMESTAMP_CLOCK_ID: u32 = 58;
const TP_FIELD_SMAPS_PACKET: u32 = 68;
const BUILTIN_CLOCK_BOOTTIME: u32 = 6;

// SmapsPacket / SmapsEntry fields.
const SP_FIELD_PID: u32 = 1;
const SP_FIELD_ENTRIES: u32 = 2;
const SE_FIELD_PATH: u32 = 1;
const SE_FIELD_SIZE_KB: u32 = 2;
const SE_FIELD_PRIVATE_DIRTY_KB: u32 = 3;
const SE_FIELD_SWAP_KB: u32 = 4;
const SE_FIELD_START_ADDRESS: u32 = 6;
const SE_FIELD_PROTECTION_FLAGS: u32 = 10;
const SE_FIELD_PRIVATE_CLEAN_RESIDENT_KB: u32 = 11;
const SE_FIELD_SHARED_DIRTY_RESIDENT_KB: u32 = 12;
const SE_FIELD_SHARED_CLEAN_RESIDENT_KB: u32 = 13;
const SE_FIELD_PROPORTIONAL_RESIDENT_KB: u32 = 15;

// A sequence id for packets appended post-hoc; distinct from live producers
// and from the privileged-marker writer.
const SMAPS_SEQUENCE_ID: u32 = 0xD0D0_CAFE;

// mach/vm_region.h `struct vm_region_submap_info_64` (v2), `#pragma pack(4)`.
const VM_REGION_SUBMAP_INFO_COUNT_64: u32 = 19; // sizeof / sizeof(natural_t)

#[repr(C, packed(4))]
#[derive(Default, Clone, Copy)]
struct VmRegionSubmapInfo64 {
    protection: i32,
    max_protection: i32,
    inheritance: u32,
    offset: u64,
    user_tag: u32,
    pages_resident: u32,
    pages_shared_now_private: u32,
    pages_swapped_out: u32,
    pages_dirtied: u32,
    ref_count: u32,
    shadow_depth: u16,
    external_pager: u8,
    share_mode: u8,
    is_submap: u32,
    behavior: i32,
    object_id: u32,
    user_wired_count: u16,
    flags: u16,
    pages_reusable: u32,
    object_id_full: u64,
}

// share_mode values (mach/vm_region.h).
const SM_PRIVATE: u8 = 2;
const SM_COW: u8 = 1;
const SM_PRIVATE_ALIASED: u8 = 6;

extern "C" {
    fn mach_vm_region_recurse(
        target_task: MachPort,
        address: *mut u64,
        size: *mut u64,
        nesting_depth: *mut u32,
        info: *mut c_void,
        info_count: *mut u32,
    ) -> i32;
    // libproc.h — resolves the backing file of a mapped region, if any.
    fn proc_regionfilename(pid: c_int, address: u64, buffer: *mut c_void, buffersize: u32) -> c_int;
}

/// One region's worth of numbers, in kb. Split out of the walk for testability
/// of the entry serialization.
struct Region {
    start: u64,
    size_kb: u64,
    private_dirty_kb: u64,
    private_clean_kb: u64,
    shared_dirty_kb: u64,
    shared_clean_kb: u64,
    swap_kb: u64,
    resident_kb: u64,
    protection: u32,
    path: String,
}

fn region_from_info(start: u64, size: u64, info: &VmRegionSubmapInfo64, page_kb: u64, path: String) -> Region {
    let resident_kb = info.pages_resident as u64 * page_kb;
    let dirty_kb = (info.pages_dirtied as u64 * page_kb).min(resident_kb);
    let clean_kb = resident_kb - dirty_kb;
    let private = matches!(info.share_mode, SM_PRIVATE | SM_COW | SM_PRIVATE_ALIASED);
    Region {
        start,
        size_kb: size / 1024,
        private_dirty_kb: if private { dirty_kb } else { 0 },
        private_clean_kb: if private { clean_kb } else { 0 },
        shared_dirty_kb: if private { 0 } else { dirty_kb },
        shared_clean_kb: if private { 0 } else { clean_kb },
        swap_kb: info.pages_swapped_out as u64 * page_kb,
        resident_kb,
        protection: info.protection as u32,
        path,
    }
}

fn write_entry(packet: &mut ProtoWriter, r: &Region) {
    let mut e = ProtoWriter::new();
    e.write_string(SE_FIELD_PATH, r.path.as_bytes());
    e.write_uint64(SE_FIELD_SIZE_KB, r.size_kb);
    e.write_uint64(SE_FIELD_PRIVATE_DIRTY_KB, r.private_dirty_kb);
    e.write_uint64(SE_FIELD_SWAP_KB, r.swap_kb);
    e.write_uint64(SE_FIELD_START_ADDRESS, r.start);
    e.write_uint32(SE_FIELD_PROTECTION_FLAGS, r.protection);
    e.write_uint64(SE_FIELD_PRIVATE_CLEAN_RESIDENT_KB, r.private_clean_kb);
    e.write_uint64(SE_FIELD_SHARED_DIRTY_RESIDENT_KB, r.shared_dirty_kb);
    e.write_uint64(SE_FIELD_SHARED_CLEAN_RESIDENT_KB, r.shared_clean_kb);
    e.write_uint64(SE_FIELD_PROPORTIONAL_RESIDENT_KB, r.resident_kb);
    packet.write_message(SP_FIELD_ENTRIES, e.bytes());
}

fn region_path(pid: i32, address: u64) -> String {
    let mut buf = [0u8; 1024]; // MAXPATHLEN
    let n = unsafe { proc_regionfilename(pid, address, buf.as_mut_ptr() as *mut c_void, buf.len() as u32) };
    if n > 0 {
        String::from_utf8_lossy(&buf[..n as usize]).into_owned()
    } else {
        String::new()
    }
}

/// Walk `pid`'s VM regions and build a Trace-wrapped SmapsPacket stamped at
/// `timestamp_ns` (CLOCK_MONOTONIC, labeled BOOTTIME like the rest of the
/// trace). `None` if the task port is unavailable (needs the debugger
/// entitlement or root) or the walk yields nothing.
pub fn smaps_trace_packet(pid: i32, timestamp_ns: u64) -> Option<Vec<u8>> {
    let mut task: MachPort = 0;
    if unsafe { libc::task_for_pid(mach_task_self_, pid, &mut task) } != KERN_SUCCESS {
        return None;
    }

    let page_kb = (unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64) / 1024;
    let mut packet = ProtoWriter::new();
    packet.write_uint32(SP_FIELD_PID, pid as u32);

    let mut address: u64 = 0;
    let mut depth: u32 = 0;
    let mut entries = 0usize;
    loop {
        let mut size: u64 = 0;
        let mut info = VmRegionSubmapInfo64::default();
        let mut count = VM_REGION_SUBMAP_INFO_COUNT_64;
        let rc = unsafe {
            mach_vm_region_recurse(
                task,
                &mut address,
                &mut size,
                &mut depth,
                &mut info as *mut _ as *mut c_void,
                &mut count,
            )
        };
        if rc != KERN_SUCCESS {
            break;
        }
        if info.is_submap != 0 {
            // Descend: re-query the same address one level deeper.
            depth += 1;
            continue;
        }
        let mut path = region_path(pid, address);
        if path.is_empty() {
            path = format!("[anon:{}]", info.user_tag);
        }
        write_entry(&mut packet, &region_from_info(address, size, &info, page_kb, path));
        entries += 1;
        address = address.saturating_add(size);
        if size == 0 {
            break; // defensive: never spin on a zero-length region
        }
    }
    unsafe { mach_port_deallocate(mach_task_self_, task) };
    if entries == 0 {
        return None;
    }

    let mut tp = ProtoWriter::new();
    tp.write_uint64(TP_FIELD_TIMESTAMP, timestamp_ns);
    tp.write_uint32(TP_FIELD_TIMESTAMP_CLOCK_ID, BUILTIN_CLOCK_BOOTTIME);
    tp.write_uint32(TP_FIELD_TRUSTED_PACKET_SEQUENCE_ID, SMAPS_SEQUENCE_ID);
    tp.write_message(TP_FIELD_SMAPS_PACKET, packet.bytes());

    let mut trace = ProtoWriter::new();
    trace.write_message(TRACE_FIELD_PACKET, tp.bytes());
    Some(trace.bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submap_info_layout_matches_header() {
        // pack(4) layout: 76 bytes total, count 19 natural_t's.
        assert_eq!(std::mem::size_of::<VmRegionSubmapInfo64>(), 76);
        assert_eq!(VM_REGION_SUBMAP_INFO_COUNT_64 as usize * 4, 76);
    }

    #[test]
    fn region_split_private_vs_shared() {
        let mut info = VmRegionSubmapInfo64::default();
        info.pages_resident = 10;
        info.pages_dirtied = 4;
        info.share_mode = SM_PRIVATE;
        let r = region_from_info(0x1000, 16 * 16384, &info, 16, "x".into());
        assert_eq!(r.size_kb, 256);
        assert_eq!(r.private_dirty_kb, 64);
        assert_eq!(r.private_clean_kb, 96);
        assert_eq!(r.shared_dirty_kb, 0);

        info.share_mode = 4; // SM_SHARED
        let r = region_from_info(0x1000, 16 * 16384, &info, 16, "x".into());
        assert_eq!(r.private_dirty_kb, 0);
        assert_eq!(r.shared_dirty_kb, 64);
        assert_eq!(r.shared_clean_kb, 96);
    }

    #[test]
    fn self_walk_produces_a_packet() {
        // Walking our own process needs no entitlement.
        let pid = unsafe { libc::getpid() };
        let pkt = smaps_trace_packet(pid, 42).expect("walk self");
        // Trace-wrapped: starts with field 1, wire type 2 (0x0a).
        assert_eq!(pkt[0], 0x0a);
        assert!(pkt.len() > 64, "expected multiple entries, got {} bytes", pkt.len());
    }
}
