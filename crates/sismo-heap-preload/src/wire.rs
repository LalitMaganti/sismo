// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Wire-format record types for the heap IPC. The layout is the ABI contract
//! between this preload (producer) and the recorder (consumer, sismo-core's
//! heap::macos_heap_capture) — it must stay byte-exact.

/// Max register-block size across architectures, padded (arm64: 33×u64=264 →
/// 272) to absorb future archs without an ABI break.
pub const MAX_REGISTER_DATA_BYTES: usize = 272;

/// Bytes of stack copied on each captured allocation (heapprofd's default).
pub const STACK_SNAPSHOT_BYTES: usize = 8192;

/// Architecture tag written into `AllocMetadata.arch`.
#[repr(u32)]
#[allow(dead_code)]
pub enum Arch {
    Unknown = 0,
    Arm64 = 1,
    X86_64 = 2,
    Arm = 3,
    Riscv64 = 4,
    Arm64e = 5,
}

/// Allocation record header (same shape as heapprofd's AllocMetadata), followed
/// in the ring by `STACK_SNAPSHOT_BYTES` of raw stack for the consumer to unwind.
#[repr(C)]
pub struct AllocMetadata {
    pub sequence_number: u64,
    pub alloc_size: u64,
    pub sample_size: u64,
    pub alloc_address: u64,
    pub stack_pointer: u64,
    pub clock_monotonic_coarse_ts: u64,
    pub register_data: [u8; MAX_REGISTER_DATA_BYTES],
    pub heap_id: u32,
    pub arch: u32,
}

/// register_data layout for arm64 (sismo convention): pc @0, lr @8, fp @16.
#[repr(C)]
pub struct RegBlockArm64 {
    pub pc: u64,
    pub lr: u64,
    pub fp: u64,
    pub _padding: u64,
}

// ABI drift guards — the recorder decodes AllocMetadata by these exact offsets.
const _: () = assert!(std::mem::size_of::<AllocMetadata>() == 328);
const _: () = assert!(std::mem::align_of::<AllocMetadata>() == 8);
const _: () = assert!(std::mem::size_of::<RegBlockArm64>() == 32);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_offsets_match_the_wire_contract() {
        // The recorder (macos_heap_capture.rs) reads these fixed offsets.
        let base = std::ptr::null::<AllocMetadata>() as usize;
        let off = |p: *const u8| p as usize - base;
        let m = std::ptr::null::<AllocMetadata>();
        unsafe {
            assert_eq!(off(std::ptr::addr_of!((*m).sample_size) as *const u8), 16);
            assert_eq!(off(std::ptr::addr_of!((*m).alloc_address) as *const u8), 24);
            assert_eq!(off(std::ptr::addr_of!((*m).stack_pointer) as *const u8), 32);
            assert_eq!(off(std::ptr::addr_of!((*m).register_data) as *const u8), 48);
            assert_eq!(off(std::ptr::addr_of!((*m).heap_id) as *const u8), 320);
            assert_eq!(off(std::ptr::addr_of!((*m).arch) as *const u8), 324);
        }
    }
}
