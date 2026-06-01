// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Wire-format record types for the sismo heap profiler IPC. Layouts
//! mirror heapprofd's `wire_protocol.h` closely (same fields, same
//! ordering, same atomicity rules) — see plans/05-heap-research.md.
//!
//! ABI stability: the structs are `extern` with explicit alignment so
//! they're invariant across Zig versions and identical between the
//! in-process client (producer) and the orchestrator (consumer), which
//! are the contract. They are NOT necessarily byte-identical to
//! heapprofd's structs.

const std = @import("std");

/// Discriminator at the start of every wire record (after the size
/// header that the ring buffer adds).
pub const RecordType = enum(u64) {
    free = 0,
    malloc = 1,
    heap_name = 2,
};

/// Max register-block size across supported architectures, rounded up
/// to absorb arm64e + future archs without an ABI break. arm64: 33 ×
/// u64 = 264 bytes; x86_64: 17 × u64 = 136 bytes; padded to 272.
pub const MAX_REGISTER_DATA_BYTES: usize = 272;

/// Architecture tag — written into AllocMetadata.arch so the consumer
/// knows how to decode the register block for unwinding.
pub const Arch = enum(u32) {
    unknown = 0,
    arm64 = 1,
    x86_64 = 2,
    arm = 3,
    riscv64 = 4,
    arm64e = 5,
};

/// Allocation record header. Same shape as heapprofd's AllocMetadata.
/// Followed in the ring by `record.size − @sizeOf(AllocMetadata)` raw
/// stack bytes the consumer feeds to framehop.
pub const AllocMetadata = extern struct {
    /// Monotonically increasing across all records on the ring (set
    /// under the ring's spinlock at BeginWrite). Lets the consumer
    /// pair frees with their allocs and detect dropped records.
    sequence_number: u64 align(8),
    /// Size requested from malloc (the actual user-visible size).
    alloc_size: u64 align(8),
    /// Sampling-weighted size: `alloc_size × (1 / sample_probability)`.
    /// Equal to alloc_size when not sampling.
    sample_size: u64 align(8),
    /// Pointer returned by malloc (or 0 for non-allocating record kinds).
    alloc_address: u64 align(8),
    /// SP at the intercept site — anchor for the stack snapshot.
    stack_pointer: u64 align(8),
    /// CLOCK_MONOTONIC_COARSE timestamp in ns.
    clock_monotonic_coarse_ts: u64 align(8),
    /// Architecture-specific register block. Only the leading
    /// `arch_register_bytes(arch)` are meaningful.
    register_data: [MAX_REGISTER_DATA_BYTES]u8 align(8),
    /// Identifies the heap this allocation is from (for the
    /// custom-allocator-API case). 0 = libc malloc.
    heap_id: u32 align(8),
    arch: Arch,
};

/// Free record. No stack snapshot — frees aren't profiled deeply,
/// they're just paired against the prior alloc by `addr`.
pub const FreeEntry = extern struct {
    sequence_number: u64 align(8),
    addr: u64 align(8),
    heap_id: u32 align(8),
};

/// Heap registration. Sent once per heap when a custom allocator
/// calls `sismo_heap_register(name, sample_interval)`.
pub const HEAP_NAME_BYTES: usize = 64;
pub const HeapName = extern struct {
    sample_interval: u64 align(8),
    heap_id: u32 align(8),
    heap_name: [HEAP_NAME_BYTES]u8,
};

// Compile-time assertions that catch ABI drift across Zig versions.
comptime {
    // 6 × u64 = 48; register block 272; heap_id+arch with 8-byte align
    // constraint = 8. Total 328.
    if (@sizeOf(AllocMetadata) != 328) {
        @compileError(std.fmt.comptimePrint(
            "AllocMetadata must be 328 bytes for ABI stability, got {d}",
            .{@sizeOf(AllocMetadata)},
        ));
    }
    if (@sizeOf(FreeEntry) != 24) {
        @compileError(std.fmt.comptimePrint(
            "FreeEntry must be 24 bytes for ABI stability, got {d}",
            .{@sizeOf(FreeEntry)},
        ));
    }
    if (@sizeOf(HeapName) != 80) {
        @compileError(std.fmt.comptimePrint(
            "HeapName must be 80 bytes for ABI stability, got {d}",
            .{@sizeOf(HeapName)},
        ));
    }
}
