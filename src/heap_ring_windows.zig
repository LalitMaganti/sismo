//! Windows stub for the heap-profiler shared-memory ring. The Windows
//! analog of POSIX `shm_open` + double-`mmap` mirror trick is
//! `CreateFileMappingW` + two `MapViewOfFileEx` calls into a region
//! pre-reserved with `VirtualAlloc(MEM_RESERVE)` (then released and
//! immediately re-mapped — there is no Windows equivalent of `MAP_FIXED`
//! over a pre-reserved range that survives the unmap).
//!
//! Not implemented yet — this file exists so `heap_ring.zig`'s per-OS
//! dispatch compiles when targeting Windows.

const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .windows) {
        @compileError("heap_ring_windows is Windows-only; import heap_ring.zig instead");
    }
}

pub const HEADER_BYTES: usize = 8;
pub const RECORD_ALIGN: usize = 8;

pub const RingError = error{
    Unimplemented,
    InvalidSize,
};

pub const MetadataPage = extern struct {
    spinlock: u32,
    _pad0: u32,
    write_pos: u64 align(8),
    read_pos: u64 align(8),
    bytes_written: u64 align(8),
    num_writes_succeeded: u64 align(8),
    num_writes_overflow: u64 align(8),
    num_reads_succeeded: u64 align(8),
    num_reads_nodata: u64 align(8),
    failed_spinlocks: u64 align(8),
    shutting_down: u32 align(8),
    _pad1: u32,
};

pub const RingBuffer = struct {
    handle: usize,
    region: [*]u8,
    region_bytes: usize,
    meta: *MetadataPage,
    data: [*]u8,
    size: u64,
    size_mask: u64,
    page_size: usize,

    pub fn create(ring_size: u64) !RingBuffer {
        _ = ring_size;
        return error.Unimplemented;
    }

    pub fn attach(handle: usize, ring_size: u64) !RingBuffer {
        _ = handle;
        _ = ring_size;
        return error.Unimplemented;
    }

    pub fn destroy(self: *RingBuffer) void {
        self.* = undefined;
    }

    pub fn beginWrite(self: *RingBuffer, payload_size: usize) ?[]u8 {
        _ = self;
        _ = payload_size;
        return null;
    }

    pub fn endWrite(self: *RingBuffer, slice: []u8) void {
        _ = self;
        _ = slice;
    }

    pub fn beginRead(self: *RingBuffer) ?[]const u8 {
        _ = self;
        return null;
    }

    pub fn endRead(self: *RingBuffer, slice: []const u8) void {
        _ = self;
        _ = slice;
    }

    pub fn signalShutdown(self: *RingBuffer) void {
        _ = self;
    }
};
