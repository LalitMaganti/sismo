//! Shared-memory ring buffer for sismo heap profiler IPC. Layout and
//! algorithm follow heapprofd's `shared_ring_buffer.{h,cc}` closely:
//!
//!   [ MetadataPage (1 page) ][ data (ring_size B) ][ data MIRROR (ring_size B) ]
//!
//! The double-mmap trick: the data region is mapped twice consecutively
//! in virtual address space, both backed by the same offset of the same
//! shm fd. Records that wrap around `ring_size` are transparently
//! contiguous from the writer's and reader's POV — no split-record
//! handling code anywhere. Cost: one extra mmap call at setup.
//!
//! Per-record layout in the ring (heapprofd-compatible):
//!
//!   [ size: atomic u32, padded to 8 ][ payload: aligned to 8 ]
//!
//! Writer writes the payload first, then RELEASE-stores the size.
//! Reader ACQUIRE-loads the size; size == 0 ⇒ writer hasn't published
//! yet (try again later). This synchronizes the whole record without
//! per-byte memory ordering.

const std = @import("std");
const builtin = @import("builtin");

comptime {
    // POSIX shm_open + mmap. Windows analog is CreateFileMapping +
    // MapViewOfFile; lives in a sibling module once we get there.
    if (builtin.os.tag == .windows) {
        @compileError("heap_ring is POSIX-only; Windows analog TBD");
    }
}

const PROT_RW: std.c.PROT = .{ .READ = true, .WRITE = true };
const PROT_NONE: std.c.PROT = .{};

/// Per-record header in the ring. Just the size atomically published.
/// 8-byte slot so records stay 8-aligned.
pub const HEADER_BYTES: usize = 8;

/// Alignment for record layout inside the ring (= sizeof header).
pub const RECORD_ALIGN: usize = 8;

inline fn alignUp(n: usize, a: usize) usize {
    return (n + a - 1) & ~(a - 1);
}

pub const RingError = error{
    ShmCreate,
    Truncate,
    ReserveAddrSpace,
    MmapMeta,
    MmapMirror,
    InvalidSize,
};

/// Header at offset 0 of the shm region. One page total. Holds the
/// spinlock + r/w cursors + drop counters. ABI-stable on a single OS
/// (we don't promise cross-OS layout for the metadata page yet).
pub const MetadataPage = extern struct {
    /// 0 = unlocked, 1 = locked. 8-byte aligned to keep the rest of
    /// the page on the right cache line.
    spinlock: u32,
    _pad0: u32,
    /// Producer-advanced (under spinlock). Bytes written into the
    /// ring (modulo size_mask in `at()`).
    write_pos: u64 align(8),
    /// Consumer-advanced. Always <= write_pos.
    read_pos: u64 align(8),

    /// Counters (mostly for diagnostics).
    bytes_written: u64 align(8),
    num_writes_succeeded: u64 align(8),
    num_writes_overflow: u64 align(8),
    num_reads_succeeded: u64 align(8),
    num_reads_nodata: u64 align(8),
    failed_spinlocks: u64 align(8),

    /// Atomic shutdown bool. Written by sismo orchestrator, polled by
    /// the producer side's spinlock loop to break out.
    shutting_down: u32 align(8),
    _pad1: u32,
};

pub const RingBuffer = struct {
    fd: c_int,
    /// Outer mmap'd region that we own. Layout:
    /// `[ meta (page) ][ data (size) ][ mirror (size) ]`.
    region: [*]u8,
    region_bytes: usize,

    meta: *MetadataPage,
    /// First byte of the data (and mirror) region.
    data: [*]u8,
    /// Power of two. Used for `& size_mask` index computation.
    size: u64,
    size_mask: u64,

    page_size: usize,

    /// Create a new shm + ring of `ring_size` data bytes (must be a
    /// power of two ≥ one page). The shm is anonymous (unlinked
    /// immediately after creation; only the fd keeps it alive — that
    /// fd can later be SCM_RIGHTS-passed to the consumer).
    pub fn create(ring_size: u64) !RingBuffer {
        const page_size = std.heap.pageSize();

        if (ring_size == 0 or (ring_size & (ring_size - 1)) != 0) return error.InvalidSize;
        if (ring_size < page_size) return error.InvalidSize;

        // shm_open with a unique name, then unlink immediately so it's
        // anonymous (lifetime tied to the fd). macOS limits posix shm
        // names to 31 chars (PSHMNAMLEN); keep it tight.
        var name_buf: [32]u8 = undefined;
        var ts: std.c.timespec = undefined;
        _ = std.c.clock_gettime(.MONOTONIC, &ts);
        const ts_lo: u32 = @truncate(@as(u64, @intCast(ts.nsec)));
        const pid: i32 = std.c.getpid();
        // "/smh_<pid>_<ts_lo_hex>" → max 5 + 6 + 1 + 8 = 20 chars
        const name = try std.fmt.bufPrintZ(
            &name_buf,
            "/smh_{d}_{x}",
            .{ pid, ts_lo },
        );
        // shm_open is variadic on Darwin (Apple ARM64 ABI requires the
        // mode arg on the stack); std.c.shm_open declares it variadic
        // so the call here passes mode through as a vararg. The flags
        // type is c_int rather than std.c.O — bitcast the O struct.
        const flags: std.c.O = .{ .ACCMODE = .RDWR, .CREAT = true, .EXCL = true };
        const fd = std.c.shm_open(name.ptr, @bitCast(flags), @as(c_uint, 0o600));
        if (fd < 0) return error.ShmCreate;
        errdefer _ = std.c.close(fd);
        _ = std.c.shm_unlink(name.ptr);

        const file_size: usize = page_size + @as(usize, @intCast(ring_size));
        if (std.c.ftruncate(fd, @intCast(file_size)) != 0) return error.Truncate;

        return try mapInto(fd, ring_size, page_size, file_size);
    }

    /// Attach to an existing shm fd (e.g., one passed via SCM_RIGHTS
    /// from sismo into the target). Caller takes ownership of `fd`.
    pub fn attach(fd: c_int, ring_size: u64) !RingBuffer {
        const page_size = std.heap.pageSize();
        const file_size: usize = page_size + @as(usize, @intCast(ring_size));
        return try mapInto(fd, ring_size, page_size, file_size);
    }

    fn mapInto(fd: c_int, ring_size: u64, page_size: usize, file_size: usize) !RingBuffer {
        // Reserve the outer address range with PROT_NONE so the two
        // MAP_FIXED mmaps below land at exactly the right place.
        const region_bytes = file_size + @as(usize, @intCast(ring_size));
        const region_raw = std.c.mmap(
            null,
            region_bytes,
            PROT_NONE,
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
            -1,
            0,
        );
        if (region_raw == std.c.MAP_FAILED) return error.ReserveAddrSpace;
        // mmap returns page-aligned memory; alignCast is sound.
        const region_aligned: *align(std.heap.page_size_min) anyopaque = @alignCast(region_raw);
        const region: [*]u8 = @ptrCast(region_aligned);

        // First mapping: meta + first data view, at offset 0 of the fd.
        const r1 = std.c.mmap(
            region_aligned,
            file_size,
            PROT_RW,
            .{ .TYPE = .SHARED, .FIXED = true },
            fd,
            0,
        );
        if (r1 == std.c.MAP_FAILED or r1 != @as(*anyopaque, region_aligned)) {
            _ = std.c.munmap(region_aligned, region_bytes);
            return error.MmapMeta;
        }

        // Second mapping: mirror of the data, at offset `page_size`
        // (i.e., the same data block remapped). Lands directly after
        // the first data view.
        const mirror_addr: [*]u8 = region + file_size;
        const mirror_aligned: *align(std.heap.page_size_min) anyopaque = @alignCast(@ptrCast(mirror_addr));
        const r2 = std.c.mmap(
            mirror_aligned,
            @as(usize, @intCast(ring_size)),
            PROT_RW,
            .{ .TYPE = .SHARED, .FIXED = true },
            fd,
            @intCast(page_size),
        );
        if (r2 == std.c.MAP_FAILED or r2 != @as(*anyopaque, mirror_aligned)) {
            _ = std.c.munmap(region_aligned, region_bytes);
            return error.MmapMirror;
        }

        const meta_ptr: *MetadataPage = @ptrCast(region_aligned);
        meta_ptr.* = std.mem.zeroes(MetadataPage);

        return .{
            .fd = fd,
            .region = region,
            .region_bytes = region_bytes,
            .meta = meta_ptr,
            .data = region + page_size,
            .size = ring_size,
            .size_mask = ring_size - 1,
            .page_size = page_size,
        };
    }

    pub fn destroy(self: *RingBuffer) void {
        const region_aligned: *align(std.heap.page_size_min) anyopaque = @alignCast(@ptrCast(self.region));
        _ = std.c.munmap(region_aligned, self.region_bytes);
        _ = std.c.close(self.fd);
        self.* = undefined;
    }

    // ---- Spinlock --------------------------------------------------------

    fn lock(self: *RingBuffer) void {
        // Test-test-and-set with exponential-ish backoff. Spike-quality;
        // production would use a futex on Linux.
        var spins: u32 = 0;
        while (true) {
            if (@atomicLoad(u32, &self.meta.spinlock, .monotonic) == 0) {
                if (@atomicRmw(u32, &self.meta.spinlock, .Xchg, 1, .acquire) == 0) return;
            }
            spins += 1;
            if (spins > 100) {
                _ = @atomicRmw(u64, &self.meta.failed_spinlocks, .Add, 1, .monotonic);
                std.atomic.spinLoopHint();
                spins = 0;
            }
        }
    }

    fn unlock(self: *RingBuffer) void {
        @atomicStore(u32, &self.meta.spinlock, 0, .release);
    }

    // ---- Writer side -----------------------------------------------------

    /// Reserve `payload_size` bytes in the ring for a record. Returns
    /// the slice the caller writes into; caller MUST follow up with
    /// `endWrite(slice)` to publish the size atomically.
    /// Returns `null` if the ring is full (writer drops the record;
    /// `num_writes_overflow` incremented).
    pub fn beginWrite(self: *RingBuffer, payload_size: usize) ?[]u8 {
        const total = alignUp(payload_size + HEADER_BYTES, RECORD_ALIGN);
        if (total > self.size) return null;

        self.lock();
        defer self.unlock();

        const wr = self.meta.write_pos;
        const rd = @atomicLoad(u64, &self.meta.read_pos, .acquire);
        const used = wr - rd;
        if (used + total > self.size) {
            self.meta.num_writes_overflow += 1;
            return null;
        }

        const wr_ptr = self.data + (wr & self.size_mask);
        // Zero the size slot (so a stale value from a prior wrap can't
        // mislead the reader). Relaxed is fine; the release-store in
        // endWrite is the synchronizer.
        const slot_size_field: *u32 = @ptrCast(@alignCast(wr_ptr));
        @atomicStore(u32, slot_size_field, 0, .monotonic);
        // Advance write_pos under the lock so the next BeginWrite sees
        // the slot as taken. The release-store in endWrite still
        // synchronizes the reader's observation of the payload bytes.
        self.meta.write_pos = wr + total;
        self.meta.bytes_written += payload_size;
        self.meta.num_writes_succeeded += 1;

        const payload_ptr = wr_ptr + HEADER_BYTES;
        return payload_ptr[0..payload_size];
    }

    /// Publish the size of the record `slice` was returned from. The
    /// release-store synchronizes the payload bytes for the reader.
    pub fn endWrite(self: *RingBuffer, slice: []u8) void {
        _ = self; // method form for API symmetry with beginWrite
        const size_field: *u32 = @ptrCast(@alignCast(slice.ptr - HEADER_BYTES));
        @atomicStore(u32, size_field, @intCast(slice.len), .release);
    }

    // ---- Reader side -----------------------------------------------------

    /// Try to read the next record. Returns the payload slice or null.
    /// The slice is borrowed from the ring; caller MUST follow up with
    /// `endRead(slice)` to advance read_pos.
    pub fn beginRead(self: *RingBuffer) ?[]const u8 {
        const rd = self.meta.read_pos;
        const wr = @atomicLoad(u64, &self.meta.write_pos, .acquire);
        if (rd >= wr) {
            self.meta.num_reads_nodata += 1;
            return null;
        }

        const rd_ptr = self.data + (rd & self.size_mask);
        const slot_size_field: *u32 = @ptrCast(@alignCast(rd_ptr));
        const size = @atomicLoad(u32, slot_size_field, .acquire);
        if (size == 0) {
            // Writer reserved the slot but hasn't published yet.
            // Try again later; preserves FIFO ordering.
            self.meta.num_reads_nodata += 1;
            return null;
        }

        const payload_ptr = rd_ptr + HEADER_BYTES;
        return payload_ptr[0..size];
    }

    pub fn endRead(self: *RingBuffer, slice: []const u8) void {
        const total = alignUp(slice.len + HEADER_BYTES, RECORD_ALIGN);
        @atomicStore(u64, &self.meta.read_pos, self.meta.read_pos + total, .release);
        self.meta.num_reads_succeeded += 1;
    }

    pub fn signalShutdown(self: *RingBuffer) void {
        @atomicStore(u32, &self.meta.shutting_down, 1, .release);
    }
};
