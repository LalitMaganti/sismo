// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Shared-memory ring buffer for the heap profiler IPC (recorder side),
//! migrated from heap_ring_posix.zig. Layout + algorithm follow heapprofd's
//! `shared_ring_buffer`:
//!
//!   [ MetadataPage (1 page) ][ data (ring_size) ][ data MIRROR (ring_size) ]
//!
//! The data region is mapped twice consecutively (double-mmap of the same shm
//! offset) so wrap-around records are transparently contiguous. Per record:
//! `[ size: atomic u32, padded to 8 ][ payload aligned to 8 ]` — the writer
//! publishes `size` last (release), the reader loads it (acquire); size 0 means
//! "reserved, not yet published".
//!
//! This is the RECORDER side (create + read); the target's Zig heap-preload is
//! the writer (attach + write). Both agree on this fixed shm layout, so the two
//! stay wire-compatible while the preload remains Zig (P6). macOS-only.

use std::os::raw::{c_int, c_uint, c_void};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const HEADER_BYTES: u64 = 8;
const RECORD_ALIGN: u64 = 8;

// macOS mmap/shm/open constants.
const PROT_READ: c_int = 0x1;
const PROT_WRITE: c_int = 0x2;
const PROT_NONE: c_int = 0x0;
const MAP_SHARED: c_int = 0x1;
const MAP_PRIVATE: c_int = 0x2;
const MAP_FIXED: c_int = 0x10;
const MAP_ANON: c_int = 0x1000;
const O_RDWR: c_int = 0x0002;
const O_CREAT: c_int = 0x0200;
const O_EXCL: c_int = 0x0800;

extern "C" {
    fn mmap(addr: *mut c_void, len: usize, prot: c_int, flags: c_int, fd: c_int, offset: i64) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> c_int;
    // shm_open is variadic on Darwin (mode must land on the stack) — declare it so.
    fn shm_open(name: *const u8, oflag: c_int, ...) -> c_int;
    fn shm_unlink(name: *const u8) -> c_int;
    fn ftruncate(fd: c_int, len: i64) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn getpid() -> c_int;
    fn getpagesize() -> c_int;
    fn clock_gettime(clk_id: c_int, tp: *mut Timespec) -> c_int;
}
const CLOCK_MONOTONIC: c_int = 6;
#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

fn map_failed() -> *mut c_void {
    usize::MAX as *mut c_void // (void*)-1
}

fn align_up(n: u64, a: u64) -> u64 {
    (n + a - 1) & !(a - 1)
}

/// Metadata page at offset 0 of the shm. Atomic fields are accessed from both
/// processes; layout is ABI-stable (matches the Zig `MetadataPage`).
#[repr(C)]
struct MetadataPage {
    spinlock: AtomicU32,
    _pad0: u32,
    write_pos: AtomicU64,
    read_pos: AtomicU64,
    bytes_written: AtomicU64,
    num_writes_succeeded: AtomicU64,
    num_writes_overflow: AtomicU64,
    num_reads_succeeded: AtomicU64,
    num_reads_nodata: AtomicU64,
    failed_spinlocks: AtomicU64,
    shutting_down: AtomicU32,
    _pad1: u32,
}

#[derive(Debug)]
pub enum RingError {
    InvalidSize,
    ShmCreate,
    Truncate,
    ReserveAddrSpace,
    MmapMeta,
    MmapMirror,
}

/// Recorder-side ring: owns the shm fd + the triple mmap region.
pub struct RingBuffer {
    fd: c_int,
    region: *mut u8,
    region_bytes: usize,
    meta: *mut MetadataPage,
    data: *mut u8,
    size: u64,
    size_mask: u64,
}

impl RingBuffer {
    /// Create an anonymous shm ring of `ring_size` data bytes (power of two ≥
    /// one page). The shm is unlinked immediately; only the fd keeps it alive
    /// (SCM_RIGHTS-passable to the target).
    pub fn create(ring_size: u64) -> Result<RingBuffer, RingError> {
        let page_size = unsafe { getpagesize() } as u64;
        if ring_size == 0 || (ring_size & (ring_size - 1)) != 0 || ring_size < page_size {
            return Err(RingError::InvalidSize);
        }

        // Unique, short name (macOS PSHMNAMLEN = 31): "/smh_<pid>_<ts_lo_hex>".
        let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts) };
        let ts_lo = ts.tv_nsec as u32;
        let pid = unsafe { getpid() };
        let name = format!("/smh_{pid}_{ts_lo:x}\0");

        let flags = O_RDWR | O_CREAT | O_EXCL;
        let fd = unsafe { shm_open(name.as_ptr(), flags, 0o600 as c_uint) };
        if fd < 0 {
            return Err(RingError::ShmCreate);
        }
        unsafe { shm_unlink(name.as_ptr()) };

        let file_size = page_size + ring_size;
        if unsafe { ftruncate(fd, file_size as i64) } != 0 {
            unsafe { close(fd) };
            return Err(RingError::Truncate);
        }
        Self::map_into(fd, ring_size, page_size, file_size)
    }

    /// Attach to an existing shm fd (SCM_RIGHTS-received). Caller owns `fd`.
    #[allow(dead_code)]
    pub fn attach(fd: c_int, ring_size: u64) -> Result<RingBuffer, RingError> {
        let page_size = unsafe { getpagesize() } as u64;
        let file_size = page_size + ring_size;
        Self::map_into(fd, ring_size, page_size, file_size)
    }

    fn map_into(fd: c_int, ring_size: u64, page_size: u64, file_size: u64) -> Result<RingBuffer, RingError> {
        let region_bytes = (file_size + ring_size) as usize;
        // Reserve the address range with PROT_NONE so the two MAP_FIXED maps land.
        let region = unsafe {
            mmap(std::ptr::null_mut(), region_bytes, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0)
        };
        if region == map_failed() {
            return Err(RingError::ReserveAddrSpace);
        }
        let region = region as *mut u8;

        // meta + first data view at fd offset 0.
        let r1 = unsafe {
            mmap(region as *mut c_void, file_size as usize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0)
        };
        if r1 == map_failed() || r1 as *mut u8 != region {
            unsafe { munmap(region as *mut c_void, region_bytes) };
            return Err(RingError::MmapMeta);
        }

        // Mirror of the data block at fd offset page_size, right after view 1.
        let mirror = unsafe { region.add(file_size as usize) };
        let r2 = unsafe {
            mmap(mirror as *mut c_void, ring_size as usize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, page_size as i64)
        };
        if r2 == map_failed() || r2 as *mut u8 != mirror {
            unsafe { munmap(region as *mut c_void, region_bytes) };
            return Err(RingError::MmapMirror);
        }

        let meta = region as *mut MetadataPage;
        // Zero the metadata page (create path — attach relies on the creator).
        unsafe { std::ptr::write_bytes(region, 0, page_size as usize) };

        Ok(RingBuffer {
            fd,
            region,
            region_bytes,
            meta,
            data: unsafe { region.add(page_size as usize) },
            size: ring_size,
            size_mask: ring_size - 1,
        })
    }

    fn meta(&self) -> &MetadataPage {
        unsafe { &*self.meta }
    }

    /// The shm fd — SCM_RIGHTS-pass this to the target so its preload attaches.
    pub fn fd(&self) -> c_int {
        self.fd
    }

    // ---- spinlock (test-test-and-set with backoff) ----
    fn lock(&self) {
        let m = self.meta();
        let mut spins: u32 = 0;
        loop {
            if m.spinlock.load(Ordering::Relaxed) == 0
                && m.spinlock.swap(1, Ordering::Acquire) == 0
            {
                return;
            }
            spins += 1;
            if spins > 100 {
                m.failed_spinlocks.fetch_add(1, Ordering::Relaxed);
                std::hint::spin_loop();
                spins = 0;
            }
        }
    }
    fn unlock(&self) {
        self.meta().spinlock.store(0, Ordering::Release);
    }

    /// Reserve `payload_size` bytes; returns a `*mut u8` payload pointer to write
    /// into, or null if the ring is full. Follow with `end_write`.
    pub fn begin_write(&self, payload_size: usize) -> *mut u8 {
        let total = align_up(payload_size as u64 + HEADER_BYTES, RECORD_ALIGN);
        if total > self.size {
            return std::ptr::null_mut();
        }
        self.lock();
        let m = self.meta();
        let wr = m.write_pos.load(Ordering::Relaxed);
        let rd = m.read_pos.load(Ordering::Acquire);
        if (wr - rd) + total > self.size {
            m.num_writes_overflow.fetch_add(1, Ordering::Relaxed);
            self.unlock();
            return std::ptr::null_mut();
        }
        let wr_ptr = unsafe { self.data.add((wr & self.size_mask) as usize) };
        // Zero the size slot so a stale wrap value can't mislead the reader.
        unsafe { &*(wr_ptr as *const AtomicU32) }.store(0, Ordering::Relaxed);
        m.write_pos.store(wr + total, Ordering::Release);
        m.bytes_written.fetch_add(payload_size as u64, Ordering::Relaxed);
        m.num_writes_succeeded.fetch_add(1, Ordering::Relaxed);
        self.unlock();
        unsafe { wr_ptr.add(HEADER_BYTES as usize) }
    }

    /// Publish the record whose payload starts at `payload` with `payload_size`
    /// bytes (release-store of the size header).
    pub fn end_write(&self, payload: *mut u8, payload_size: usize) {
        let size_field = unsafe { payload.sub(HEADER_BYTES as usize) as *const AtomicU32 };
        unsafe { &*size_field }.store(payload_size as u32, Ordering::Release);
    }

    /// Try to read the next record; returns (ptr, len) or None. Follow with
    /// `end_read(len)`.
    pub fn begin_read(&self) -> Option<(*const u8, usize)> {
        let m = self.meta();
        let rd = m.read_pos.load(Ordering::Relaxed);
        let wr = m.write_pos.load(Ordering::Acquire);
        if rd >= wr {
            m.num_reads_nodata.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let rd_ptr = unsafe { self.data.add((rd & self.size_mask) as usize) };
        let size = unsafe { &*(rd_ptr as *const AtomicU32) }.load(Ordering::Acquire);
        if size == 0 {
            m.num_reads_nodata.fetch_add(1, Ordering::Relaxed);
            return None; // reserved but not yet published
        }
        Some((unsafe { rd_ptr.add(HEADER_BYTES as usize) }, size as usize))
    }

    /// Advance past a record of `payload_len` bytes read via `begin_read`.
    pub fn end_read(&self, payload_len: usize) {
        let total = align_up(payload_len as u64 + HEADER_BYTES, RECORD_ALIGN);
        let m = self.meta();
        let rd = m.read_pos.load(Ordering::Relaxed);
        m.read_pos.store(rd + total, Ordering::Release);
        m.num_reads_succeeded.fetch_add(1, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    pub fn signal_shutdown(&self) {
        self.meta().shutting_down.store(1, Ordering::Release);
    }
}

impl Drop for RingBuffer {
    fn drop(&mut self) {
        unsafe {
            munmap(self.region as *mut c_void, self.region_bytes);
            close(self.fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_write_read_roundtrip() {
        // In-process create + write + read (the double-mmap mirror works within
        // one process; no target/root needed).
        let ring = RingBuffer::create(64 * 1024).expect("create");

        // Write two records.
        for payload in [b"hello".as_slice(), b"a-longer-record-payload".as_slice()] {
            let p = ring.begin_write(payload.len());
            assert!(!p.is_null());
            unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), p, payload.len()) };
            ring.end_write(p, payload.len());
        }

        // Read them back in order.
        let (p1, n1) = ring.begin_read().expect("first record");
        assert_eq!(unsafe { std::slice::from_raw_parts(p1, n1) }, b"hello");
        ring.end_read(n1);

        let (p2, n2) = ring.begin_read().expect("second record");
        assert_eq!(unsafe { std::slice::from_raw_parts(p2, n2) }, b"a-longer-record-payload");
        ring.end_read(n2);

        assert!(ring.begin_read().is_none(), "ring should be drained");
    }

    #[test]
    fn rejects_bad_sizes() {
        assert!(RingBuffer::create(0).is_err());
        assert!(RingBuffer::create(1000).is_err()); // not a power of two
        assert!(RingBuffer::create(100).is_err()); // below a page
    }

    #[test]
    fn wraparound_is_contiguous() {
        // Fill and drain repeatedly so write_pos wraps past `size`; the mirror
        // makes wrapped records contiguous, so reads still see whole payloads.
        let ring = RingBuffer::create(16 * 1024).expect("create");
        let payload = vec![0xABu8; 4000];
        for _ in 0..20 {
            let p = ring.begin_write(payload.len());
            assert!(!p.is_null());
            unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), p, payload.len()) };
            ring.end_write(p, payload.len());
            let (rp, rn) = ring.begin_read().expect("record");
            assert_eq!(rn, payload.len());
            assert!(unsafe { std::slice::from_raw_parts(rp, rn) }.iter().all(|&b| b == 0xAB));
            ring.end_read(rn);
        }
    }
}
