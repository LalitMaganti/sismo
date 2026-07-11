// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Shared-memory ring buffer for the heap profiler IPC (recorder side). Layout
//! + algorithm follow heapprofd's `shared_ring_buffer`:
//!
//!   [ MetadataPage (1 page) ][ data (ring_size) ][ data MIRROR (ring_size) ]
//!
//! The data region is mapped twice consecutively (double-mmap of the same shm
//! offset) so wrap-around records are transparently contiguous. Per record:
//! `[ size: atomic u32, padded to 8 ][ payload aligned to 8 ]` — the writer
//! publishes `size` last (release), the reader loads it (acquire); size 0 means
//! "reserved, not yet published".
//!
//! This is the RECORDER side (create + read); the target's heap-preload is the
//! writer (attach + write). Both agree on this fixed shm layout. macOS-only.

use libc::{c_char, c_int, c_uint, c_void};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const HEADER_BYTES: u64 = 8;
const RECORD_ALIGN: u64 = 8;

fn align_up(n: u64, a: u64) -> u64 {
    (n + a - 1) & !(a - 1)
}

/// Metadata page at offset 0 of the shm. Atomic fields are accessed from both
/// processes; layout is ABI-stable (matches the preload's `MetadataPage`).
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
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        if ring_size == 0 || (ring_size & (ring_size - 1)) != 0 || ring_size < page_size {
            return Err(RingError::InvalidSize);
        }

        // Unique, short name (macOS PSHMNAMLEN = 31): "/smh_<pid>_<ts_lo_hex>".
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        let ts_lo = ts.tv_nsec as u32;
        let pid = unsafe { libc::getpid() };
        let name = format!("/smh_{pid}_{ts_lo:x}\0");

        // shm_open's mode is variadic on Darwin, so pass it as c_uint.
        let flags = libc::O_RDWR | libc::O_CREAT | libc::O_EXCL;
        let fd = unsafe { libc::shm_open(name.as_ptr() as *const c_char, flags, 0o600 as c_uint) };
        if fd < 0 {
            return Err(RingError::ShmCreate);
        }
        unsafe { libc::shm_unlink(name.as_ptr() as *const c_char) };

        let file_size = page_size + ring_size;
        if unsafe { libc::ftruncate(fd, file_size as i64) } != 0 {
            unsafe { libc::close(fd) };
            return Err(RingError::Truncate);
        }
        Self::map_into(fd, ring_size, page_size, file_size)
    }

    fn map_into(fd: c_int, ring_size: u64, page_size: u64, file_size: u64) -> Result<RingBuffer, RingError> {
        let region_bytes = (file_size + ring_size) as usize;
        // Reserve the address range with PROT_NONE so the two MAP_FIXED maps land.
        let region = unsafe {
            libc::mmap(std::ptr::null_mut(), region_bytes, libc::PROT_NONE, libc::MAP_PRIVATE | libc::MAP_ANON, -1, 0)
        };
        if region == libc::MAP_FAILED {
            return Err(RingError::ReserveAddrSpace);
        }
        let region = region as *mut u8;

        // meta + first data view at fd offset 0.
        let r1 = unsafe {
            libc::mmap(region as *mut c_void, file_size as usize, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED | libc::MAP_FIXED, fd, 0)
        };
        if r1 == libc::MAP_FAILED || r1 as *mut u8 != region {
            unsafe { libc::munmap(region as *mut c_void, region_bytes) };
            return Err(RingError::MmapMeta);
        }

        // Mirror of the data block at fd offset page_size, right after view 1.
        let mirror = unsafe { region.add(file_size as usize) };
        let r2 = unsafe {
            libc::mmap(mirror as *mut c_void, ring_size as usize, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED | libc::MAP_FIXED, fd, page_size as i64)
        };
        if r2 == libc::MAP_FAILED || r2 as *mut u8 != mirror {
            unsafe { libc::munmap(region as *mut c_void, region_bytes) };
            return Err(RingError::MmapMirror);
        }

        let meta = region as *mut MetadataPage;
        // Zero the metadata page (the creator owns it).
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
}

impl Drop for RingBuffer {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.region as *mut c_void, self.region_bytes);
            libc::close(self.fd);
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
