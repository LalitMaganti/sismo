// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Shared-memory ring buffer — **preload (writer) side**. The layout +
//! algorithm are byte-identical to the recorder's `heap::heap_ring` (they share
//! this shm), so the
//! two stay wire-compatible. Transitional duplication — a shared crate can
//! unify them in P7.
//!
//!   [ MetadataPage (1 page) ][ data (ring_size) ][ data MIRROR (ring_size) ]
//!
//! The preload `attach`es an SCM_RIGHTS-received fd, then `begin_write` /
//! `end_write` per sampled allocation. `create` + the read side are `#[cfg(test)]`
//! only (the injected dylib never creates or reads), so they don't bloat it.

use std::os::raw::{c_int, c_void};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const HEADER_BYTES: u64 = 8;
const RECORD_ALIGN: u64 = 8;

const PROT_READ: c_int = 0x1;
const PROT_WRITE: c_int = 0x2;
const PROT_NONE: c_int = 0x0;
const MAP_SHARED: c_int = 0x1;
const MAP_PRIVATE: c_int = 0x2;
const MAP_FIXED: c_int = 0x10;
const MAP_ANON: c_int = 0x1000;

extern "C" {
    fn mmap(addr: *mut c_void, len: usize, prot: c_int, flags: c_int, fd: c_int, offset: i64) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn getpagesize() -> c_int;
}

fn map_failed() -> *mut c_void {
    usize::MAX as *mut c_void // (void*)-1
}

fn align_up(n: u64, a: u64) -> u64 {
    (n + a - 1) & !(a - 1)
}

/// Metadata page at offset 0 (shared with the recorder; ABI-stable).
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
    ReserveAddrSpace,
    MmapMeta,
    MmapMirror,
    #[cfg(test)]
    InvalidSize,
    #[cfg(test)]
    ShmCreate,
    #[cfg(test)]
    Truncate,
}

/// The mapped shm ring. `Drop` munmaps + closes the fd (the listener drops it on
/// detach). Safe to `Send` between the listener and the malloc shim: it's a
/// stable mmap the shim only ever reads through atomics.
pub struct RingBuffer {
    fd: c_int,
    region: *mut u8,
    region_bytes: usize,
    meta: *mut MetadataPage,
    data: *mut u8,
    size: u64,
    size_mask: u64,
}

unsafe impl Send for RingBuffer {}
unsafe impl Sync for RingBuffer {}

impl RingBuffer {
    /// Attach to an SCM_RIGHTS-received shm fd (the recorder created it). The
    /// creator zeroed the metadata; we just map. Caller owns `fd`.
    pub fn attach(fd: c_int, ring_size: u64) -> Result<RingBuffer, RingError> {
        let page_size = unsafe { getpagesize() } as u64;
        let file_size = page_size + ring_size;
        Self::map_into(fd, ring_size, page_size, file_size, false)
    }

    fn map_into(fd: c_int, ring_size: u64, page_size: u64, file_size: u64, zero_meta: bool) -> Result<RingBuffer, RingError> {
        let region_bytes = (file_size + ring_size) as usize;
        let region = unsafe {
            mmap(std::ptr::null_mut(), region_bytes, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0)
        };
        if region == map_failed() {
            return Err(RingError::ReserveAddrSpace);
        }
        let region = region as *mut u8;

        let r1 = unsafe {
            mmap(region as *mut c_void, file_size as usize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0)
        };
        if r1 == map_failed() || r1 as *mut u8 != region {
            unsafe { munmap(region as *mut c_void, region_bytes) };
            return Err(RingError::MmapMeta);
        }

        let mirror = unsafe { region.add(file_size as usize) };
        let r2 = unsafe {
            mmap(mirror as *mut c_void, ring_size as usize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, page_size as i64)
        };
        if r2 == map_failed() || r2 as *mut u8 != mirror {
            unsafe { munmap(region as *mut c_void, region_bytes) };
            return Err(RingError::MmapMirror);
        }

        let meta = region as *mut MetadataPage;
        if zero_meta {
            unsafe { std::ptr::write_bytes(region, 0, page_size as usize) };
        }

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

    // ---- spinlock (test-test-and-set with backoff) ----
    fn lock(&self) {
        let m = self.meta();
        let mut spins: u32 = 0;
        loop {
            if m.spinlock.load(Ordering::Relaxed) == 0 && m.spinlock.swap(1, Ordering::Acquire) == 0 {
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

    /// Reserve `payload_size` bytes; returns a payload pointer to write into, or
    /// null if the ring is full. Follow with `end_write`.
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
        unsafe { &*(wr_ptr as *const AtomicU32) }.store(0, Ordering::Relaxed);
        m.write_pos.store(wr + total, Ordering::Release);
        m.bytes_written.fetch_add(payload_size as u64, Ordering::Relaxed);
        m.num_writes_succeeded.fetch_add(1, Ordering::Relaxed);
        self.unlock();
        unsafe { wr_ptr.add(HEADER_BYTES as usize) }
    }

    /// Publish the record (release-store of the size header).
    ///
    /// # Safety
    /// `payload` must be a pointer returned by `begin_write` on this ring that
    /// has not yet been published, and `payload_size` must match that call.
    pub unsafe fn end_write(&self, payload: *mut u8, payload_size: usize) {
        let size_field = unsafe { payload.sub(HEADER_BYTES as usize) as *const AtomicU32 };
        unsafe { &*size_field }.store(payload_size as u32, Ordering::Release);
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
    use std::os::raw::c_uint;

    const O_RDWR: c_int = 0x0002;
    const O_CREAT: c_int = 0x0200;
    const O_EXCL: c_int = 0x0800;
    const CLOCK_MONOTONIC: c_int = 6;
    #[repr(C)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }
    extern "C" {
        fn shm_open(name: *const u8, oflag: c_int, ...) -> c_int;
        fn shm_unlink(name: *const u8) -> c_int;
        fn ftruncate(fd: c_int, len: i64) -> c_int;
        fn getpid() -> c_int;
        fn clock_gettime(clk_id: c_int, tp: *mut Timespec) -> c_int;
    }

    impl RingBuffer {
        /// Test-only creator (the recorder does this at runtime; the preload
        /// only attaches). Lets the write side be exercised end to end here.
        fn create(ring_size: u64) -> Result<RingBuffer, RingError> {
            let page_size = unsafe { getpagesize() } as u64;
            if ring_size == 0 || (ring_size & (ring_size - 1)) != 0 || ring_size < page_size {
                return Err(RingError::InvalidSize);
            }
            let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
            unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts) };
            let name = format!("/smhp_{}_{:x}\0", unsafe { getpid() }, ts.tv_nsec as u32);
            let fd = unsafe { shm_open(name.as_ptr(), O_RDWR | O_CREAT | O_EXCL, 0o600 as c_uint) };
            if fd < 0 {
                return Err(RingError::ShmCreate);
            }
            unsafe { shm_unlink(name.as_ptr()) };
            let file_size = page_size + ring_size;
            if unsafe { ftruncate(fd, file_size as i64) } != 0 {
                unsafe { close(fd) };
                return Err(RingError::Truncate);
            }
            Self::map_into(fd, ring_size, page_size, file_size, true)
        }

        fn begin_read(&self) -> Option<(*const u8, usize)> {
            let m = self.meta();
            let rd = m.read_pos.load(Ordering::Relaxed);
            let wr = m.write_pos.load(Ordering::Acquire);
            if rd >= wr {
                return None;
            }
            let rd_ptr = unsafe { self.data.add((rd & self.size_mask) as usize) };
            let size = unsafe { &*(rd_ptr as *const AtomicU32) }.load(Ordering::Acquire);
            if size == 0 {
                return None;
            }
            Some((unsafe { rd_ptr.add(HEADER_BYTES as usize) }, size as usize))
        }
        fn end_read(&self, payload_len: usize) {
            let total = align_up(payload_len as u64 + HEADER_BYTES, RECORD_ALIGN);
            let m = self.meta();
            let rd = m.read_pos.load(Ordering::Relaxed);
            m.read_pos.store(rd + total, Ordering::Release);
        }
    }

    #[test]
    fn write_then_read_roundtrips() {
        let rb = RingBuffer::create(64 * 1024).expect("create");
        let payload = b"heap-record-xyz";
        let slot = rb.begin_write(payload.len());
        assert!(!slot.is_null());
        unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), slot, payload.len()) };
        unsafe { rb.end_write(slot, payload.len()) };

        let (ptr, len) = rb.begin_read().expect("a record");
        assert_eq!(len, payload.len());
        let got = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert_eq!(got, payload);
        rb.end_read(len);
        assert!(rb.begin_read().is_none()); // drained
    }

    #[test]
    fn oversized_write_is_rejected() {
        let rb = RingBuffer::create(64 * 1024).expect("create");
        assert!(rb.begin_write(128 * 1024).is_null());
    }
}
