// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! macOS heap capture worker. Owns its
//! worker thread and the C++ SDK data-source lifecycle (on_setup/start/stop/
//! flush trampolines). The heavy setup — task_for_pid, module enumeration,
//! framehop + wholesym, the shm ring + heap-protocol attach — runs once at
//! startup; then the worker sleeps between drain cycles, waking on the drain
//! interval OR a trampoline/shutdown signal.
//!
//! **Heap emits on FLUSH and on STOP** (see the block comments in `run`): macOS
//! perfetto fires on_flush once before stop and the target attaches after the
//! session starts, so emitting on both makes output deterministic regardless of
//! when data lands in the ring.
//!
//! The ring read side, control protocol, unwinder, symbolizer, module loading,
//! config decode, and heap-profile assembly are all already-Rust siblings —
//! called directly, no FFI round-trip. cmd_record/cmd_datasource drive this via
//! `HeapCapture::start` / `HeapCapture::shutdown`.
//!
//! The producer C ABI (`sismo_ds_*`) is provided by the C++ shim in the final
//! binary; `#[cfg(test)]` stubs (in worker_sdk) stand in so `cargo test` links.
//!
//! macOS/arm64 only; gated in lib.rs.

use crate::heap::{HeapImage, HeapSite};
use crate::heap::heap_protocol::{connect_and_attach, AttachConfig};
use crate::heap::heap_ring::RingBuffer;
use crate::proto::sismo_config::{config_extract, heap_decode};
use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

// Sibling Rust modules (direct calls, no FFI round-trip).
use crate::symbolize::dyld_images::{load_target_modules, ImageList};
use crate::heap::{build_clock_snapshot_packet, build_profile_packet};
use crate::proto::session_config::encode_data_source_descriptor;
use crate::symbolize::symbolizer::Symbolizer;
use crate::symbolize::unwinder::{StackRegs, Unwinder};
use crate::ffi::{sismo_ds_emit, sismo_ds_register, sismo_flush_done, sismo_stop_done};
use crate::worker_sdk::{now_ns, read_u64, wait_for_setup, Event};

const DS_NAME: &[u8] = b"sismo.heap";

// Producer-side defaults; on_setup may override target_pid / ring_size /
// sample_interval via SismoHeapConfig.
const DEFAULT_RING_SIZE_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_SAMPLE_INTERVAL_BYTES: u64 = 4 * 1024;
/// How often the worker drains the shm ring while RUNNING.
const DRAIN_INTERVAL_NS: u64 = 1_000_000; // 1 ms
/// Settling pause after detach so the target's preload observes EOF on its
/// listener fd before we drain leftovers. 5 ms covers any in-flight malloc.
const DETACH_SETTLE_NS: u64 = 5_000_000;
/// Retry connect at 25 ms for up to ~3 s (120 attempts) — the preload's
/// listener binds only after dyld maps the inserted dylib.
const ATTACH_MAX_ATTEMPTS: usize = 120;

const STACK_SNAPSHOT_BYTES: usize = 8192;
const MAX_FRAMES: usize = 32;
const ALLOC_METADATA_BYTES: usize = 328;

// AllocMetadata field offsets (8-byte aligned extern struct).
const OFF_SEQUENCE: usize = 0;
const OFF_SAMPLE_SIZE: usize = 16;
const OFF_ALLOC_ADDRESS: usize = 24;
const OFF_STACK_POINTER: usize = 32;
// register_data starts at 48; RegBlockArm64 = { pc, lr, fp, _pad }.
const OFF_REG_PC: usize = 48;
const OFF_REG_LR: usize = 56;
const OFF_REG_FP: usize = 64;

// Free-batch record shape (mirror of sismo-heap-preload's wire.rs, which owns
// the ABI): FreeBatchHeader { magic, num } then num × FreeEntry { seq, addr }.
const FREE_BATCH_MAGIC: u64 = 0x5346_5245_454e_5452;
const FREE_HEADER_BYTES: usize = 16;
const FREE_ENTRY_BYTES: usize = 16;

use crate::mach::{mach_task_self_, MachPort, KERN_SUCCESS};

/// An aggregated allocation site's totals; the site key (its full leaf-first
/// callstack) lives in the map key.
#[derive(Default)]
struct SiteStats {
    allocated: u64,
    freed: u64,
    alloc_count: u64,
    free_count: u64,
}

/// One live sampled allocation awaiting its free.
struct LiveAlloc {
    seq: u64,
    sample_size: u64,
    pcs: Vec<u64>,
}

/// heapprofd-style bookkeeping: sampled allocations tracked by address until
/// their (batched) free arrives; sites keyed by the FULL callstack, so two
/// paths sharing a leaf stay distinct.
///
/// Frees are batched client-side, so they arrive LATE relative to allocations
/// of the same (reused) address: alloc(A,1) free(A,2) alloc(A,3) free(A,4)
/// can arrive as alloc(1) alloc(3) free(2) free(4). The shared sequence
/// counter makes this unambiguous without a global reorder: each address
/// keeps its live allocations seq-ascending, and a free matches the NEWEST
/// live allocation older than it — free(2) takes alloc(1), free(4) takes
/// alloc(3), regardless of arrival order.
#[derive(Default)]
struct HeapBook {
    sites: HashMap<Vec<u64>, SiteStats>,
    live: HashMap<u64, Vec<LiveAlloc>>,
}

impl HeapBook {
    fn apply_alloc(&mut self, seq: u64, addr: u64, sample_size: u64, pcs: Vec<u64>) {
        let s = self.sites.entry(pcs.clone()).or_default();
        s.allocated += sample_size;
        s.alloc_count += 1;
        // Allocations arrive in seq order (written to the ring at alloc
        // time), so pushing keeps the per-address list ascending.
        self.live.entry(addr).or_default().push(LiveAlloc { seq, sample_size, pcs });
    }

    fn apply_free(&mut self, seq: u64, addr: u64) {
        // Unmatched frees are the common case: frees of unsampled allocations.
        let Some(list) = self.live.get_mut(&addr) else {
            return;
        };
        let i = list.partition_point(|l| l.seq < seq);
        if i == 0 {
            return; // stale: older than every live allocation at this address
        }
        let l = list.remove(i - 1);
        if list.is_empty() {
            self.live.remove(&addr);
        }
        if let Some(s) = self.sites.get_mut(&l.pcs) {
            s.freed += l.sample_size;
            s.free_count += 1;
        }
    }
}

// ---- Worker ----------------------------------------------------------------

/// Shared worker state. All fields are Sync (atomics / Mutex) so the trampolines
/// (SDK threads) and the worker thread can share `&HeapCapture` via a raw pointer.
pub struct HeapCapture {
    ds_slot: AtomicU32,

    wakeup: Event,
    running: AtomicBool,
    exit_requested: AtomicBool,
    pending_stopper: AtomicUsize,
    pending_flusher: AtomicUsize,

    setup_received: AtomicBool,
    // Decoded from on_setup's DataSourceConfig.
    setup_target_pid: AtomicU32,
    setup_ring_size: AtomicU64,
    setup_sample_interval: AtomicU64,

    target_pid: AtomicU32, // resolved, read by the loop / emit
    // Resolved sample interval (setup or default); used at emit time.
    sample_interval: AtomicU64,

    records: AtomicU64,
    bytes_alloc: AtomicU64,
    sites_observed: AtomicU32,

    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

fn as_ref<'a>(p: *mut c_void) -> &'a HeapCapture {
    unsafe { &*(p as *const HeapCapture) }
}

extern "C" fn on_setup(user_arg: *mut c_void, dsc_bytes: *const c_void, dsc_size: usize) {
    let self_ = as_ref(user_arg);
    // Extract sismo_config (field 2000) then decode target_pid + ring + interval.
    if !dsc_bytes.is_null() {
        let dsc = unsafe { std::slice::from_raw_parts(dsc_bytes as *const u8, dsc_size) };
        if let Some((pid, ring, interval)) = config_extract(dsc).map(heap_decode) {
            self_.setup_target_pid.store(pid, Ordering::Release);
            self_.setup_ring_size.store(ring, Ordering::Release);
            self_.setup_sample_interval.store(interval, Ordering::Release);
        }
    }
    self_.setup_received.store(true, Ordering::Release);
    self_.wakeup.set();
}

extern "C" fn on_start(user_arg: *mut c_void) {
    let self_ = as_ref(user_arg);
    self_.running.store(true, Ordering::Release);
    self_.wakeup.set();
}

extern "C" fn on_stop(user_arg: *mut c_void, stopper: *mut c_void) {
    let self_ = as_ref(user_arg);
    if !stopper.is_null() {
        self_.pending_stopper.store(stopper as usize, Ordering::Release);
    }
    self_.wakeup.set();
}

extern "C" fn on_flush(user_arg: *mut c_void, flusher: *mut c_void) {
    let self_ = as_ref(user_arg);
    if !flusher.is_null() {
        self_.pending_flusher.store(flusher as usize, Ordering::Release);
    }
    self_.wakeup.set();
}

impl HeapCapture {
    /// Setup-failure path: park honoring stop, flush, and exit so the
    /// orchestrator's shutdown still joins us cleanly.
    fn park_until_exit(&self) {
        loop {
            self.wakeup.reset();
            if self.exit_requested.load(Ordering::Acquire) {
                return;
            }
            let flusher = self.pending_flusher.swap(0, Ordering::AcqRel);
            if flusher != 0 {
                unsafe { sismo_flush_done(flusher as *mut c_void) };
            }
            let stopper = self.pending_stopper.swap(0, Ordering::AcqRel);
            if stopper != 0 {
                unsafe { sismo_stop_done(stopper as *mut c_void) };
                self.running.store(false, Ordering::Release);
            }
            if self.exit_requested.load(Ordering::Acquire) {
                return;
            }
            self.wakeup.wait();
        }
    }

    fn run(&self) {
        // Wait for on_setup so we know which target to attach to.
        if !wait_for_setup(&self.wakeup, &self.exit_requested, &self.setup_received) {
            return;
        }

        let target_pid = self.setup_target_pid.load(Ordering::Acquire);
        let ring_size_bytes = {
            let s = self.setup_ring_size.load(Ordering::Acquire);
            if s != 0 { s } else { DEFAULT_RING_SIZE_BYTES }
        };
        let sample_interval = {
            let s = self.setup_sample_interval.load(Ordering::Acquire);
            if s != 0 { s } else { DEFAULT_SAMPLE_INTERVAL_BYTES }
        };
        self.sample_interval.store(sample_interval, Ordering::Release);

        if target_pid == 0 {
            eprintln!("heap_capture: SismoHeapConfig.target_pid not set — bailing");
            self.park_until_exit();
            return;
        }
        self.target_pid.store(target_pid, Ordering::Release);

        // ---- Heavy setup phase -----------------------------------------
        let mut task: MachPort = 0;
        if unsafe { libc::task_for_pid(mach_task_self_, target_pid as i32, &mut task) } != KERN_SUCCESS {
            eprintln!("heap_capture: task_for_pid({target_pid}) failed — need sudo or the debugger entitlement.");
            self.park_until_exit();
            return;
        }

        // Unwinder + symbolizer must exist before we register modules into them.
        let mut unwinder = Unwinder::new_arm64();
        let mut symbolizer = match Symbolizer::new() {
            Some(s) => s,
            None => {
                eprintln!("heap_capture: symbolizer.create failed");
                self.park_until_exit();
                return;
            }
        };

        // Enumerate + register the target's modules into the symbolizer +
        // unwinder (all in Rust). Retries the post-spawn empty-list window,
        // polling the abort closure so shutdown interrupts the wait. The returned
        // list (sorted by base) is kept for the profile's mappings. This runs
        // BEFORE the attach on purpose: it copies __TEXT slabs for every image
        // (seconds of mach reads for a big process), and doing it here pipelines
        // with the target's startup — after the attach it would stall the drain
        // loop while the ring fills.
        let image_list = match load_target_modules(
            task,
            Some(&mut symbolizer),
            Some(&mut unwinder),
            50 * 1_000_000,
            5 * 1_000_000_000,
            || self.exit_requested.load(Ordering::Acquire),
        ) {
            Ok(l) => l,
            Err(load_err) => {
                eprintln!("heap_capture: load_target_modules failed (err={load_err})");
                self.park_until_exit();
                return;
            }
        };

        let ring = match RingBuffer::create(ring_size_bytes) {
            Ok(r) => r,
            Err(_) => {
                eprintln!("heap_capture: ring.create failed");
                self.park_until_exit();
                return;
            }
        };

        let attach_cfg = AttachConfig {
            version: 1,
            ring_size: ring_size_bytes as u32,
            sample_interval,
            reserved: [0u8; 16],
        };
        let ctrl_fd =
            match unsafe { connect_and_attach(target_pid as i32, ring.fd(), &attach_cfg, ATTACH_MAX_ATTEMPTS) } {
                Ok(fd) => fd,
                Err(_) => {
                    eprintln!("heap_capture: connectAndAttach({target_pid}) failed — target's heap_preload may not be loaded yet");
                    drop(ring);
                    self.park_until_exit();
                    return;
                }
            };
        let mut ctrl_fd_open = true;

        let mut book = HeapBook::default();

        // ---- Main loop -------------------------------------------------
        loop {
            self.wakeup.reset();

            if self.exit_requested.load(Ordering::Acquire) {
                break;
            }

            if self.running.load(Ordering::Acquire) {
                self.drain_into(&ring, &mut unwinder, &mut book);
            }

            // Flush: catch up on the ring, stamp the snapshot moment HERE (not
            // after symbolicate+encode below, which would misplace samples by
            // the emit duration), then emit the ProfilePacket.
            let flusher = self.pending_flusher.swap(0, Ordering::AcqRel);
            if flusher != 0 {
                self.drain_into(&ring, &mut unwinder, &mut book);
                let snapshot_ts = now_ns();
                self.sites_observed.store(book.sites.len() as u32, Ordering::Release);
                self.emit_profile(&book, &image_list, &symbolizer, snapshot_ts);
                unsafe { sismo_flush_done(flusher as *mut c_void) };
            }

            // Stop: detach from the target so it stops producing, do a final
            // drain, and emit the complete accumulated snapshot. macOS perfetto
            // fires on_flush only once and heap attaches after the session
            // starts, so that single flush can land before any allocation is
            // captured — emitting here makes heap output deterministic. Then
            // ack the postponed stopper.
            let stopper = self.pending_stopper.swap(0, Ordering::AcqRel);
            if stopper != 0 {
                if ctrl_fd_open {
                    unsafe { libc::close(ctrl_fd) };
                    ctrl_fd_open = false;
                    self.wakeup.wait_timeout(Duration::from_nanos(DETACH_SETTLE_NS));
                }
                self.drain_into(&ring, &mut unwinder, &mut book);
                let dropped = ring.overflow_count();
                if dropped > 0 {
                    eprintln!(
                        "sismo heap: {dropped} record(s) dropped on ring overflow — allocated/freed totals undercount"
                    );
                }
                let snapshot_ts = now_ns();
                self.sites_observed.store(book.sites.len() as u32, Ordering::Release);
                self.emit_profile(&book, &image_list, &symbolizer, snapshot_ts);
                unsafe { sismo_stop_done(stopper as *mut c_void) };
                self.running.store(false, Ordering::Release);
            }

            if self.exit_requested.load(Ordering::Acquire) {
                break;
            }

            if self.running.load(Ordering::Acquire) {
                self.wakeup.wait_timeout(Duration::from_nanos(DRAIN_INTERVAL_NS));
            } else {
                self.wakeup.wait();
            }
        }

        if ctrl_fd_open {
            unsafe { libc::close(ctrl_fd) };
        }
        // ring, image_list, symbolizer, and unwinder drop here.
    }

    /// Drain up to 4096 ring records into the bookkeeping.
    fn drain_into(&self, ring: &RingBuffer, unwinder: &mut Unwinder, book: &mut HeapBook) {
        let mut batch = 0u64;
        while let Some((ptr, len)) = ring.begin_read() {
            let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
            self.process_record(slice, unwinder, book);
            ring.end_read(len);
            batch += 1;
            if batch > 4096 {
                break;
            }
        }
    }

    fn process_record(&self, slice: &[u8], unwinder: &mut Unwinder, book: &mut HeapBook) {
        // Free batches are the only other record type; discriminate by magic
        // (an allocation record's first field is a sequence number, but its
        // size is also always ALLOC + snapshot, checked below).
        if slice.len() >= FREE_HEADER_BYTES && read_u64(slice, 0) == FREE_BATCH_MAGIC {
            let num = read_u64(slice, 8) as usize;
            let have = (slice.len() - FREE_HEADER_BYTES) / FREE_ENTRY_BYTES;
            for i in 0..num.min(have) {
                let off = FREE_HEADER_BYTES + i * FREE_ENTRY_BYTES;
                let seq = read_u64(slice, off);
                let addr = read_u64(slice, off + 8);
                book.apply_free(seq, addr);
            }
            return;
        }
        if slice.len() < ALLOC_METADATA_BYTES + STACK_SNAPSHOT_BYTES {
            return;
        }
        let seq = read_u64(slice, OFF_SEQUENCE);
        let sample_size = read_u64(slice, OFF_SAMPLE_SIZE);
        let alloc_address = read_u64(slice, OFF_ALLOC_ADDRESS);
        let sp = read_u64(slice, OFF_STACK_POINTER);
        let pc = read_u64(slice, OFF_REG_PC);
        let lr = read_u64(slice, OFF_REG_LR);
        let fp = read_u64(slice, OFF_REG_FP);
        let stack_bytes = &slice[ALLOC_METADATA_BYTES..];

        let mut pcs =
            unwinder.walk_snapshot(StackRegs { pc, fp, lr, sp }, stack_bytes, sp, MAX_FRAMES);
        if pcs.is_empty() {
            pcs = vec![alloc_address];
        }
        pcs.truncate(MAX_FRAMES);
        book.apply_alloc(seq, alloc_address, sample_size, pcs);

        self.records.fetch_add(1, Ordering::Relaxed);
        self.bytes_alloc.fetch_add(sample_size, Ordering::Relaxed);
    }

    /// Emit the heap profile snapshot: flatten the aggregated sites + target
    /// images into flat FFI arrays and hand them to the Rust heap builder, which
    /// interns/symbolizes/serializes and returns wrapped TracePacket bodies; we
    /// emit each via the C++ SDK shim and free it.
    fn emit_profile(
        &self,
        book: &HeapBook,
        image_list: &ImageList,
        symbolizer: &Symbolizer,
        snapshot_ts_ns: u64,
    ) {
        let slot = self.ds_slot.load(Ordering::Acquire);
        let pid = self.target_pid.load(Ordering::Acquire);
        let sample_interval = self.sample_interval.load(Ordering::Acquire);

        // HeapImage array from the Rust image list (sorted by base in
        // load_target_modules; iid = index + 1, so order matters). Paths point
        // into the list, which outlives this call.
        let images: Vec<HeapImage> = image_list
            .images()
            .iter()
            .map(|(base, path)| HeapImage { base_avma: *base, path })
            .collect();

        let sites: Vec<HeapSite> = book
            .sites
            .iter()
            .map(|(pcs, s)| HeapSite {
                pcs,
                count: s.alloc_count,
                total_size: s.allocated,
                freed: s.freed,
                free_count: s.free_count,
            })
            .collect();

        // Clock snapshot first: it registers the MONOTONIC_COARSE clock that the
        // samples' timestamp is interpreted against.
        let cs = build_clock_snapshot_packet(snapshot_ts_ns);
        unsafe { sismo_ds_emit(slot, cs.as_ptr(), cs.len()) };

        let pp = build_profile_packet(
            pid,
            sample_interval,
            snapshot_ts_ns,
            Some(symbolizer),
            &images,
            &sites,
        );
        unsafe { sismo_ds_emit(slot, pp.as_ptr(), pp.len()) };
    }
}

impl HeapCapture {
    /// Create the heap capture: register the data source and spawn the worker
    /// thread. `None` on registration failure.
    pub fn start() -> Option<Box<HeapCapture>> {
        let cap = Box::new(HeapCapture {
            ds_slot: AtomicU32::new(u32::MAX),
            wakeup: Event::new(),
            running: AtomicBool::new(false),
            exit_requested: AtomicBool::new(false),
            pending_stopper: AtomicUsize::new(0),
            pending_flusher: AtomicUsize::new(0),
            setup_received: AtomicBool::new(false),
            setup_target_pid: AtomicU32::new(0),
            setup_ring_size: AtomicU64::new(0),
            setup_sample_interval: AtomicU64::new(0),
            target_pid: AtomicU32::new(0),
            sample_interval: AtomicU64::new(DEFAULT_SAMPLE_INTERVAL_BYTES),
            records: AtomicU64::new(0),
            bytes_alloc: AtomicU64::new(0),
            sites_observed: AtomicU32::new(0),
            thread: Mutex::new(None),
        });

        // The worker shares `&HeapCapture` via the box's (stable) heap address,
        // which outlives the thread: shutdown joins it before the box drops.
        let cap_addr = &*cap as *const HeapCapture as usize;

        // Register the data source (descriptor built via the Rust encoder).
        let desc = encode_data_source_descriptor(DS_NAME, true, false, &[]);
        let slot = unsafe {
            sismo_ds_register(desc.as_ptr(), desc.len(), on_setup, on_start, on_stop, on_flush, cap_addr as *mut c_void)
        };
        if slot == u32::MAX {
            return None;
        }
        cap.ds_slot.store(slot, Ordering::Release);

        let handle = std::thread::spawn(move || {
            let self_ = unsafe { &*(cap_addr as *const HeapCapture) };
            self_.run();
        });
        *cap.thread.lock().unwrap() = Some(handle);
        Some(cap)
    }

    /// Signal exit, join the worker, and return the accumulated stats.
    pub fn shutdown(self: Box<Self>) -> HeapStats {
        self.exit_requested.store(true, Ordering::Release);
        self.wakeup.set();
        let handle = self.thread.lock().unwrap().take();
        if let Some(h) = handle {
            let _ = h.join();
        }
        HeapStats {
            records: self.records.load(Ordering::Relaxed),
            bytes_alloc: self.bytes_alloc.load(Ordering::Relaxed),
            sites: self.sites_observed.load(Ordering::Relaxed),
        }
    }
}

/// Heap stats reported by [`HeapCapture::shutdown`].
pub struct HeapStats {
    pub records: u64,
    pub bytes_alloc: u64,
    pub sites: u32,
}

#[cfg(test)]
mod tests {
    use super::HeapBook;

    #[test]
    fn alloc_then_free_moves_bytes_to_freed() {
        let mut b = HeapBook::default();
        b.apply_alloc(1, 0x1000, 4096, vec![0xa, 0xb]);
        b.apply_alloc(2, 0x2000, 8192, vec![0xa, 0xb]);
        b.apply_free(3, 0x1000);
        let s = &b.sites[[0xau64, 0xb].as_slice()];
        assert_eq!((s.allocated, s.freed), (12288, 4096));
        assert_eq!((s.alloc_count, s.free_count), (2, 1));
        assert!(b.live.contains_key(&0x2000) && !b.live.contains_key(&0x1000));
    }

    #[test]
    fn delayed_free_batch_matches_across_address_reuse() {
        // The churn pattern: one address reused every iteration, frees
        // arriving late as a batch. alloc(1) alloc(3) alloc(5) then
        // free(2) free(4) free(6): each free must take the newest live
        // allocation older than itself.
        let mut b = HeapBook::default();
        b.apply_alloc(1, 0x1000, 100, vec![0xa]);
        b.apply_alloc(3, 0x1000, 200, vec![0xa]);
        b.apply_alloc(5, 0x1000, 300, vec![0xa]);
        b.apply_free(2, 0x1000);
        b.apply_free(4, 0x1000);
        b.apply_free(6, 0x1000);
        let s = &b.sites[[0xau64].as_slice()];
        assert_eq!((s.allocated, s.freed), (600, 600));
        assert_eq!((s.alloc_count, s.free_count), (3, 3));
        assert!(b.live.is_empty());
    }

    #[test]
    fn free_older_than_every_live_alloc_is_stale() {
        let mut b = HeapBook::default();
        b.apply_alloc(3, 0x1000, 200, vec![0xb]);
        b.apply_free(2, 0x1000); // stale: predates the only live alloc
        assert_eq!(b.sites[[0xbu64].as_slice()].freed, 0);
        b.apply_free(4, 0x1000);
        assert_eq!(b.sites[[0xbu64].as_slice()].freed, 200);
    }

    #[test]
    fn unmatched_frees_are_ignored() {
        let mut b = HeapBook::default();
        b.apply_free(1, 0xdead); // free of an unsampled allocation
        assert!(b.sites.is_empty() && b.live.is_empty());
    }

    #[test]
    fn distinct_paths_to_one_leaf_stay_distinct_sites() {
        let mut b = HeapBook::default();
        b.apply_alloc(1, 0x1000, 64, vec![0xf00d, 0x10]);
        b.apply_alloc(2, 0x2000, 64, vec![0xf00d, 0x20]);
        assert_eq!(b.sites.len(), 2);
    }
}
