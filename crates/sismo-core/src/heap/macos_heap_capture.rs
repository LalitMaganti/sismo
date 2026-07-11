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
use crate::worker_sdk::Event;

const DS_NAME: &[u8] = b"sismo.heap";
const U32_MAX: u32 = u32::MAX;

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
const OFF_SAMPLE_SIZE: usize = 16;
const OFF_ALLOC_ADDRESS: usize = 24;
const OFF_STACK_POINTER: usize = 32;
// register_data starts at 48; RegBlockArm64 = { pc, lr, fp, _pad }.
const OFF_REG_PC: usize = 48;
const OFF_REG_LR: usize = 56;
const OFF_REG_FP: usize = 64;

type MachPort = u32;
const KERN_SUCCESS: i32 = 0;

// libc's mach_task_self_ is deprecated (mach2 crate); keep it hand-rolled.
extern "C" {
    static mach_task_self_: MachPort;
}

fn now_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn read_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// An aggregated allocation site keyed by leaf PC.
struct AllocStats {
    count: u64,
    total_size: u64,
    pcs: [u64; MAX_FRAMES],
    pc_count: usize,
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
        if let Some((pid, ring, interval)) = config_extract(dsc).and_then(heap_decode) {
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
        while !self.exit_requested.load(Ordering::Acquire)
            && !self.setup_received.load(Ordering::Acquire)
        {
            self.wakeup.reset();
            if self.exit_requested.load(Ordering::Acquire)
                || self.setup_received.load(Ordering::Acquire)
            {
                break;
            }
            self.wakeup.wait();
        }
        if self.exit_requested.load(Ordering::Acquire) {
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
        // list (sorted by base) is kept for the profile's mappings.
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

        let mut sizes_by_top_pc: HashMap<u64, AllocStats> = HashMap::new();

        // ---- Main loop -------------------------------------------------
        loop {
            self.wakeup.reset();

            if self.exit_requested.load(Ordering::Acquire) {
                break;
            }

            if self.running.load(Ordering::Acquire) {
                self.drain_into(&ring, &mut unwinder, &mut sizes_by_top_pc);
            }

            // Flush: catch up on the ring, stamp the snapshot moment HERE (not
            // after symbolicate+encode below, which would misplace samples by
            // the emit duration), then emit the ProfilePacket.
            let flusher = self.pending_flusher.swap(0, Ordering::AcqRel);
            if flusher != 0 {
                self.drain_into(&ring, &mut unwinder, &mut sizes_by_top_pc);
                let snapshot_ts = now_ns();
                self.sites_observed.store(sizes_by_top_pc.len() as u32, Ordering::Release);
                self.emit_profile(&sizes_by_top_pc, &image_list, &symbolizer, snapshot_ts);
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
                self.drain_into(&ring, &mut unwinder, &mut sizes_by_top_pc);
                let snapshot_ts = now_ns();
                self.sites_observed.store(sizes_by_top_pc.len() as u32, Ordering::Release);
                self.emit_profile(&sizes_by_top_pc, &image_list, &symbolizer, snapshot_ts);
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

    /// Drain up to 4096 ring records into the aggregation map.
    fn drain_into(
        &self,
        ring: &RingBuffer,
        unwinder: &mut Unwinder,
        sizes: &mut HashMap<u64, AllocStats>,
    ) {
        let mut batch = 0u64;
        while let Some((ptr, len)) = ring.begin_read() {
            let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
            self.process_record(slice, unwinder, sizes);
            ring.end_read(len);
            batch += 1;
            if batch > 4096 {
                break;
            }
        }
    }

    fn process_record(
        &self,
        slice: &[u8],
        unwinder: &mut Unwinder,
        sizes: &mut HashMap<u64, AllocStats>,
    ) {
        if slice.len() < ALLOC_METADATA_BYTES + STACK_SNAPSHOT_BYTES {
            return;
        }
        let sample_size = read_u64(slice, OFF_SAMPLE_SIZE);
        let alloc_address = read_u64(slice, OFF_ALLOC_ADDRESS);
        let sp = read_u64(slice, OFF_STACK_POINTER);
        let pc = read_u64(slice, OFF_REG_PC);
        let lr = read_u64(slice, OFF_REG_LR);
        let fp = read_u64(slice, OFF_REG_FP);
        let stack_bytes = &slice[ALLOC_METADATA_BYTES..];

        let pcs =
            unwinder.walk_snapshot(StackRegs { pc, fp, lr, sp }, stack_bytes, sp, MAX_FRAMES);

        let top_pc = pcs.first().copied().unwrap_or(alloc_address);
        let entry = sizes.entry(top_pc).or_insert_with(|| {
            let mut stat = AllocStats { count: 0, total_size: 0, pcs: [0; MAX_FRAMES], pc_count: 0 };
            let cap = pcs.len().min(MAX_FRAMES);
            stat.pcs[..cap].copy_from_slice(&pcs[..cap]);
            stat.pc_count = cap;
            stat
        });
        entry.count += 1;
        entry.total_size += sample_size;

        self.records.fetch_add(1, Ordering::Relaxed);
        self.bytes_alloc.fetch_add(sample_size, Ordering::Relaxed);
    }

    /// Emit the heap profile snapshot: flatten the aggregated sites + target
    /// images into flat FFI arrays and hand them to the Rust heap builder, which
    /// interns/symbolizes/serializes and returns wrapped TracePacket bodies; we
    /// emit each via the C++ SDK shim and free it.
    fn emit_profile(
        &self,
        sizes: &HashMap<u64, AllocStats>,
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

        let sites: Vec<HeapSite> = sizes
            .values()
            .map(|s| HeapSite { pcs: &s.pcs[..s.pc_count], count: s.count, total_size: s.total_size })
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
            ds_slot: AtomicU32::new(U32_MAX),
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
        if slot == U32_MAX {
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
