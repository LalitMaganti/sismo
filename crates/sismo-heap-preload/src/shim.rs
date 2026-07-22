// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! The malloc interposer + control-plane listener. This is the delicate
//! runtime core:
//!
//! - `__DATA,__mod_init_func` runs `module_init` at dyld load → spawns the
//!   listener thread (dormant; the malloc hot path is one atomic load + branch).
//! - The listener binds the per-PID socket; on attach it maps the shm ring and
//!   flips `G_ENABLED`. On EOF (recorder detaches) it tears down.
//! - `__DATA,__interpose` redirects `malloc` to `sismo_malloc_shim`, which
//!   Poisson-samples, captures the caller's arm64 frame (x29 chain), copies a
//!   stack snapshot, and writes an AllocMetadata record to the ring.
//!
//! Hard constraints (a bug crashes the injected target): the hot path allocates
//! NOTHING (const thread-locals, no format!/Box), a threadlocal `in_capture`
//! guard prevents re-entry, and the frame capture must live directly in the
//! interposed function so x29 points at the user→shim frame.
//!
//! macOS/arm64 only. Runtime-validated by `sudo tools/e2e-all-sources` (the
//! frame-walk asm is unit-tested standalone below).

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use crate::protocol;
use crate::ring::RingBuffer;
use crate::sampler::Sampler;
use crate::wire::{
    AllocMetadata, FreeBatchHeader, FreeEntry, RegBlockArm64, FREE_BATCH_CAP, FREE_BATCH_MAGIC,
    MAX_REGISTER_DATA_BYTES, STACK_SNAPSHOT_BYTES,
};
use std::cell::{Cell, RefCell};
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};

// ---- libc ------------------------------------------------------------------

// The allocator family stays hand-declared (not via the libc crate): the
// __interpose tuples below store these symbols as the original functions.
// Everything else is libc.
extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn calloc(nmemb: usize, size: usize) -> *mut c_void;
    fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void;
    fn valloc(size: usize) -> *mut c_void;
    fn aligned_alloc(align: usize, size: usize) -> *mut c_void;
    fn posix_memalign(memptr: *mut *mut c_void, align: usize, size: usize) -> i32;
    fn free(ptr: *mut c_void);
}

fn now_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn log(s: &[u8]) {
    unsafe { libc::write(2, s.as_ptr() as *const c_void, s.len()) };
}

// ---- Global state ----------------------------------------------------------

static G_ENABLED: AtomicBool = AtomicBool::new(false);
static G_RB: AtomicPtr<RingBuffer> = AtomicPtr::new(std::ptr::null_mut());
static G_SEQ: AtomicU64 = AtomicU64::new(1);
static G_SAMPLING_INTERVAL: AtomicU64 = AtomicU64::new(4096);
static G_SESSION_GEN: AtomicU64 = AtomicU64::new(0);
static G_LISTENER_STARTED: AtomicBool = AtomicBool::new(false);
static G_EMITTED: AtomicU64 = AtomicU64::new(0);
static G_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Per-thread pending free batch. Frees are cheap (no stack), so they are
/// batched and flushed when the batch fills or its oldest entry passes
/// FLUSH_AGE_NS — one ring write (and one spinlock take) per batch, not per
/// free. A thread that stops freeing can strand a partial batch (bounded
/// retained-size overcount); the age check on that thread's next free is the
/// only flush trigger, deliberately — no timers in the injected target.
struct FreeBatchTls {
    num: usize,
    first_ns: u64,
    gen: u64,
    entries: [FreeEntry; FREE_BATCH_CAP],
}

const FLUSH_AGE_NS: u64 = 100_000_000; // 100ms

// const-initialized thread-locals: no lazy heap init on first touch (critical —
// the hot path must not allocate).
thread_local! {
    static IN_CAPTURE: Cell<bool> = const { Cell::new(false) };
    static T_SAMPLER: RefCell<Option<Sampler>> = const { RefCell::new(None) };
    static T_SAMPLER_GEN: Cell<u64> = const { Cell::new(0) };
    static T_FREES: RefCell<FreeBatchTls> = const {
        RefCell::new(FreeBatchTls {
            num: 0,
            first_ns: 0,
            gen: 0,
            entries: [FreeEntry { sequence_number: 0, address: 0 }; FREE_BATCH_CAP],
        })
    };
}

fn in_capture() -> bool {
    IN_CAPTURE.with(|c| c.get())
}
fn set_in_capture(v: bool) {
    IN_CAPTURE.with(|c| c.set(v));
}

/// Per-thread Poisson decision, re-seeding the thread's sampler when the session
/// generation advances (a new attach).
fn sample_size_for(size: u64) -> u64 {
    let gen = G_SESSION_GEN.load(Ordering::Acquire);
    T_SAMPLER.with(|cell| {
        let mut opt = cell.borrow_mut();
        if opt.is_none() || T_SAMPLER_GEN.with(|g| g.get()) != gen {
            let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
            let seed = ts.tv_nsec as u64 ^ (cell as *const _ as u64);
            *opt = Some(Sampler::new(G_SAMPLING_INTERVAL.load(Ordering::Relaxed), seed));
            T_SAMPLER_GEN.with(|g| g.set(gen));
        }
        opt.as_mut().unwrap().sample_size(size)
    })
}

// ---- Listener thread (control plane) ---------------------------------------

extern "C" fn listener_thread(_: *mut c_void) -> *mut c_void {
    set_in_capture(true); // never re-enter the shim from this thread
    let pid = unsafe { libc::getpid() };
    let listener = match protocol::Listener::listen(pid) {
        Ok(l) => l,
        Err(_) => {
            log(b"sismo-heap: listenForAttach failed\n");
            return std::ptr::null_mut();
        }
    };

    loop {
        let mut attach = match unsafe { listener.accept_and_receive() } {
            Ok(a) => a,
            Err(_) => {
                sleep_us(50_000); // brief backoff; EINTR/EBADF shouldn't kill the listener
                continue;
            }
        };

        // Map the SCM_RIGHTS shm fd (the ring then owns it). Box it via libc
        // malloc — guarded by in_capture, so the shim skips this allocation.
        let ring = match RingBuffer::attach(attach.shm_fd, attach.config.ring_size as u64) {
            Ok(r) => r,
            Err(_) => {
                attach.close_all();
                continue;
            }
        };
        let rb_ptr = Box::into_raw(Box::new(ring));

        G_SEQ.store(1, Ordering::Relaxed);
        G_EMITTED.store(0, Ordering::Relaxed);
        G_DROPPED.store(0, Ordering::Relaxed);
        let si = if attach.config.sample_interval == 0 { 1 } else { attach.config.sample_interval };
        G_SAMPLING_INTERVAL.store(si, Ordering::Relaxed);
        G_SESSION_GEN.fetch_add(1, Ordering::Release); // each thread re-seeds its sampler
        G_RB.store(rb_ptr, Ordering::Release);
        G_ENABLED.store(true, Ordering::Release);
        log(b"sismo-heap: attached\n");

        // Block on the control connection until EOF (a liveness signal only).
        let mut b = [0u8; 1];
        unsafe { libc::read(attach.conn_fd, b.as_mut_ptr() as *mut c_void, 1) };

        // Detach: disable, tear down the ring (Drop munmaps + closes shm_fd).
        G_ENABLED.store(false, Ordering::Release);
        log(b"sismo-heap: detached\n");
        let old = G_RB.swap(std::ptr::null_mut(), Ordering::AcqRel);
        if !old.is_null() {
            drop(unsafe { Box::from_raw(old) });
        }
        unsafe { libc::close(attach.conn_fd) };
    }
}

fn sleep_us(us: u64) {
    let ts = libc::timespec { tv_sec: (us / 1_000_000) as i64, tv_nsec: ((us % 1_000_000) * 1000) as i64 };
    unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
}

// ---- Module init (dyld load) -----------------------------------------------

extern "C" fn module_init() {
    if G_LISTENER_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    set_in_capture(true);
    let mut tid: libc::pthread_t = 0;
    unsafe { libc::pthread_create(&mut tid, std::ptr::null(), listener_thread, std::ptr::null_mut()) };
    set_in_capture(false);
    log(b"sismo-heap: preload loaded, listener thread spawned\n");

    // SISMO_HEAP_WAIT_ATTACH=1 (set by `sismo record` when it spawned us to
    // profile from the start): hold main() here until the recorder attaches,
    // so its setup latency cannot lose the workload's earliest allocations.
    // Bounded so a dead recorder doesn't wedge the target; `sismo prepare`
    // targets run without it and attach whenever the recorder shows up.
    let wait = unsafe { libc::getenv(c"SISMO_HEAP_WAIT_ATTACH".as_ptr()) };
    if !wait.is_null() && unsafe { *wait } == b'1' as libc::c_char {
        const WAIT_ATTACH_MAX_MS: u64 = 5_000;
        let mut waited_ms: u64 = 0;
        while !G_ENABLED.load(Ordering::Acquire) && waited_ms < WAIT_ATTACH_MAX_MS {
            sleep_us(1_000);
            waited_ms += 1;
        }
        if !G_ENABLED.load(Ordering::Acquire) {
            log(b"sismo-heap: recorder did not attach within 5s - continuing unprofiled\n");
        }
    }
}

/// dyld runs each `__mod_init_func` pointer at load, before other image code.
#[used]
#[link_section = "__DATA,__mod_init_func"]
static SISMO_HEAP_CTOR: extern "C" fn() = module_init;

// ---- Malloc intercept (data plane) -----------------------------------------

/// Read the caller's arm64 frame: x29 = our frame pointer, pointing at
/// `[saved_caller_fp, saved_lr]`. So caller_fp = fp[0], the return address into
/// the caller (pc) = fp[1], and the caller's sp at the call site = fp + 16.
/// MUST run directly in the interposed function so x29 is the user→shim frame.
#[inline(always)]
fn capture_user_frame() -> (u64, RegBlockArm64) {
    let our_fp: u64;
    unsafe {
        core::arch::asm!("mov {}, x29", out(reg) our_fp, options(nomem, nostack, preserves_flags));
    }
    let frame = our_fp as *const u64;
    let user_fp = unsafe { *frame };
    let pc = unsafe { *frame.add(1) }; // return address into the caller
    let user_sp = our_fp + 16;
    (user_sp, RegBlockArm64 { pc, lr: pc, fp: user_fp, _padding: 0 })
}

/// Write one AllocMetadata + stack-snapshot record. `in_capture` must already
/// be held; `user_sp`/`regs` come from `capture_user_frame()` run directly in
/// the interposed function.
fn emit_alloc_record(size: u64, sample_size: u64, ptr: *mut c_void, user_sp: u64, regs: RegBlockArm64) {
    let rb = G_RB.load(Ordering::Acquire);
    if rb.is_null() {
        return;
    }
    let rb = unsafe { &*rb };
    let payload_size = std::mem::size_of::<AllocMetadata>() + STACK_SNAPSHOT_BYTES;
    let slot = rb.begin_write(payload_size);
    if slot.is_null() {
        G_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let seq = G_SEQ.fetch_add(1, Ordering::Relaxed);
    let meta = slot as *mut AllocMetadata;
    unsafe {
        (*meta).sequence_number = seq;
        (*meta).alloc_size = size;
        (*meta).sample_size = sample_size;
        (*meta).alloc_address = ptr as u64;
        (*meta).stack_pointer = user_sp;
        (*meta).clock_monotonic_coarse_ts = now_ns();
        (*meta).register_data = [0u8; MAX_REGISTER_DATA_BYTES];
        (*meta).heap_id = 0;
        (*meta).arch = crate::wire::Arch::Arm64 as u32;
        // Pack the user regs at the head of register_data.
        *(std::ptr::addr_of_mut!((*meta).register_data) as *mut RegBlockArm64) = regs;
        // Snapshot the stack from user_sp upward (grows down), clamped to the
        // thread's stack base: a shallow caller (few frames below main) has
        // less than STACK_SNAPSHOT_BYTES of stack above sp, and reading past
        // it lands in a guard region (SIGBUS). The tail is zeroed so the
        // recorder's FP walk terminates instead of chasing stale ring bytes.
        let stack_top = libc::pthread_get_stackaddr_np(libc::pthread_self()) as u64;
        let avail = if stack_top > user_sp { (stack_top - user_sp) as usize } else { 0 };
        let snap = avail.min(STACK_SNAPSHOT_BYTES);
        let snapshot_dst = slot.add(std::mem::size_of::<AllocMetadata>());
        std::ptr::copy_nonoverlapping(user_sp as *const u8, snapshot_dst, snap);
        std::ptr::write_bytes(snapshot_dst.add(snap), 0, STACK_SNAPSHOT_BYTES - snap);
        rb.end_write(slot, payload_size);
    }
    G_EMITTED.fetch_add(1, Ordering::Relaxed);
}

/// Queue one freed pointer into the thread's batch, flushing on full/stale.
/// `in_capture` must already be held. The sequence stamp shares G_SEQ with
/// allocations so the recorder can order a free against a racing reuse of the
/// same address.
fn queue_free(addr: u64) {
    let gen = G_SESSION_GEN.load(Ordering::Acquire);
    T_FREES.with(|cell| {
        let mut b = cell.borrow_mut();
        if b.gen != gen {
            // Entries from a previous session would be unmatched noise in the
            // new session's ring — drop them.
            b.num = 0;
            b.gen = gen;
        }
        let seq = G_SEQ.fetch_add(1, Ordering::Relaxed);
        let n = b.num;
        b.entries[n] = FreeEntry { sequence_number: seq, address: addr };
        b.num = n + 1;
        let now = now_ns();
        if b.num == 1 {
            b.first_ns = now;
        }
        if b.num >= FREE_BATCH_CAP || now.saturating_sub(b.first_ns) > FLUSH_AGE_NS {
            flush_frees(&mut b);
        }
    });
}

/// Write the batch as one FreeBatchHeader + entries ring record.
fn flush_frees(b: &mut FreeBatchTls) {
    if b.num == 0 {
        return;
    }
    let rb = G_RB.load(Ordering::Acquire);
    if !rb.is_null() {
        let rb = unsafe { &*rb };
        let payload_size =
            std::mem::size_of::<FreeBatchHeader>() + b.num * std::mem::size_of::<FreeEntry>();
        let slot = rb.begin_write(payload_size);
        if !slot.is_null() {
            unsafe {
                let hdr = slot as *mut FreeBatchHeader;
                (*hdr).magic = FREE_BATCH_MAGIC;
                (*hdr).num = b.num as u64;
                std::ptr::copy_nonoverlapping(
                    b.entries.as_ptr() as *const u8,
                    slot.add(std::mem::size_of::<FreeBatchHeader>()),
                    b.num * std::mem::size_of::<FreeEntry>(),
                );
                rb.end_write(slot, payload_size);
            }
        } else {
            G_DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }
    b.num = 0;
}

/// The shared alloc-side wrapper: dormant fast path, re-entrancy guard,
/// Poisson decision, frame capture, then `alloc()` and a record when sampled.
/// #[inline(always)] is load-bearing: it (and capture_user_frame's own
/// inline(always)) places the x29 read inside the extern "C" shim's frame, so
/// the walked frame is user→shim.
#[inline(always)]
fn sampled_alloc(size: u64, alloc: impl FnOnce() -> *mut c_void) -> *mut c_void {
    if !G_ENABLED.load(Ordering::Acquire) || in_capture() {
        return alloc();
    }
    set_in_capture(true);
    let sample_size = sample_size_for(size);
    if sample_size == 0 {
        set_in_capture(false);
        return alloc();
    }
    // Capture the caller's frame BEFORE the real allocation (may reuse it).
    let (user_sp, regs) = capture_user_frame();
    let ptr = alloc();
    if !ptr.is_null() {
        emit_alloc_record(size, sample_size, ptr, user_sp, regs);
    }
    set_in_capture(false);
    ptr
}

#[inline(never)]
extern "C" fn sismo_malloc_shim(size: usize) -> *mut c_void {
    sampled_alloc(size as u64, || unsafe { malloc(size) })
}

#[inline(never)]
extern "C" fn sismo_calloc_shim(nmemb: usize, size: usize) -> *mut c_void {
    let total = (nmemb as u64).saturating_mul(size as u64);
    sampled_alloc(total, || unsafe { calloc(nmemb, size) })
}

#[inline(never)]
extern "C" fn sismo_valloc_shim(size: usize) -> *mut c_void {
    sampled_alloc(size as u64, || unsafe { valloc(size) })
}

#[inline(never)]
extern "C" fn sismo_aligned_alloc_shim(align: usize, size: usize) -> *mut c_void {
    sampled_alloc(size as u64, || unsafe { aligned_alloc(align, size) })
}

/// realloc = free(old) + alloc(new): the old pointer is queued as a free and
/// the new allocation is Poisson-sampled, so a site that grows a buffer in
/// place still nets out correctly (freed(old) matches the earlier sampled
/// alloc, if any; the new size re-enters the sample decision).
#[inline(never)]
extern "C" fn sismo_realloc_shim(ptr: *mut c_void, size: usize) -> *mut c_void {
    if !G_ENABLED.load(Ordering::Acquire) || in_capture() {
        return unsafe { realloc(ptr, size) };
    }
    set_in_capture(true);
    if !ptr.is_null() {
        queue_free(ptr as u64);
    }
    let sample_size = sample_size_for(size as u64);
    let (user_sp, regs) = capture_user_frame();
    let new_ptr = unsafe { realloc(ptr, size) };
    if sample_size != 0 && !new_ptr.is_null() {
        emit_alloc_record(size as u64, sample_size, new_ptr, user_sp, regs);
    }
    set_in_capture(false);
    new_ptr
}

#[inline(never)]
extern "C" fn sismo_posix_memalign_shim(memptr: *mut *mut c_void, align: usize, size: usize) -> i32 {
    if !G_ENABLED.load(Ordering::Acquire) || in_capture() {
        return unsafe { posix_memalign(memptr, align, size) };
    }
    set_in_capture(true);
    let sample_size = sample_size_for(size as u64);
    let (user_sp, regs) = capture_user_frame();
    let rc = unsafe { posix_memalign(memptr, align, size) };
    if rc == 0 && sample_size != 0 {
        let ptr = unsafe { *memptr };
        if !ptr.is_null() {
            emit_alloc_record(size as u64, sample_size, ptr, user_sp, regs);
        }
    }
    set_in_capture(false);
    rc
}

/// The free record is queued BEFORE the real free: the address cannot be
/// reused by another thread until libc's free runs, so the (seq-stamped)
/// free is ordered ahead of any subsequent sampled reuse of the address.
#[inline(never)]
extern "C" fn sismo_free_shim(ptr: *mut c_void) {
    if ptr.is_null() || !G_ENABLED.load(Ordering::Acquire) || in_capture() {
        return unsafe { free(ptr) };
    }
    set_in_capture(true);
    queue_free(ptr as u64);
    set_in_capture(false);
    unsafe { free(ptr) }
}

/// dyld's `__interpose` tuples: `{ replacement, original }` redirects every
/// call to an allocator-family symbol to its shim (except the preload's own —
/// so a shim's real-allocator call reaches libc). Signatures differ per
/// symbol, so the pairs are stored as raw code pointers (same ABI as the C
/// `void*` pair).
#[repr(C)]
struct InterposePair {
    new_func: *const c_void,
    orig_func: *const c_void,
}
unsafe impl Sync for InterposePair {}

#[used]
#[link_section = "__DATA,__interpose"]
static SISMO_INTERPOSES: [InterposePair; 7] = [
    InterposePair { new_func: sismo_malloc_shim as *const c_void, orig_func: malloc as *const c_void },
    InterposePair { new_func: sismo_calloc_shim as *const c_void, orig_func: calloc as *const c_void },
    InterposePair { new_func: sismo_realloc_shim as *const c_void, orig_func: realloc as *const c_void },
    InterposePair { new_func: sismo_valloc_shim as *const c_void, orig_func: valloc as *const c_void },
    InterposePair {
        new_func: sismo_aligned_alloc_shim as *const c_void,
        orig_func: aligned_alloc as *const c_void,
    },
    InterposePair {
        new_func: sismo_posix_memalign_shim as *const c_void,
        orig_func: posix_memalign as *const c_void,
    },
    InterposePair { new_func: sismo_free_shim as *const c_void, orig_func: free as *const c_void },
];

#[cfg(test)]
mod tests {
    /// Validate the x29 frame-walk in isolation: a caller whose frame we know,
    /// then a callee that reads x29 and walks one frame back to recover the
    /// caller's saved fp + return address. Confirms the asm + offsets are right
    /// (the same walk the shim does on the user→shim frame).
    #[inline(never)]
    fn callee_reads_caller_frame() -> (u64, u64) {
        let our_fp: u64;
        unsafe {
            core::arch::asm!("mov {}, x29", out(reg) our_fp, options(nomem, nostack, preserves_flags));
        }
        let frame = our_fp as *const u64;
        let caller_fp = unsafe { *frame };
        let ret_addr = unsafe { *frame.add(1) };
        (caller_fp, ret_addr)
    }

    #[inline(never)]
    fn caller() -> (u64, u64, u64) {
        let my_fp: u64;
        unsafe {
            core::arch::asm!("mov {}, x29", out(reg) my_fp, options(nomem, nostack, preserves_flags));
        }
        let (seen_caller_fp, ret_addr) = callee_reads_caller_frame();
        (my_fp, seen_caller_fp, ret_addr)
    }

    #[test]
    fn frame_walk_recovers_the_caller_fp_and_return_addr() {
        let (my_fp, seen_caller_fp, ret_addr) = caller();
        // The callee, walking one frame back from its x29, must recover the
        // caller's frame pointer.
        assert_eq!(seen_caller_fp, my_fp, "walked caller fp must match caller's x29");
        // The recovered return address must point back into `caller`'s code.
        assert!(ret_addr != 0);
        let caller_addr = caller as *const () as u64;
        // The return site is inside `caller` (a few instrs past its entry).
        assert!(
            ret_addr > caller_addr && ret_addr < caller_addr + 0x1000,
            "return addr {ret_addr:#x} not inside caller {caller_addr:#x}"
        );
    }
}
