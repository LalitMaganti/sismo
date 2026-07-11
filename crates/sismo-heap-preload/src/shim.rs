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
use crate::wire::{AllocMetadata, RegBlockArm64, MAX_REGISTER_DATA_BYTES, STACK_SNAPSHOT_BYTES};
use std::cell::{Cell, RefCell};
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};

// ---- libc ------------------------------------------------------------------

// malloc stays hand-declared (not via the libc crate): the __interpose tuple
// below stores this symbol as the original function. Everything else is libc.
extern "C" {
    fn malloc(size: usize) -> *mut c_void;
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

// const-initialized thread-locals: no lazy heap init on first touch (critical —
// the hot path must not allocate).
thread_local! {
    static IN_CAPTURE: Cell<bool> = const { Cell::new(false) };
    static T_SAMPLER: RefCell<Option<Sampler>> = const { RefCell::new(None) };
    static T_SAMPLER_GEN: Cell<u64> = const { Cell::new(0) };
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

#[inline(never)]
extern "C" fn sismo_malloc_shim(size: usize) -> *mut c_void {
    // FAST PATH: dormant — one acquire load + branch.
    if !G_ENABLED.load(Ordering::Acquire) {
        return unsafe { malloc(size) };
    }
    // Re-entrancy guard (the capture path may itself allocate).
    if in_capture() {
        return unsafe { malloc(size) };
    }
    set_in_capture(true);

    // Poisson decision before touching the ring or the stack.
    let sample_size = sample_size_for(size as u64);
    if sample_size == 0 {
        set_in_capture(false);
        return unsafe { malloc(size) };
    }

    // Capture the caller's frame BEFORE the real malloc (which may reuse it).
    let (user_sp, regs) = capture_user_frame();
    let ptr = unsafe { malloc(size) };

    let rb = G_RB.load(Ordering::Acquire);
    if !rb.is_null() {
        let rb = unsafe { &*rb };
        let payload_size = std::mem::size_of::<AllocMetadata>() + STACK_SNAPSHOT_BYTES;
        let slot = rb.begin_write(payload_size);
        if !slot.is_null() {
            let seq = G_SEQ.fetch_add(1, Ordering::Relaxed);
            let meta = slot as *mut AllocMetadata;
            unsafe {
                (*meta).sequence_number = seq;
                (*meta).alloc_size = size as u64;
                (*meta).sample_size = sample_size;
                (*meta).alloc_address = ptr as u64;
                (*meta).stack_pointer = user_sp;
                (*meta).clock_monotonic_coarse_ts = now_ns();
                (*meta).register_data = [0u8; MAX_REGISTER_DATA_BYTES];
                (*meta).heap_id = 0;
                (*meta).arch = crate::wire::Arch::Arm64 as u32;
                // Pack the user regs at the head of register_data.
                *(std::ptr::addr_of_mut!((*meta).register_data) as *mut RegBlockArm64) = regs;
                // Snapshot the stack from user_sp upward (grows down).
                let snapshot_dst = slot.add(std::mem::size_of::<AllocMetadata>());
                std::ptr::copy_nonoverlapping(user_sp as *const u8, snapshot_dst, STACK_SNAPSHOT_BYTES);
            }
            unsafe { rb.end_write(slot, payload_size) };
            G_EMITTED.fetch_add(1, Ordering::Relaxed);
        } else {
            G_DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }

    set_in_capture(false);
    ptr
}

/// dyld's `__interpose` tuple: `{ replacement, original }` redirects all
/// `malloc` calls to the shim (except the preload's own — so the shim's
/// `malloc()` reaches the real one). Stored as typed fn pointers (pointer-sized,
/// same ABI as the C `void*` pair) so no fn→ptr cast is needed.
#[repr(C)]
struct InterposePair {
    new_func: extern "C" fn(usize) -> *mut c_void,
    orig_func: unsafe extern "C" fn(usize) -> *mut c_void,
}
unsafe impl Sync for InterposePair {}

#[used]
#[link_section = "__DATA,__interpose"]
static SISMO_INTERPOSE_MALLOC: InterposePair =
    InterposePair { new_func: sismo_malloc_shim, orig_func: malloc };

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
