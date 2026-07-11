// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! macOS CPU-samples capture worker. Owns its worker thread and the C++ SDK
//! data-source lifecycle (on_setup/start/stop/flush trampolines); the
//! per-sample work, module registration, config decode, and unwinding live in
//! the Rust paths it calls. cmd_record drives it via `sismo_cpu_capture_init` /
//! `sismo_cpu_capture_shutdown`.
//!
//! The producer C ABI (`sismo_ds_*`) is provided by the C++ shim in the final
//! binary; `#[cfg(test)]` stubs stand in so `cargo test` links standalone.
//!
//! macOS/arm64 only; gated in lib.rs.

use crate::proto::sismo_config::{config_extract, cpu_decode};
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

const DS_NAME: &[u8] = b"sismo.macos_cpu_samples";
const DEFAULT_INTERVAL_NS: u64 = 1_000_000; // 1 kHz
const U32_MAX: u32 = u32::MAX;

// ---- Mach thread enumeration (task_for_pid + task_threads + thread_info) ----

type MachPort = u32;
const KERN_SUCCESS: i32 = 0;
const THREAD_BASIC_INFO: i32 = 3;
const THREAD_BASIC_INFO_COUNT: u32 = 10;
const THREAD_IDENTIFIER_INFO: i32 = 4;
const THREAD_IDENTIFIER_INFO_COUNT: u32 = 6;

extern "C" {
    static mach_task_self_: MachPort;
    fn task_for_pid(target_tport: MachPort, pid: i32, t: *mut MachPort) -> i32;
    fn task_threads(task: MachPort, act_list: *mut *mut MachPort, act_count: *mut u32) -> i32;
    fn thread_info(target: MachPort, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
    fn mach_port_deallocate(task: MachPort, name: MachPort) -> i32;
    fn mach_vm_deallocate(target: MachPort, address: u64, size: u64) -> i32;
}

fn read_i32(b: &[u8], off: usize) -> i32 {
    i32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn read_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

unsafe fn thread_cpu_time_us(thread: MachPort) -> Option<u64> {
    let mut buf = [0u8; 40];
    let mut count = THREAD_BASIC_INFO_COUNT;
    if unsafe { thread_info(thread, THREAD_BASIC_INFO, buf.as_mut_ptr() as *mut i32, &mut count) }
        != KERN_SUCCESS
    {
        return None;
    }
    // user_time (@0) + system_time (@8), each { i32 sec; i32 usec }.
    let us = |so: usize, uo: usize| read_i32(&buf, so) as u64 * 1_000_000 + read_i32(&buf, uo) as u64;
    Some(us(0, 4) + us(8, 12))
}

unsafe fn thread_kernel_tid(thread: MachPort) -> u64 {
    let mut buf = [0u8; 24];
    let mut count = THREAD_IDENTIFIER_INFO_COUNT;
    if unsafe {
        thread_info(thread, THREAD_IDENTIFIER_INFO, buf.as_mut_ptr() as *mut i32, &mut count)
    } != KERN_SUCCESS
    {
        return 0;
    }
    read_u64(&buf, 0) // thread_id
}

// Producer C ABI lives in ffi; the worker Event in worker_sdk.
use crate::ffi::{sismo_ds_emit, sismo_ds_register, sismo_flush_done, sismo_stop_done};
use crate::worker_sdk::Event;

// The rest of the pipeline is already Rust — call the sibling modules directly
// (no FFI round-trip): descriptor encoding, unwinder lifecycle, module loading,
// and per-sample capture.
use crate::symbolize::dyld_images::load_target_modules;
use crate::cpu::mach_sampler::sample_thread;
use crate::proto::session_config::encode_data_source_descriptor;
use crate::symbolize::unwinder::Unwinder;

// ---- Worker ----------------------------------------------------------------

/// Shared worker state. All fields are Sync (atomics / Mutex) so the trampolines
/// (SDK threads) and the worker thread can share `&CpuCapture` via a raw pointer.
pub struct CpuCapture {
    ds_slot: AtomicU32,
    config_interval_ns: u64,

    wakeup: Event,
    running: AtomicBool,
    exit_requested: AtomicBool,
    pending_stopper: AtomicUsize,

    setup_received: AtomicBool,
    // Decoded from on_setup's DataSourceConfig.
    setup_target_pid: AtomicU32,
    setup_interval_us: AtomicU32,

    target_pid: AtomicU32, // resolved (setup or default), read by the loop

    samples: AtomicU64,
    active_samples: AtomicU64,

    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

fn as_ref<'a>(p: *mut c_void) -> &'a CpuCapture {
    unsafe { &*(p as *const CpuCapture) }
}

extern "C" fn on_setup(user_arg: *mut c_void, dsc_bytes: *const c_void, dsc_size: usize) {
    let self_ = as_ref(user_arg);
    // Extract sismo_config (field 2000) then decode target_pid + interval_us.
    if !dsc_bytes.is_null() {
        let dsc = unsafe { std::slice::from_raw_parts(dsc_bytes as *const u8, dsc_size) };
        if let Some((pid, interval_us)) = config_extract(dsc).and_then(cpu_decode) {
            self_.setup_target_pid.store(pid, Ordering::Release);
            self_.setup_interval_us.store(interval_us, Ordering::Release);
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

extern "C" fn on_flush(_user_arg: *mut c_void, flusher: *mut c_void) {
    // Emits happen synchronously in the sampling loop; nothing buffered — ack
    // immediately on the SDK thread, no worker involvement needed.
    if !flusher.is_null() {
        unsafe { sismo_flush_done(flusher) };
    }
}


impl CpuCapture {
    fn park_until_exit(&self) {
        loop {
            self.wakeup.reset();
            if self.exit_requested.load(Ordering::Acquire) {
                return;
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
        // Wait for on_setup (carries target_pid).
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
        let interval_us = self.setup_interval_us.load(Ordering::Acquire);
        let interval_ns = if interval_us != 0 {
            interval_us as u64 * 1_000
        } else {
            self.config_interval_ns
        };
        if target_pid == 0 {
            eprintln!("cpu_sampler: SismoMacosCpuSamplesConfig.target_pid not set — bailing");
            self.park_until_exit();
            return;
        }
        self.target_pid.store(target_pid, Ordering::Release);

        let mut task: MachPort = 0;
        if unsafe { task_for_pid(mach_task_self_, target_pid as i32, &mut task) } != KERN_SUCCESS {
            eprintln!(
                "cpu_sampler: task_for_pid({target_pid}) failed — need sudo or the\n  com.apple.security.cs.debugger entitlement."
            );
            self.park_until_exit();
            return;
        }

        let mut unwinder = Unwinder::new_arm64();

        // Register the target's modules into the unwinder (Rust). No symbolizer
        // — cpu samples are symbolized post-record. The returned image list is
        // unused here (cpu doesn't emit mappings), so it drops immediately.
        if let Err(load_err) = load_target_modules(
            task,
            None,
            Some(&mut unwinder),
            50 * 1_000_000,
            5 * 1_000_000_000,
            || self.exit_requested.load(Ordering::Acquire),
        ) {
            eprintln!("cpu_sampler: load_target_modules failed (err={load_err})");
            self.park_until_exit();
            return;
        }

        // thread port -> (tid, last_cpu_us)
        let mut thread_states: std::collections::HashMap<MachPort, (u64, u64)> =
            std::collections::HashMap::new();
        let mut threadlist_was_ok = true;
        let slot = self.ds_slot.load(Ordering::Acquire);
        let pid = self.target_pid.load(Ordering::Acquire);

        loop {
            self.wakeup.reset();
            if self.exit_requested.load(Ordering::Acquire) {
                break;
            }

            if self.running.load(Ordering::Acquire) {
                let mut list: *mut MachPort = std::ptr::null_mut();
                let mut count: u32 = 0;
                let rc = unsafe { task_threads(task, &mut list, &mut count) };
                if rc != KERN_SUCCESS {
                    if threadlist_was_ok {
                        eprintln!("cpu_sampler: threadList failed (suppressing until recovery)");
                        threadlist_was_ok = false;
                    }
                } else {
                    if !threadlist_was_ok {
                        eprintln!("cpu_sampler: threadList recovered");
                        threadlist_was_ok = true;
                    }
                    let threads = unsafe { std::slice::from_raw_parts(list, count as usize) };
                    for &t in threads {
                        self.sample_one(task, t, &mut unwinder, pid, slot, &mut thread_states);
                    }
                    // Free the Mach-allocated thread-port array.
                    for &t in threads {
                        unsafe { mach_port_deallocate(task, t) };
                    }
                    unsafe {
                        mach_vm_deallocate(
                            task,
                            list as u64,
                            (count as u64) * std::mem::size_of::<MachPort>() as u64,
                        )
                    };
                }
            }

            let stopper = self.pending_stopper.swap(0, Ordering::AcqRel);
            if stopper != 0 {
                unsafe { sismo_stop_done(stopper as *mut c_void) };
                self.running.store(false, Ordering::Release);
            }

            if self.exit_requested.load(Ordering::Acquire) {
                break;
            }

            if self.running.load(Ordering::Acquire) {
                self.wakeup.wait_timeout(Duration::from_nanos(interval_ns));
            } else {
                self.wakeup.wait();
            }
        }
    }

    fn sample_one(
        &self,
        task: MachPort,
        thread: MachPort,
        unwinder: &mut Unwinder,
        pid: u32,
        slot: u32,
        states: &mut std::collections::HashMap<MachPort, (u64, u64)>,
    ) {
        self.samples.fetch_add(1, Ordering::Relaxed);
        let entry = states.entry(thread).or_insert_with(|| {
            let tid = unsafe { thread_kernel_tid(thread) };
            let cpu = unsafe { thread_cpu_time_us(thread) }.unwrap_or(0);
            (tid, cpu)
        });
        let (tid, last_cpu_us) = *entry;

        let sample = sample_thread(task, thread, unwinder, pid, tid, last_cpu_us);
        entry.1 = sample.new_cpu_us;
        if sample.active {
            self.active_samples.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(packet) = sample.packet {
            unsafe { sismo_ds_emit(slot, packet.as_ptr(), packet.len()) };
        }
    }
}

/// Create the CPU-samples capture: register the data source and spawn the
/// worker thread. Returns an opaque handle, or null on registration failure.
///
/// # Safety
/// The returned pointer must be passed to `sismo_cpu_capture_shutdown` exactly
/// once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_cpu_capture_init(default_interval_ns: u64) -> *mut CpuCapture {
    let interval = if default_interval_ns != 0 { default_interval_ns } else { DEFAULT_INTERVAL_NS };
    let cap = Box::into_raw(Box::new(CpuCapture {
        ds_slot: AtomicU32::new(U32_MAX),
        config_interval_ns: interval,
        wakeup: Event::new(),
        running: AtomicBool::new(false),
        exit_requested: AtomicBool::new(false),
        pending_stopper: AtomicUsize::new(0),
        setup_received: AtomicBool::new(false),
        setup_target_pid: AtomicU32::new(0),
        setup_interval_us: AtomicU32::new(0),
        target_pid: AtomicU32::new(0),
        samples: AtomicU64::new(0),
        active_samples: AtomicU64::new(0),
        thread: Mutex::new(None),
    }));

    // Register the data source (descriptor built via the Rust encoder).
    let desc = encode_data_source_descriptor(DS_NAME, true, false, &[]);
    let slot = unsafe {
        sismo_ds_register(
            desc.as_ptr(),
            desc.len(),
            on_setup,
            on_start,
            on_stop,
            on_flush,
            cap as *mut c_void,
        )
    };
    if slot == U32_MAX {
        drop(unsafe { Box::from_raw(cap) });
        return std::ptr::null_mut();
    }
    unsafe { (*cap).ds_slot.store(slot, Ordering::Release) };

    // Spawn the worker thread. It shares `&CpuCapture` via the raw pointer,
    // which stays valid until shutdown joins the thread and frees the box.
    let cap_addr = cap as usize;
    let handle = std::thread::spawn(move || {
        let self_ = unsafe { &*(cap_addr as *const CpuCapture) };
        self_.run();
    });
    *unsafe { &*cap }.thread.lock().unwrap() = Some(handle);
    cap
}

/// Signal exit, join the worker thread, write stats, and free the capture.
///
/// # Safety
/// `cap` must be a pointer from `sismo_cpu_capture_init`, passed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_cpu_capture_shutdown(
    cap: *mut CpuCapture,
    out_samples: *mut u64,
    out_active_samples: *mut u64,
) {
    if cap.is_null() {
        return;
    }
    let self_ = unsafe { &*cap };
    self_.exit_requested.store(true, Ordering::Release);
    self_.wakeup.set();
    let handle = self_.thread.lock().unwrap().take();
    if let Some(h) = handle {
        let _ = h.join();
    }
    unsafe {
        *out_samples = self_.samples.load(Ordering::Relaxed);
        *out_active_samples = self_.active_samples.load(Ordering::Relaxed);
    }
    drop(unsafe { Box::from_raw(cap) });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_thread_cpu_time_and_tid_readable() {
        extern "C" {
            fn mach_thread_self() -> MachPort;
        }
        let t = unsafe { mach_thread_self() };
        assert!(unsafe { thread_cpu_time_us(t) }.is_some());
        // tid may be 0 in odd sandboxes, but the call must not crash.
        let _ = unsafe { thread_kernel_tid(t) };
    }
}
