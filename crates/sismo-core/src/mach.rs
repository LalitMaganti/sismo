// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Mach primitives the `libc` crate doesn't cover, centralized so the macOS
//! capture workers share one declaration instead of re-hand-rolling per file.
//!
//! Two reasons a symbol lands here rather than coming from `libc`:
//!   - **absent** — libc has no binding (`mach_vm_read_overwrite`,
//!     `mach_vm_deallocate`, `mach_port_deallocate`, `thread_suspend`,
//!     `thread_resume`, `thread_get_state`).
//!   - **deprecated** — libc exposes it but points at the `mach2` crate, so
//!     using it trips `deprecated` warnings (`mach_task_self_`,
//!     `mach_thread_self`, the `mach_timebase_info` struct).
//!
//! Everything libc DOES cover cleanly (clock_gettime, task_for_pid,
//! task_threads, thread_info, task_info, …) is called through `libc` directly.
//!
//! `sismo-symbolize`'s dyld_images re-declares `mach_vm_read_overwrite` locally
//! rather than sharing this module — it sits in a crate below sismo-core, so it
//! can't reach here.
//!
//! macOS-only; gated in lib.rs.

/// A mach port name (task or thread port). `mach_port_t` in <mach/port.h>.
pub type MachPort = u32;

/// A Mach `kern_return_t` success (KERN_SUCCESS).
pub const KERN_SUCCESS: i32 = 0;

/// `mach_timebase_info_data_t` — numer/denom for scaling mach_absolute_time.
#[repr(C)]
pub struct TimebaseInfo {
    pub numer: u32,
    pub denom: u32,
}

extern "C" {
    pub static mach_task_self_: MachPort;
    pub fn mach_thread_self() -> MachPort;
    pub fn mach_timebase_info(info: *mut TimebaseInfo) -> i32;
    pub fn thread_suspend(target: MachPort) -> i32;
    pub fn thread_resume(target: MachPort) -> i32;
    pub fn thread_get_state(
        target: MachPort,
        flavor: i32,
        state: *mut i32,
        count: *mut u32,
    ) -> i32;
    pub fn mach_vm_read_overwrite(
        target: MachPort,
        address: u64,
        size: u64,
        data: u64,
        out_size: *mut u64,
    ) -> i32;
    pub fn mach_port_deallocate(task: MachPort, name: MachPort) -> i32;
    pub fn mach_vm_deallocate(target: MachPort, address: u64, size: u64) -> i32;
}
