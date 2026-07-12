// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.
//
//! Shared kdebug-ring abstraction: the wire record types the kernel drains into
//! caller buffers, and the [`RingConsumer`] contract the ring host fans events
//! out to.
//!
//! The kdebug ring is a machine-global singleton, so its consumers (the sched
//! timeline, off-CPU lazy.wait samples, on-CPU timer samples) can't each own a
//! ring — they share one, hosted by `ring_host`. Each consumer declares the
//! `(class<<8)|subclass` ranges it needs (the host unions them into the ring's
//! typefilter) and processes each drained batch. The per-data-source control
//! state the SDK trampolines poke lives in [`ConsumerCtl`], shared (Arc) between
//! the host's trampolines and the worker-thread consumer.
//!
//! macOS-only; gated in sched/mod.rs.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize};

/// A kdebug ring record — 64 bytes on arm64, read directly from the ring by
/// `KdebugRing::drain`. `arg5` is the kernel-stamped thread id of whatever was
/// running when the event was logged (kperf sample events key on it). The record
/// is the single event currency every consumer sees.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KdEvent {
    pub timestamp: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
    pub debugid: u32,
    pub cpuid: u32,
    pub unused: u64,
}

impl KdEvent {
    /// A zeroed record, for sizing drain buffers.
    pub const ZERO: KdEvent = KdEvent {
        timestamp: 0,
        arg1: 0,
        arg2: 0,
        arg3: 0,
        arg4: 0,
        arg5: 0,
        debugid: 0,
        cpuid: 0,
        unused: 0,
    };

    /// Event code from the debugid: `(debugid & KDBG_CODE_MASK) >> KDBG_CODE_OFFSET`.
    pub fn code(&self) -> u32 {
        (self.debugid & 0x0000_fffc) >> 2
    }
}

/// A kd_threadmap entry — 32 bytes. `pid` is the owning process; `command` is
/// the (nul-padded) short thread/process name.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KdThreadMap {
    pub thread: u64,
    pub pid: i32,
    pub command: [u8; 20],
}

impl KdThreadMap {
    pub const ZERO: KdThreadMap = KdThreadMap { thread: 0, pid: 0, command: [0; 20] };

    /// The command as a nul-terminated slice.
    pub fn command_bytes(&self) -> &[u8] {
        let n = self.command.iter().position(|&b| b == 0).unwrap_or(self.command.len());
        &self.command[..n]
    }
}

/// Per-data-source control block, shared (Arc) between the host's SDK
/// trampolines (which flip `running` and stash a `pending_stopper`) and the
/// worker-thread consumer (which reads `ds_slot` to emit and bumps `samples`).
/// All-atomic so it's `Sync` for the cross-thread sharing.
pub struct ConsumerCtl {
    /// The registered data-source slot (u32::MAX until registration succeeds).
    pub ds_slot: AtomicU32,
    /// True between on_start and on_stop — gates emission.
    pub running: AtomicBool,
    /// A stop callback's `stopper` pointer, stashed for the worker to ack after
    /// a final drain (0 = none). Stored as usize so it's atomic.
    pub pending_stopper: AtomicUsize,
    /// Consumer-defined sample/event counter, reported at shutdown.
    pub samples: AtomicU64,
}

impl ConsumerCtl {
    pub fn new() -> Self {
        ConsumerCtl {
            ds_slot: AtomicU32::new(u32::MAX),
            running: AtomicBool::new(false),
            pending_stopper: AtomicUsize::new(0),
            samples: AtomicU64::new(0),
        }
    }
}

impl Default for ConsumerCtl {
    fn default() -> Self {
        Self::new()
    }
}

/// A consumer of the shared kdebug ring, living on the host's worker thread. It
/// holds its own decode + emit state; the host drains the ring once per interval
/// and hands the whole batch (plus the current thread map, for name resolution)
/// to every running consumer.
pub trait RingConsumer {
    /// The `(class<<8)|subclass` ranges (inclusive) this consumer needs present
    /// in the ring's typefilter. The host unions these across consumers.
    fn csc_ranges(&self) -> &[(u16, u16)];

    /// Process one drained batch of events (in timestamp order) with the current
    /// thread map. Called only when this consumer's data source is running.
    fn on_drain(&mut self, events: &[KdEvent], thread_map: &[KdThreadMap]);
}
