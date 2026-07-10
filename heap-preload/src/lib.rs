// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! sismo-heap-preload — the macOS DYLD_INSERT_LIBRARIES heap client.
//!
//! Injected into a target via `DYLD_INSERT_LIBRARIES=…/libsismo_heap.dylib`. A
//! `__mod_init_func` constructor spawns a listener thread; when the recorder
//! attaches (SCM_RIGHTS shm fd over a per-PID socket), the interposed `malloc`
//! streams sampled allocations into the shared ring. Migrated from
//! src/heap_preload_macos.zig (P6).
//!
//! Carries its own tiny copies of the wire layout + ring (attach/write side) +
//! control protocol (listen/accept side) so it links nothing heavy — it must be
//! safe to inject into any process. No allocation on the malloc hot path.
//!
//! Migration in progress: the pure/self-contained pieces (sampler, wire) land
//! first with tests; the ring/protocol server side, the interposer, and the
//! build swap follow.

pub mod protocol;
pub mod ring;
pub mod sampler;
pub mod wire;
