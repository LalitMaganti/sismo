// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! FFI declarations for the Perfetto C++ shim (`crates/sismo-sys/csrc`), the
//! recording control plane the `record`/`datasource` commands drive: producer
//! init, the in-process `traced` + `traced_probes` services, and the consumer
//! session.
//!
//! The data-plane producer ABI (`sismo_ds_*`, the per-packet emit path) and its
//! data-source callback types live below; the snapshot clone ABI is used by the
//! `sismo-cli` crate's snapshot command, which keeps its own `#[cfg(test)]` stub.
//! The
//! `#[cfg(test)]` stubs here let the standalone test binary link without the
//! C++ shim. [`crate::worker_sdk`] holds the `Event` primitive the workers pair
//! with this ABI.

use std::os::raw::{c_char, c_int, c_void};

/// Opaque handle to an in-process `traced` service (tracing daemon).
#[repr(C)]
pub struct TracedSvc {
    _opaque: [u8; 0],
}

/// Opaque handle to a consumer session (owns one tracing session's lifecycle).
#[repr(C)]
pub struct ConsumerSession {
    _opaque: [u8; 0],
}

extern "C" {
    /// Connect the in-process producer to `producer_socket`. Must run before any
    /// data source registers.
    pub fn sismo_init(producer_socket: *const c_char);

    pub fn sismo_traced_create(
        producer_socket: *const c_char,
        consumer_socket: *const c_char,
    ) -> *mut TracedSvc;
    pub fn sismo_traced_stop(svc: *mut TracedSvc);
    pub fn sismo_traced_destroy(svc: *mut TracedSvc);

    pub fn sismo_traced_probes_create(producer_socket: *const c_char) -> *mut c_void;
    pub fn sismo_traced_probes_stop(svc: *mut c_void);
    pub fn sismo_traced_probes_destroy(svc: *mut c_void);

    pub fn sismo_consumer_session_create() -> *mut ConsumerSession;
    pub fn sismo_consumer_session_setup(
        session: *mut ConsumerSession,
        cfg: *const c_void,
        cfg_len: usize,
    ) -> c_int;
    pub fn sismo_consumer_session_start_blocking(session: *mut ConsumerSession);
    pub fn sismo_consumer_session_stop_blocking(session: *mut ConsumerSession);
    pub fn sismo_consumer_session_destroy(session: *mut ConsumerSession);
    pub fn sismo_consumer_query_service_state(
        session: *mut ConsumerSession,
        out_buf: *mut c_void,
        out_buf_size: usize,
        written: *mut usize,
    ) -> c_int;
}

// ---- Snapshot clone (flight-recorder consumer stream) ----------------------

/// Chunk callback the clone stream invokes with each slice of trace bytes.
pub type ChunkCb =
    extern "C" fn(data: *const c_void, size: usize, has_more: bool, user_arg: *mut c_void);

#[cfg(not(test))]
extern "C" {
    pub fn sismo_consumer_clone_and_stream(
        name: *const c_char,
        cb: ChunkCb,
        user_arg: *mut c_void,
    ) -> c_int;
}

#[cfg(test)]
pub unsafe extern "C" fn sismo_consumer_clone_and_stream(
    _name: *const c_char,
    _cb: ChunkCb,
    _user_arg: *mut c_void,
) -> c_int {
    0
}

// ---- Data-plane producer ABI (per data-source emit path) -------------------

/// Data-source lifecycle callbacks (invoked by the SDK on its IO thread).
pub type OnSetup = extern "C" fn(*mut c_void, *const c_void, usize);
pub type OnStart = extern "C" fn(*mut c_void);
pub type OnStop = extern "C" fn(*mut c_void, *mut c_void);
pub type OnFlush = extern "C" fn(*mut c_void, *mut c_void);

#[cfg(not(test))]
extern "C" {
    pub fn sismo_ds_register(
        desc_bytes: *const u8,
        desc_len: usize,
        on_setup: OnSetup,
        on_start: OnStart,
        on_stop: OnStop,
        on_flush: OnFlush,
        user_arg: *mut c_void,
    ) -> u32;
    pub fn sismo_ds_emit(slot: u32, packet_bytes: *const u8, packet_len: usize);
    pub fn sismo_stop_done(handle: *mut c_void);
    pub fn sismo_flush_done(handle: *mut c_void);
}

// cargo test links the rlib standalone with no C++ shim; stub the producer ABI
// (once, here) so the test binary resolves these #[no_mangle] symbols.
#[cfg(test)]
mod stubs {
    use super::{OnFlush, OnSetup, OnStart, OnStop};
    use std::os::raw::c_void;
    #[no_mangle]
    pub unsafe extern "C" fn sismo_ds_register(
        _d: *const u8,
        _dl: usize,
        _s: OnSetup,
        _st: OnStart,
        _sp: OnStop,
        _f: OnFlush,
        _u: *mut c_void,
    ) -> u32 {
        u32::MAX
    }
    #[no_mangle]
    pub unsafe extern "C" fn sismo_ds_emit(_slot: u32, _b: *const u8, _l: usize) {}
    #[no_mangle]
    pub unsafe extern "C" fn sismo_stop_done(_h: *mut c_void) {}
    #[no_mangle]
    pub unsafe extern "C" fn sismo_flush_done(_h: *mut c_void) {}
}
#[cfg(test)]
pub use stubs::{sismo_ds_emit, sismo_ds_register, sismo_flush_done, sismo_stop_done};
