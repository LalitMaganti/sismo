// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! FFI declarations for the Perfetto C++ shim (`crates/sismo-sys/csrc`), the
//! recording control plane the `record`/`datasource` commands drive: producer
//! init, the in-process `traced` + `traced_probes` services, and the consumer
//! session.
//!
//! The data-plane producer ABI (`sismo_ds_*`, the per-packet emit path) lives
//! in [`crate::worker_sdk`] alongside the data-source trampolines it belongs
//! with; the snapshot clone ABI lives in [`crate::cmd_snapshot`]. Both keep
//! their own `#[cfg(test)]` stubs so the standalone test binary links without
//! the shim.

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
