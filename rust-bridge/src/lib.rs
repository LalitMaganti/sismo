//! Spike: bare-minimum extern "C" facade so we can prove the cargo→staticlib→Zig
//! FFI wiring works end-to-end. Real bridge contents land later.

pub mod symbolizer;
pub mod unwinder;

use std::ptr;
