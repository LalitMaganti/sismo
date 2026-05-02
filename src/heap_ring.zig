//! OS dispatcher for the heap-profiler shared-memory ring. Re-exports
//! the per-OS implementation so consumers (heap_capture, heap_preload_*)
//! only ever say `@import("heap_ring.zig")`.
//!
//! Per-OS implementations:
//! - POSIX (macOS, Linux): `heap_ring_posix.zig` — `shm_open` + the
//!   double-mmap mirror trick from heapprofd.
//! - Windows: `heap_ring_windows.zig` — TODO (`CreateFileMappingW` +
//!   `MapViewOfFileEx` to land the mirror at the right address).

const builtin = @import("builtin");

const impl = if (builtin.os.tag == .windows)
    @import("heap_ring_windows.zig")
else
    @import("heap_ring_posix.zig");

pub const HEADER_BYTES = impl.HEADER_BYTES;
pub const RECORD_ALIGN = impl.RECORD_ALIGN;
pub const RingError = impl.RingError;
pub const MetadataPage = impl.MetadataPage;
pub const RingBuffer = impl.RingBuffer;
