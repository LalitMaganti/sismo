//! OS dispatcher for the heap-profiler control channel. Re-exports
//! the per-OS implementation so consumers (heap_capture, heap_preload_*,
//! cmd_record) only ever say `@import("heap_protocol.zig")`.
//!
//! Per-OS implementations:
//! - POSIX (macOS, Linux): `heap_protocol_posix.zig` — Unix socket +
//!   SCM_RIGHTS fd passing.
//! - Windows: `heap_protocol_windows.zig` — TODO (named pipe +
//!   DuplicateHandle).

const builtin = @import("builtin");

const impl = if (builtin.os.tag == .windows)
    @import("heap_protocol_windows.zig")
else
    @import("heap_protocol_posix.zig");

pub const ProtocolError = impl.ProtocolError;
pub const AttachConfig = impl.AttachConfig;
pub const AttachState = impl.AttachState;
pub const Listener = impl.Listener;
pub const socketPath = impl.socketPath;
pub const listenForAttach = impl.listenForAttach;
pub const acceptAndReceive = impl.acceptAndReceive;
pub const connectAndAttach = impl.connectAndAttach;
