// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Cross-platform compile sentinel. `zig build check -Dtarget=…` builds
//! this file as an object (no link, no install) for the target, catching
//! cross-platform regressions in the remaining OS-portable Zig
//! (proto_writer, sismo_paths) without needing Perfetto or rust-bridge.
//!
//! cmd_record isn't checked here: it @embedFiles the build-generated
//! sched.bpf.o, which this standalone object can't provide. The real
//! per-OS builds cover it.
//!
//! Calling each public function forces the semantic analyzer to visit
//! its body. The file is never executed — calls are wrapped in `catch {}`
//! and may run with garbage args; correctness isn't the point.

const std = @import("std");
const builtin = @import("builtin");

const proto_writer = @import("proto_writer.zig");

comptime {
    _ = proto_writer;
}

pub export fn sismo_check_posix() void {
    if (comptime builtin.os.tag == .windows) return;
    const sismo_paths = @import("sismo_paths.zig");
    const io: std.Io = undefined;
    _ = sismo_paths.acquireSessionLock(1) catch {};
    sismo_paths.releaseSessionLock(1);
    _ = sismo_paths.readRecorderPid() catch {};
    _ = sismo_paths.heapDylibPath(io, std.heap.page_allocator) catch {};
}
