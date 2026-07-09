// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Cross-platform compile sentinel. `zig build check -Dtarget=…` builds
//! this file as an object (no link, no install) for the target, catching
//! cross-platform regressions in OS-portable code (heap_wire,
//! proto_writer, sismo_config, …) and the per-OS dispatcher modules
//! (heap_protocol, heap_ring) without needing Perfetto or rust-bridge.
//!
//! Calling each public function forces the semantic analyzer to visit
//! its body. The file is never executed — calls are wrapped in `catch {}`
//! and may run with garbage args; correctness isn't the point.

const std = @import("std");
const builtin = @import("builtin");

const heap_wire = @import("heap_wire.zig");
const proto_writer = @import("proto_writer.zig");
const sismo_config = @import("sismo_config.zig");
const heap_protocol = @import("heap_protocol.zig");
const heap_ring = @import("heap_ring.zig");

comptime {
    _ = heap_wire;
    _ = proto_writer;
    _ = sismo_config;
}

pub export fn sismo_check_cmds() void {
    // Windows excluded: the cmd_* subcommands use POSIX primitives
    // (flock-based session lock, posix_spawnp, POSIX Args.iterate) with
    // no direct Windows equivalents yet, so the Windows build is
    // sample-target only.
    if (comptime builtin.os.tag == .windows) return;
    const init: std.process.Init = undefined;
    @import("cmd_record.zig").runRecord(init) catch {};
    @import("cmd_prepare.zig").runPrepare(init) catch {};
    // cmd_snapshot now lives in Rust (rust-bridge/src/cmd_snapshot.rs).
    @import("cmd_datasource.zig").runDatasource(init) catch {};
}

pub export fn sismo_check_dispatchers() void {
    var path_buf: [128]u8 = undefined;
    _ = heap_protocol.socketPath(1, &path_buf) catch {};
    var listener = heap_protocol.listenForAttach(1) catch return;
    defer listener.close();
    _ = heap_protocol.acceptAndReceive(&listener) catch {};

    _ = heap_ring.RingBuffer.create(4096) catch {};
    _ = heap_ring.RingBuffer.attach(0, 4096) catch {};
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
