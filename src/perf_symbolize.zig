// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Post-record symbolization for perf CPU samples.
//!
//! traced_perf writes raw stack frames as (mapping, rel_pc) pairs with no
//! function names — perfetto leaves symbolization to an offline step. This
//! module is that step for sismo: it pulls the unsymbolized frames out of
//! the recorded trace via the trace_processor C++ library (src/c/
//! sismo_trace_query.cc), resolves each with wholesym (src/symbolizer.zig),
//! and appends `ModuleSymbols` packets that trace_processor matches back to
//! the frames by (build_id, address).
//!
//! Address convention (validated against a non-PIE x86-64 binary and the
//! PIE libc): trace_processor's `rel_pc` is the module-relative virtual
//! address that an emitted `AddressSymbols.address` must equal. wholesym's
//! `LookupAddress::Relative` wants `rel_pc - load_bias`, which the bridge
//! computes as `avma - base_avma` — so we register each module at
//! `base_avma = load_bias` and resolve `rel_pc` directly.

const std = @import("std");
const builtin = @import("builtin");
const ProtoWriter = @import("proto_writer.zig").ProtoWriter;
const symbolizer = @import("symbolizer.zig");

// Field tags, inlined from protos/perfetto/trace/{trace_packet,profiling/
// profile_common}.proto.
const TP_FIELD_TRACE_PACKET: u32 = 1;
const TP_FIELD_MODULE_SYMBOLS: u32 = 61;
const MS_FIELD_PATH: u32 = 1;
const MS_FIELD_BUILD_ID: u32 = 2;
const MS_FIELD_ADDRESS_SYMBOLS: u32 = 3;
const AS_FIELD_ADDRESS: u32 = 1;
const AS_FIELD_LINES: u32 = 2;
const LINE_FIELD_FUNCTION_NAME: u32 = 1;

extern "c" fn sismo_trace_query_unsymbolized(
    trace_path: [*:0]const u8,
    cb: *const fn (
        ctx: ?*anyopaque,
        name: [*]const u8,
        name_len: usize,
        build_id: [*]const u8,
        build_id_len: usize,
        rel_pc: u64,
        load_bias: u64,
    ) callconv(.c) void,
    ctx: ?*anyopaque,
) c_int;

const Module = struct {
    name: []u8,
    build_id_hex: []u8,
    load_bias: u64,
    rel_pcs: std.ArrayList(u64) = .empty,
    seen: std.AutoHashMapUnmanaged(u64, void) = .empty,
};

const Collector = struct {
    gpa: std.mem.Allocator,
    modules: std.ArrayList(Module) = .empty,
    failed: bool = false,

    fn deinit(self: *Collector) void {
        for (self.modules.items) |*m| {
            self.gpa.free(m.name);
            self.gpa.free(m.build_id_hex);
            m.rel_pcs.deinit(self.gpa);
            m.seen.deinit(self.gpa);
        }
        self.modules.deinit(self.gpa);
    }
};

/// Per-row callback: rows arrive grouped by (name, build_id, load_bias), so
/// we extend the trailing module while the key matches and start a new one
/// when it changes. Duplicate rel_pcs (many samples hitting one address)
/// are collapsed via `seen`.
fn onRow(
    ctx: ?*anyopaque,
    name_ptr: [*]const u8,
    name_len: usize,
    build_id_ptr: [*]const u8,
    build_id_len: usize,
    rel_pc: u64,
    load_bias: u64,
) callconv(.c) void {
    const self: *Collector = @ptrCast(@alignCast(ctx.?));
    if (self.failed) return;
    const name = name_ptr[0..name_len];
    const build_id = build_id_ptr[0..build_id_len];

    collect(self, name, build_id, load_bias, rel_pc) catch {
        self.failed = true;
    };
}

fn collect(
    self: *Collector,
    name: []const u8,
    build_id: []const u8,
    load_bias: u64,
    rel_pc: u64,
) !void {
    const gpa = self.gpa;
    const cur: ?*Module = if (self.modules.items.len == 0)
        null
    else
        &self.modules.items[self.modules.items.len - 1];

    const same = cur != null and
        cur.?.load_bias == load_bias and
        std.mem.eql(u8, cur.?.name, name) and
        std.mem.eql(u8, cur.?.build_id_hex, build_id);

    const m = if (same) cur.? else blk: {
        try self.modules.append(gpa, .{
            .name = try gpa.dupe(u8, name),
            .build_id_hex = try gpa.dupe(u8, build_id),
            .load_bias = load_bias,
        });
        break :blk &self.modules.items[self.modules.items.len - 1];
    };

    const gop = try m.seen.getOrPut(gpa, rel_pc);
    if (!gop.found_existing) try m.rel_pcs.append(gpa, rel_pc);
}

/// Read the unsymbolized frames from `trace_path`, resolve them, and append
/// `ModuleSymbols` packets to the same file. Best-effort: any failure is
/// logged and swallowed so a symbolization problem never loses a recording.
pub fn symbolizeTrace(gpa: std.mem.Allocator, io: std.Io, trace_path: []const u8) void {
    symbolizeTraceImpl(gpa, io, trace_path) catch |err| {
        std.debug.print("sismo record: symbolization skipped ({s})\n", .{@errorName(err)});
    };
}

fn symbolizeTraceImpl(gpa: std.mem.Allocator, io: std.Io, trace_path: []const u8) !void {
    const path_z = try gpa.dupeZ(u8, trace_path);
    defer gpa.free(path_z);

    var collector: Collector = .{ .gpa = gpa };
    defer collector.deinit();

    const rc = sismo_trace_query_unsymbolized(path_z.ptr, &onRow, &collector);
    if (rc != 0) return error.QueryFailed;
    if (collector.failed) return error.OutOfMemory;
    if (collector.modules.items.len == 0) return; // nothing to symbolize

    const sym = try symbolizer.create();
    defer symbolizer.destroy(sym);

    var out = ProtoWriter.init(gpa);
    defer out.deinit();
    var n_funcs: usize = 0;
    var n_addrs: usize = 0;

    for (collector.modules.items) |*m| {
        if (m.rel_pcs.items.len == 0) continue;
        const ms = try buildModuleSymbols(gpa, sym, m, &n_funcs, &n_addrs);
        defer gpa.free(ms);
        if (ms.len == 0) continue;
        // Wrap the ModuleSymbols body in TracePacket.module_symbols (61),
        // then the packet in Trace.packet (1).
        var tp = ProtoWriter.init(gpa);
        defer tp.deinit();
        try tp.writeMessage(TP_FIELD_MODULE_SYMBOLS, ms);
        try out.writeMessage(TP_FIELD_TRACE_PACKET, tp.bytes());
    }

    if (out.bytes().len == 0) {
        std.debug.print("sismo record: symbolization found no resolvable frames\n", .{});
        return;
    }

    var file = try std.Io.Dir.cwd().openFile(io, trace_path, .{ .mode = .read_write });
    defer file.close(io);
    const end = try file.length(io);
    try file.writePositionalAll(io, out.bytes(), end);

    std.debug.print(
        "sismo record: symbolized {d} addresses ({d} resolved) across {d} modules\n",
        .{ n_addrs, n_funcs, collector.modules.items.len },
    );
}

/// Build one ModuleSymbols message for `m`, or return an empty slice if no
/// address in it resolved (so we don't emit a useless empty record).
fn buildModuleSymbols(
    gpa: std.mem.Allocator,
    sym: *symbolizer.Symbolizer,
    m: *Module,
    n_funcs: *usize,
    n_addrs: *usize,
) ![]u8 {
    // base_avma = load_bias makes the bridge's `rel = avma - base_avma`
    // equal `rel_pc - load_bias`, the module-relative address wholesym wants.
    // end_avma just has to be past every rel_pc (and strictly above base).
    var max_pc: u64 = m.load_bias;
    for (m.rel_pcs.items) |pc| max_pc = @max(max_pc, pc);
    const end_avma = max_pc + 1;

    // wholesym loads symbols from the file at `m.name`. A missing or
    // symbol-less binary registers the range but resolves to nothing —
    // we just emit no lines for it.
    symbolizer.addModule(sym, m.load_bias, end_avma, m.name, null, null) catch {};

    var address_symbols = ProtoWriter.init(gpa);
    defer address_symbols.deinit();

    var name_buf: [1024]u8 = undefined;
    var any = false;
    for (m.rel_pcs.items) |rel_pc| {
        n_addrs.* += 1;
        const n = symbolizer.resolve(sym, rel_pc, &name_buf);
        if (n == 0) continue;
        const func = stripOffset(name_buf[0..n]);
        if (func.len == 0) continue;
        n_funcs.* += 1;
        any = true;

        var line = ProtoWriter.init(gpa);
        defer line.deinit();
        try line.writeString(LINE_FIELD_FUNCTION_NAME, func);

        var as = ProtoWriter.init(gpa);
        defer as.deinit();
        try as.writeUint64(AS_FIELD_ADDRESS, rel_pc);
        try as.writeMessage(AS_FIELD_LINES, line.bytes());

        try address_symbols.writeMessage(MS_FIELD_ADDRESS_SYMBOLS, as.bytes());
    }
    if (!any) return &.{};

    var build_id_raw_buf: [64]u8 = undefined;
    const build_id_raw = hexToBytes(m.build_id_hex, &build_id_raw_buf);

    var ms = ProtoWriter.init(gpa);
    errdefer ms.deinit();
    try ms.writeString(MS_FIELD_PATH, m.name);
    if (build_id_raw.len > 0) try ms.writeString(MS_FIELD_BUILD_ID, build_id_raw);
    // address_symbols already holds the repeated AddressSymbols fields
    // tagged at MS_FIELD_ADDRESS_SYMBOLS, so splice its bytes in directly.
    try ms.buf.appendSlice(gpa, address_symbols.bytes());
    return ms.buf.toOwnedSlice(gpa);
}

/// Strip wholesym's trailing " +<offset>" so only the function name is
/// emitted (trace_processor recomputes the per-frame offset itself).
fn stripOffset(s: []const u8) []const u8 {
    var i = s.len;
    while (i > 0 and std.ascii.isDigit(s[i - 1])) i -= 1;
    if (i < s.len and i >= 2 and s[i - 1] == '+' and s[i - 2] == ' ') {
        return s[0 .. i - 2];
    }
    return s;
}

/// Decode a lowercase/uppercase hex string into `buf`, returning the filled
/// prefix. Odd-length or non-hex input yields an empty slice (build_id then
/// omitted rather than corrupted).
fn hexToBytes(hex: []const u8, buf: []u8) []const u8 {
    if (hex.len == 0 or hex.len % 2 != 0 or hex.len / 2 > buf.len) return &.{};
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        const hi = std.fmt.charToDigit(hex[i], 16) catch return &.{};
        const lo = std.fmt.charToDigit(hex[i + 1], 16) catch return &.{};
        buf[i / 2] = (hi << 4) | lo;
    }
    return buf[0 .. hex.len / 2];
}

comptime {
    if (builtin.os.tag == .windows) {
        @compileError("perf_symbolize is POSIX-only (uses std.Io.Dir file append)");
    }
}

test "stripOffset removes trailing offset" {
    try std.testing.expectEqualStrings("matmul", stripOffset("matmul +12"));
    try std.testing.expectEqualStrings("operator+", stripOffset("operator+ +0"));
    try std.testing.expectEqualStrings("nooffset", stripOffset("nooffset"));
}

test "hexToBytes roundtrips a build id" {
    var buf: [4]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &.{ 0x1f, 0x6e, 0xd5, 0xcd }, hexToBytes("1f6ed5cd", &buf));
    try std.testing.expectEqual(@as(usize, 0), hexToBytes("abc", &buf).len); // odd length
}
