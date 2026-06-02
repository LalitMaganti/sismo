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
//! computes as `avma - base_avma` — so each module is registered at
//! `base_avma = load_bias` and `rel_pc` resolves directly.

const std = @import("std");
const builtin = @import("builtin");
const ProtoWriter = @import("proto_writer.zig").ProtoWriter;
const symbolizer = @import("symbolizer.zig");
const source_asm_sidecar = @import("source_asm_sidecar.zig");
const disasm = @import("disasm.zig");

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
const LINE_FIELD_SOURCE_FILE_NAME: u32 = 2;
const LINE_FIELD_LINE_NUMBER: u32 = 3;

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
/// the trailing module is extended while the key matches and a new one
/// starts when it changes. Duplicate rel_pcs (many samples hitting one
/// address) are collapsed via `seen`.
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

    var stats: std.ArrayList(ModuleStat) = .empty;
    defer stats.deinit(gpa);

    // Unique source-file paths referenced by sampled addresses (owned keys),
    // collected during the resolve loop and bundled into the trace afterwards.
    var src_set: std.StringHashMapUnmanaged(void) = .empty;
    defer {
        var it = src_set.keyIterator();
        while (it.next()) |k| gpa.free(k.*);
        src_set.deinit(gpa);
    }

    // Per-function disassembly listings to bundle (owned func + json; module and
    // build_id borrow from the still-live Collector). Only on a supported arch.
    var asm_records: std.ArrayList(source_asm_sidecar.AsmRecord) = .empty;
    defer {
        for (asm_records.items) |rec| {
            gpa.free(rec.func);
            gpa.free(rec.json);
        }
        asm_records.deinit(gpa);
    }
    const host_arch = disasm.currentArch();

    var n_funcs: usize = 0;
    var n_addrs: usize = 0;

    for (collector.modules.items) |*m| {
        if (m.rel_pcs.items.len == 0) continue;
        var stat: ModuleStat = .{ .name = m.name, .build_id_hex = m.build_id_hex };
        const ms = try buildModuleSymbols(gpa, sym, m, &stat, &src_set);
        defer gpa.free(ms);
        n_addrs += stat.n_addrs;
        n_funcs += stat.n_resolved;
        try stats.append(gpa, stat);
        // Disassemble this module's hot functions while `sym` is scoped exactly
        // as buildModuleSymbols saw it (line resolution reuses the same lookups).
        if (host_arch) |arch| collectModuleDisasm(gpa, sym, m, arch, &asm_records) catch {};
        if (ms.len == 0) continue;
        var tp = ProtoWriter.init(gpa);
        defer tp.deinit();
        try tp.writeMessage(TP_FIELD_MODULE_SYMBOLS, ms);
        try out.writeMessage(TP_FIELD_TRACE_PACKET, tp.bytes());
    }

    if (out.bytes().len > 0) {
        var file = try std.Io.Dir.cwd().openFile(io, trace_path, .{ .mode = .read_write });
        defer file.close(io);
        const end = try file.length(io);
        try file.writePositionalAll(io, out.bytes(), end);
    }

    appendSourceAsmSidecar(gpa, io, trace_path, &src_set, asm_records.items);

    report(io, stats.items, n_addrs, n_funcs);
}

fn appendSourceAsmSidecar(
    gpa: std.mem.Allocator,
    io: std.Io,
    trace_path: []const u8,
    src_set: *std.StringHashMapUnmanaged(void),
    asm_records: []const source_asm_sidecar.AsmRecord,
) void {
    if (src_set.count() == 0 and asm_records.len == 0) return;
    var paths: std.ArrayList([]const u8) = .empty;
    defer paths.deinit(gpa);
    var it = src_set.keyIterator();
    while (it.next()) |k| paths.append(gpa, k.*) catch return;
    source_asm_sidecar.appendSidecar(gpa, io, trace_path, paths.items, asm_records) catch |err| {
        std.debug.print("sismo record: source/asm bundling skipped ({s})\n", .{@errorName(err)});
    };
}

// ==== BEGIN HACK: disassembly collection over the sidecar channel ====
// Mirrors the source-bundling hack above; delete with sismo_privileged_marker.zig
// when the real sidecar lands. The disasm bridge itself (disasm.zig / disasm.rs)
// is reusable infra — only this trace-injection path is the hack.

const DisasmInsn = struct { rel_pc: u64, bytes_hex: []u8, text: []u8 };

const DisasmCtx = struct {
    gpa: std.mem.Allocator,
    funcs: std.AutoArrayHashMapUnmanaged(u64, std.ArrayList(DisasmInsn)) = .empty,
    failed: bool = false,

    fn deinit(self: *DisasmCtx) void {
        var it = self.funcs.iterator();
        while (it.next()) |e| {
            for (e.value_ptr.items) |insn| {
                self.gpa.free(insn.bytes_hex);
                self.gpa.free(insn.text);
            }
            e.value_ptr.deinit(self.gpa);
        }
        self.funcs.deinit(self.gpa);
    }
};

fn onInsn(
    ctx_opaque: ?*anyopaque,
    func_start: u64,
    insn_rel_pc: u64,
    bytes_ptr: [*]const u8,
    bytes_len: usize,
    text_ptr: [*]const u8,
    text_len: usize,
) callconv(.c) void {
    const ctx: *DisasmCtx = @ptrCast(@alignCast(ctx_opaque.?));
    if (ctx.failed) return;
    appendInsn(
        ctx,
        func_start,
        insn_rel_pc,
        bytes_ptr[0..bytes_len],
        text_ptr[0..text_len],
    ) catch {
        ctx.failed = true;
    };
}

fn appendInsn(
    ctx: *DisasmCtx,
    func_start: u64,
    rel_pc: u64,
    bytes: []const u8,
    text: []const u8,
) !void {
    const gop = try ctx.funcs.getOrPut(ctx.gpa, func_start);
    if (!gop.found_existing) gop.value_ptr.* = .empty;
    const hex = try bytesToHex(ctx.gpa, bytes);
    errdefer ctx.gpa.free(hex);
    const txt = try ctx.gpa.dupe(u8, text);
    try gop.value_ptr.append(ctx.gpa, .{ .rel_pc = rel_pc, .bytes_hex = hex, .text = txt });
}

fn collectModuleDisasm(
    gpa: std.mem.Allocator,
    sym: *symbolizer.Symbolizer,
    m: *Module,
    arch: disasm.Arch,
    out: *std.ArrayList(source_asm_sidecar.AsmRecord),
) !void {
    var ctx: DisasmCtx = .{ .gpa = gpa };
    defer ctx.deinit();
    if (!disasm.disassembleModule(m.name, arch, m.rel_pcs.items, &onInsn, &ctx)) return;
    if (ctx.failed) return;

    var name_buf: [1024]u8 = undefined;
    var file_buf: [1024]u8 = undefined;
    var it = ctx.funcs.iterator();
    while (it.next()) |e| {
        const insns = e.value_ptr.items;
        if (insns.len == 0) continue;
        const r = symbolizer.resolve(sym, e.key_ptr.*, &name_buf, &file_buf);
        if (r.name_len == 0) continue;
        const fname = stripOffset(name_buf[0..r.name_len]);
        if (fname.len == 0) continue;

        var js: std.ArrayList(u8) = .empty;
        errdefer js.deinit(gpa);
        try js.append(gpa, '[');
        for (insns, 0..) |insn, i| {
            if (i > 0) try js.append(gpa, ',');
            const lr = symbolizer.resolve(sym, insn.rel_pc, &name_buf, &file_buf);
            try appendInsnJson(gpa, &js, insn, lr.line);
        }
        try js.append(gpa, ']');

        const func_owned = try gpa.dupe(u8, fname);
        errdefer gpa.free(func_owned);
        try out.append(gpa, .{
            .func = func_owned,
            .module = m.name,
            .build_id_hex = m.build_id_hex,
            .json = try js.toOwnedSlice(gpa),
        });
    }
}

fn bytesToHex(gpa: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const digits = "0123456789abcdef";
    const hex = try gpa.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |b, i| {
        hex[i * 2] = digits[b >> 4];
        hex[i * 2 + 1] = digits[b & 0xf];
    }
    return hex;
}

fn appendInsnJson(
    gpa: std.mem.Allocator,
    js: *std.ArrayList(u8),
    insn: DisasmInsn,
    line: u32,
) !void {
    var numbuf: [24]u8 = undefined;
    try js.appendSlice(gpa, "{\"a\":\"");
    try js.appendSlice(gpa, try std.fmt.bufPrint(&numbuf, "{d}", .{insn.rel_pc}));
    try js.appendSlice(gpa, "\",\"b\":\"");
    try js.appendSlice(gpa, insn.bytes_hex);
    try js.appendSlice(gpa, "\",\"t\":\"");
    try appendJsonEscaped(gpa, js, insn.text);
    try js.appendSlice(gpa, "\"");
    if (line > 0) {
        try js.appendSlice(gpa, ",\"l\":");
        try js.appendSlice(gpa, try std.fmt.bufPrint(&numbuf, "{d}", .{line}));
    }
    try js.append(gpa, '}');
}

fn appendJsonEscaped(gpa: std.mem.Allocator, js: *std.ArrayList(u8), s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try js.appendSlice(gpa, "\\\""),
            '\\' => try js.appendSlice(gpa, "\\\\"),
            '\n' => try js.appendSlice(gpa, "\\n"),
            '\t' => try js.appendSlice(gpa, "\\t"),
            else => if (c >= 0x20) try js.append(gpa, c),
        }
    }
}

// ==== END HACK ====

/// What happened when we tried to symbolize one module. Carries enough to
/// tell a missing-symbols problem (actionable: install debug info) apart
/// from a loaded-but-nothing-matched problem (a capture/build mismatch),
/// which need very different fixes.
const ModuleStat = struct {
    name: []const u8, // borrowed from the Module (outlives the report)
    build_id_hex: []const u8,
    /// false → wholesym couldn't load symbols for this path at all.
    symbols_loaded: bool = false,
    /// Symbol count when loaded; 0 otherwise.
    symbol_count: u64 = 0,
    n_addrs: usize = 0,
    n_resolved: usize = 0,
    /// wholesym's load-failure reason (empty unless `!symbols_loaded`).
    err_buf: [256]u8 = undefined,
    err_len: usize = 0,

    const Status = enum { ok, partial, unresolved, no_symbols };

    fn err(self: *const ModuleStat) []const u8 {
        return self.err_buf[0..self.err_len];
    }

    fn status(self: *const ModuleStat) Status {
        if (!self.symbols_loaded) return .no_symbols;
        if (self.n_resolved == 0) return .unresolved;
        if (self.n_resolved < self.n_addrs) return .partial;
        return .ok;
    }
};

/// Print the per-module symbolization result, then — when something didn't
/// fully resolve — concrete next steps. The whole point is that a user (or
/// an agent) staring at hex addresses in the UI can run `record` again, read
/// this, and know whether to install debug symbols or look at the capture.
fn report(io: std.Io, stats: []const ModuleStat, n_addrs: usize, n_funcs: usize) void {
    if (stats.len == 0) {
        std.debug.print("sismo record: no unsymbolized frames to resolve\n", .{});
        return;
    }
    std.debug.print(
        "sismo record: symbolized {d}/{d} addresses across {d} modules\n",
        .{ n_funcs, n_addrs, stats.len },
    );
    // Only `no_symbols` / `unresolved` are actionable; `partial` (a few
    // PLT/JIT stubs missing) is shown in the table but needs no advice.
    var needs_help = false;
    for (stats) |*s| {
        const tag = switch (s.status()) {
            .ok => "ok        ",
            .partial => "partial   ",
            .unresolved => "unresolved",
            .no_symbols => "no symbols",
        };
        switch (s.status()) {
            .no_symbols, .unresolved => needs_help = true,
            .ok, .partial => {},
        }
        std.debug.print("  [{s}] {d:>5}/{d:<5} {s}\n", .{ tag, s.n_resolved, s.n_addrs, s.name });
    }
    if (needs_help) printGuidance(io, stats);
}

fn printGuidance(io: std.Io, stats: []const ModuleStat) void {
    const hint = installHint(io);
    std.debug.print("\nsismo record: some modules did not fully symbolize:\n", .{});
    for (stats) |*s| {
        switch (s.status()) {
            .ok, .partial => continue, // partial is usually PLT stubs / JIT — not actionable
            .no_symbols => {
                std.debug.print("\n  {s}\n    no symbols could be loaded", .{s.name});
                if (s.err().len > 0) std.debug.print(" — wholesym: {s}", .{s.err()});
                std.debug.print("\n", .{});
                if (!fileExists(io, s.name)) {
                    std.debug.print(
                        "    the file is no longer at this path (deleted/unmounted since recording?)\n",
                        .{},
                    );
                } else {
                    std.debug.print("    the binary on disk is stripped and has no separate debug info installed.\n", .{});
                    std.debug.print("    fix it one of these ways:\n", .{});
                    std.debug.print("      - install its debug package: {s}\n", .{hint});
                    std.debug.print("      - or let sismo fetch it: export DEBUGINFOD_URLS=https://debuginfod.fedoraproject.org/\n", .{});
                    std.debug.print("        then re-run `sismo record` (sismo honors DEBUGINFOD_URLS and caches downloads).\n", .{});
                }
            },
            .unresolved => {
                std.debug.print("\n  {s}\n    {d} symbols loaded, but 0/{d} sampled addresses fell inside any function.\n", .{ s.name, s.symbol_count, s.n_addrs });
                std.debug.print("    this is NOT a missing-symbols problem. The sampled addresses don't match this build.\n", .{});
                std.debug.print("    likely the binary changed since recording, or a build-id mismatch:\n", .{});
                std.debug.print("      sampled build-id: {s}\n", .{s.build_id_hex});
                std.debug.print("      on disk:          readelf -n {s} | grep -i 'build id'\n", .{s.name});
            },
        }
    }
    std.debug.print("\n", .{});
}

fn fileExists(io: std.Io, path: []const u8) bool {
    var file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch return false;
    file.close(io);
    return true;
}

/// Read up to `buf.len` bytes of an absolute path. Returns null if it can't
/// be opened/read — callers treat that as "info unavailable".
fn readFileAbsolute(io: std.Io, path: []const u8, buf: []u8) ?[]u8 {
    var file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch return null;
    defer file.close(io);
    const n = file.readPositional(io, &.{buf}, 0) catch return null;
    return buf[0..n];
}

/// Best-effort debug-package install command for the running distro, read
/// from /etc/os-release. Falls back to a generic note.
fn installHint(io: std.Io) []const u8 {
    var buf: [4096]u8 = undefined;
    const text = readFileAbsolute(io, "/etc/os-release", &buf) orelse return generic_hint;
    const id = osReleaseId(text) orelse return generic_hint;
    if (eqlAny(id, &.{ "fedora", "rhel", "centos", "rocky", "almalinux" }))
        return "sudo dnf debuginfo-install <package>";
    if (eqlAny(id, &.{ "debian", "ubuntu", "pop", "linuxmint" }))
        return "sudo apt install <package>-dbgsym  (enable the debug/-dbgsym repo first)";
    if (eqlAny(id, &.{ "arch", "manjaro" }))
        return "install the matching -debug package (or use a debuginfod server)";
    return generic_hint;
}

const generic_hint = "install your distro's debug-symbols package for this library";

fn osReleaseId(text: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "ID=")) continue;
        var v = line["ID=".len..];
        if (v.len >= 2 and v[0] == '"' and v[v.len - 1] == '"') v = v[1 .. v.len - 1];
        return v;
    }
    return null;
}

fn eqlAny(id: []const u8, names: []const []const u8) bool {
    for (names) |n| if (std.mem.eql(u8, id, n)) return true;
    return false;
}

/// Build one ModuleSymbols message for `m`, or return an empty slice if no
/// address in it resolved (avoids emitting a useless empty record).
fn buildModuleSymbols(
    gpa: std.mem.Allocator,
    sym: *symbolizer.Symbolizer,
    m: *Module,
    stat: *ModuleStat,
    src_set: *std.StringHashMapUnmanaged(void),
) ![]u8 {
    // base_avma = load_bias makes the bridge's `rel = avma - base_avma`
    // equal `rel_pc - load_bias`, the module-relative address wholesym wants.
    // end_avma just has to be past every rel_pc (and strictly above base).
    var max_pc: u64 = m.load_bias;
    for (m.rel_pcs.items) |pc| max_pc = @max(max_pc, pc);
    const end_avma = max_pc + 1;

    // wholesym loads symbols from the file at `m.name`. Capture why it did
    // or didn't so `report` can guide the user; a failed load still
    // registers the range and just resolves to nothing.
    var diag: symbolizer.Diag = .{};
    if (symbolizer.addModule(sym, m.load_bias, end_avma, m.name, null, null, &diag)) {
        stat.symbols_loaded = true;
    } else |_| {
        stat.symbols_loaded = false;
    }
    stat.symbol_count = diag.symbol_count;
    const reason = diag.err();
    stat.err_len = @min(reason.len, stat.err_buf.len);
    @memcpy(stat.err_buf[0..stat.err_len], reason[0..stat.err_len]);

    var address_symbols = ProtoWriter.init(gpa);
    defer address_symbols.deinit();

    var name_buf: [1024]u8 = undefined;
    var file_buf: [1024]u8 = undefined;
    var any = false;
    for (m.rel_pcs.items) |rel_pc| {
        stat.n_addrs += 1;
        const r = symbolizer.resolve(sym, rel_pc, &name_buf, &file_buf);
        if (r.name_len == 0) continue;
        const func = stripOffset(name_buf[0..r.name_len]);
        if (func.len == 0) continue;
        stat.n_resolved += 1;
        any = true;

        var line = ProtoWriter.init(gpa);
        defer line.deinit();
        try line.writeString(LINE_FIELD_FUNCTION_NAME, func);
        // Source file + line come from DWARF; absent for symtab-only modules.
        if (r.file_len > 0) {
            const fpath = file_buf[0..r.file_len];
            try line.writeString(LINE_FIELD_SOURCE_FILE_NAME, fpath);
            // Remember the path so its text gets bundled (own the key — fpath
            // points into the reused stack buffer).
            const gop = try src_set.getOrPut(gpa, fpath);
            if (!gop.found_existing) gop.key_ptr.* = try gpa.dupe(u8, fpath);
        }
        if (r.line > 0) try line.writeUint32(LINE_FIELD_LINE_NUMBER, r.line);

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

test "osReleaseId extracts and unquotes the distro id" {
    try std.testing.expectEqualStrings("fedora", osReleaseId("NAME=\"Fedora\"\nID=fedora\nVERSION=44\n").?);
    try std.testing.expectEqualStrings("ubuntu", osReleaseId("ID=\"ubuntu\"\n").?);
    try std.testing.expect(osReleaseId("NAME=nope\n") == null);
}

test "installHint maps known distro families" {
    try std.testing.expect(eqlAny("fedora", &.{ "fedora", "rhel" }));
    try std.testing.expect(!eqlAny("gentoo", &.{ "fedora", "rhel" }));
}

test "ModuleStat status classification" {
    const loaded: ModuleStat = .{ .name = "x", .build_id_hex = "", .symbols_loaded = true, .n_addrs = 10, .n_resolved = 10 };
    try std.testing.expectEqual(ModuleStat.Status.ok, loaded.status());
    const partial: ModuleStat = .{ .name = "x", .build_id_hex = "", .symbols_loaded = true, .n_addrs = 10, .n_resolved = 3 };
    try std.testing.expectEqual(ModuleStat.Status.partial, partial.status());
    const unresolved: ModuleStat = .{ .name = "x", .build_id_hex = "", .symbols_loaded = true, .n_addrs = 10, .n_resolved = 0 };
    try std.testing.expectEqual(ModuleStat.Status.unresolved, unresolved.status());
    const none: ModuleStat = .{ .name = "x", .build_id_hex = "", .symbols_loaded = false, .n_addrs = 10 };
    try std.testing.expectEqual(ModuleStat.Status.no_symbols, none.status());
}

test "hexToBytes roundtrips a build id" {
    var buf: [4]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &.{ 0x1f, 0x6e, 0xd5, 0xcd }, hexToBytes("1f6ed5cd", &buf));
    try std.testing.expectEqual(@as(usize, 0), hexToBytes("abc", &buf).len); // odd length
}
