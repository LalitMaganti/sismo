// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Minimal `/proc/<pid>/maps` reader for turning a sampled absolute user PC
//! into (module, file-offset). Only executable, file-backed mappings are kept
//! — those are the ones a PC can land in and that a symbolizer can resolve.
//!
//! The file-offset convention: for a PC inside mapping `m`,
//!   rel_pc = pc - m.start + m.offset
//! is the byte offset into the backing file. Emitted as `Frame.rel_pc` with
//! `Mapping.load_bias = 0`, this is exactly what wholesym's relative-address
//! lookup wants (see perf_symbolize.zig), so the existing symbolize pass names
//! the frames unchanged.

const std = @import("std");
const linux = std.os.linux;

pub const Mapping = struct {
    start: u64,
    end: u64,
    offset: u64,
    /// avma of the file's lowest mapping (where the ELF image base loads).
    /// Used as the symbolizer's per-module base: `pc - base_avma` is the
    /// image-relative address symbol lookup wants, valid for PIE and non-PIE
    /// alike (unlike start-offset, which can go negative).
    base_avma: u64,
    path: []const u8, // borrowed from Maps.arena
    /// Raw GNU build-id bytes, or empty if the file has none / is unreadable.
    /// Borrowed from Maps.arena. trace_processor needs this (its symbolization
    /// query drops mappings with no build-id).
    build_id: []const u8,
};

pub const Maps = struct {
    arena: std.heap.ArenaAllocator,
    items: []Mapping, // sorted by start, ascending

    pub fn deinit(self: *Maps) void {
        self.arena.deinit();
    }

    /// The executable file-backed mapping containing `addr`, or null.
    pub fn find(self: *const Maps, addr: u64) ?*const Mapping {
        var lo: usize = 0;
        var hi: usize = self.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            const m = &self.items[mid];
            if (addr < m.start) {
                hi = mid;
            } else if (addr >= m.end) {
                lo = mid + 1;
            } else {
                return m;
            }
        }
        return null;
    }
};

/// Parse `/proc/<pid>/maps`. The caller owns the returned Maps and must
/// `deinit` it. /proc files report size 0, so this reads to EOF in chunks.
pub fn parse(gpa: std.mem.Allocator, pid: u32) !Maps {
    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buf, "/proc/{d}/maps", .{pid});

    const open_rc = linux.openat(linux.AT.FDCWD, path.ptr, .{ .ACCMODE = .RDONLY }, 0);
    if (@as(isize, @bitCast(open_rc)) < 0) return error.OpenFailed;
    const fd: i32 = @intCast(open_rc);
    defer _ = linux.close(fd);

    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(gpa);
    var chunk: [64 * 1024]u8 = undefined;
    while (true) {
        const read_rc = linux.read(fd, &chunk, chunk.len);
        const n: isize = @bitCast(read_rc);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        try raw.appendSlice(gpa, chunk[0..@intCast(n)]);
    }

    var items: std.ArrayList(Mapping) = .empty;
    errdefer items.deinit(gpa);

    // Per-file state (cached so a multi-segment binary is read once): the build
    // -id and the base avma = the lowest start across all the file's mappings.
    const FileInfo = struct { build_id: []const u8, base_avma: u64 };
    var files = std.StringHashMap(*FileInfo).init(gpa);
    defer files.deinit();

    // First pass: every file-backed line updates its file's base avma (the
    // header mapping is usually non-executable, so this must see all lines).
    var lines = std.mem.splitScalar(u8, raw.items, '\n');
    while (lines.next()) |line| {
        const m = parseLine(line) orelse continue;
        const gop = try files.getOrPut(m.path);
        if (!gop.found_existing) {
            gop.key_ptr.* = try a.dupe(u8, m.path);
            const fi = try a.create(FileInfo);
            // Prefer the ELF's GNU build-id; synthesize a stable id from the
            // path otherwise (the toolchain may omit it, and trace_processor's
            // symbolization query drops mappings with an empty build-id).
            fi.* = .{
                .build_id = readBuildId(a, gop.key_ptr.*) orelse try synthBuildId(a, gop.key_ptr.*),
                .base_avma = m.start,
            };
            gop.value_ptr.* = fi;
        } else if (m.start < gop.value_ptr.*.base_avma) {
            gop.value_ptr.*.base_avma = m.start;
        }
    }

    // Second pass: keep the executable, file-backed mappings (those a PC lands
    // in), attaching their file's build-id and base avma.
    lines = std.mem.splitScalar(u8, raw.items, '\n');
    while (lines.next()) |line| {
        const m = parseLine(line) orelse continue;
        if (!m.exec) continue;
        const fi = files.get(m.path).?;
        try items.append(gpa, .{
            .start = m.start,
            .end = m.end,
            .offset = m.offset,
            .base_avma = fi.base_avma,
            .path = fi_path: {
                // reuse the arena-owned key string
                break :fi_path (files.getKey(m.path).?);
            },
            .build_id = fi.build_id,
        });
    }

    const owned = try a.dupe(Mapping, items.items);
    items.deinit(gpa);
    return .{ .arena = arena, .items = owned };
}

const PT_NOTE = 4;
const NT_GNU_BUILD_ID = 3;

fn align4(n: usize) usize {
    return (n + 3) & ~@as(usize, 3);
}

fn preadAll(fd: i32, buf: []u8, offset: u64) bool {
    const rc = linux.pread(fd, buf.ptr, buf.len, @bitCast(offset));
    return @as(isize, @bitCast(rc)) == @as(isize, @intCast(buf.len));
}

/// Read the GNU build-id (raw bytes) from the ELF at `path`, allocated in `a`.
/// Returns null on any read/parse problem — best effort. Assumes a 64-bit LE
/// ELF (x86-64 / aarch64); other classes just yield null.
fn readBuildId(a: std.mem.Allocator, path: []const u8) ?[]u8 {
    var path_buf: [4096]u8 = undefined;
    if (path.len >= path_buf.len) return null;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&path_buf);

    const open_rc = linux.openat(linux.AT.FDCWD, path_z, .{ .ACCMODE = .RDONLY }, 0);
    if (@as(isize, @bitCast(open_rc)) < 0) return null;
    const fd: i32 = @intCast(open_rc);
    defer _ = linux.close(fd);

    var ehdr: [64]u8 = undefined;
    if (!preadAll(fd, &ehdr, 0)) return null;
    if (!std.mem.eql(u8, ehdr[0..4], "\x7fELF")) return null;
    if (ehdr[4] != 2) return null; // ELFCLASS64

    const e_phoff = std.mem.readInt(u64, ehdr[32..40], .little);
    const e_phentsize = std.mem.readInt(u16, ehdr[54..56], .little);
    const e_phnum = std.mem.readInt(u16, ehdr[56..58], .little);
    if (e_phentsize < 56) return null;

    var i: u16 = 0;
    while (i < e_phnum) : (i += 1) {
        var phdr: [56]u8 = undefined;
        if (!preadAll(fd, &phdr, e_phoff + @as(u64, i) * e_phentsize)) return null;
        const p_type = std.mem.readInt(u32, phdr[0..4], .little);
        if (p_type != PT_NOTE) continue;
        const p_offset = std.mem.readInt(u64, phdr[8..16], .little);
        const p_filesz = std.mem.readInt(u64, phdr[32..40], .little);
        if (p_filesz == 0 or p_filesz > 64 * 1024) continue;

        const notes = a.alloc(u8, @intCast(p_filesz)) catch return null;
        if (!preadAll(fd, notes, p_offset)) continue;

        var off: usize = 0;
        while (off + 12 <= notes.len) {
            const namesz = std.mem.readInt(u32, notes[off..][0..4], .little);
            const descsz = std.mem.readInt(u32, notes[off + 4 ..][0..4], .little);
            const ntype = std.mem.readInt(u32, notes[off + 8 ..][0..4], .little);
            const name_off = off + 12;
            const desc_off = name_off + align4(namesz);
            const next = desc_off + align4(descsz);
            if (next > notes.len) break;
            if (ntype == NT_GNU_BUILD_ID and namesz >= 4 and
                std.mem.eql(u8, notes[name_off..][0..3], "GNU"))
            {
                return a.dupe(u8, notes[desc_off..][0..descsz]) catch null;
            }
            off = next;
        }
    }
    return null;
}

/// A 16-byte synthetic build-id derived from the module path, for binaries
/// without a GNU build-id note. Stable within a recording (the only place it
/// has to be consistent), distinct in length from real (20-byte sha1) ids.
fn synthBuildId(a: std.mem.Allocator, path: []const u8) ![]u8 {
    var out = try a.alloc(u8, 16);
    std.mem.writeInt(u64, out[0..8], std.hash.Wyhash.hash(0x5193, path), .little);
    std.mem.writeInt(u64, out[8..16], std.hash.Wyhash.hash(0x9E37, path), .little);
    return out;
}

const Line = struct { start: u64, end: u64, offset: u64, exec: bool, path: []const u8 };

/// One maps line: `start-end perms offset dev inode  pathname`. Keeps every
/// absolute-path-backed mapping (skips [vdso]/[heap]/anon), flagging which are
/// executable — non-exec lines still matter for a file's base avma.
fn parseLine(line: []const u8) ?Line {
    var it = std.mem.tokenizeAny(u8, line, " \t");
    const range = it.next() orelse return null;
    const perms = it.next() orelse return null;
    const offset_s = it.next() orelse return null;
    _ = it.next() orelse return null; // dev
    _ = it.next() orelse return null; // inode
    const path = it.next() orelse return null; // pathname (absent → skip)

    if (perms.len < 3) return null;
    if (path.len == 0 or path[0] != '/') return null;

    const dash = std.mem.indexOfScalar(u8, range, '-') orelse return null;
    const start = std.fmt.parseInt(u64, range[0..dash], 16) catch return null;
    const end = std.fmt.parseInt(u64, range[dash + 1 ..], 16) catch return null;
    const offset = std.fmt.parseInt(u64, offset_s, 16) catch return null;
    return .{ .start = start, .end = end, .offset = offset, .exec = perms[2] == 'x', .path = path };
}

test "parseLine parses executable file mappings" {
    const l = parseLine("7f1234500000-7f1234600000 r-xp 00012000 fd:01 1234  /usr/lib/libc.so.6").?;
    try std.testing.expectEqual(@as(u64, 0x7f1234500000), l.start);
    try std.testing.expectEqual(@as(u64, 0x7f1234600000), l.end);
    try std.testing.expectEqual(@as(u64, 0x12000), l.offset);
    try std.testing.expect(l.exec);
    try std.testing.expectEqualStrings("/usr/lib/libc.so.6", l.path);
}

test "parseLine keeps non-exec file mappings but flags them" {
    const l = parseLine("7f1234500000-7f1234600000 r--p 00000000 fd:01 1234  /usr/lib/libc.so.6").?;
    try std.testing.expect(!l.exec);
    try std.testing.expectEqual(@as(u64, 0), l.offset);
}

test "parseLine skips anon and special mappings" {
    try std.testing.expect(parseLine("7f1234500000-7f1234600000 r-xp 00000000 00:00 0 ") == null);
    try std.testing.expect(parseLine("7ffd00000000-7ffd00021000 r-xp 00000000 00:00 0  [vdso]") == null);
}
