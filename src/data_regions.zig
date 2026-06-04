// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `/proc/<pid>/maps` reader for turning a sampled *data* address into the
//! memory region it landed in — the cache focus's data-side attribution.
//!
//! This is the data counterpart to linux_proc_maps.zig, which keeps only
//! executable file-backed mappings (where a *code* PC lands). A load that
//! misses cache can target anything: the heap, a thread stack, a file's data
//! segment, or a bare anonymous mapping. So this keeps *every* mapping and
//! labels it for ranking:
//!   - file-backed   → the file's basename (e.g. "libc.so.6")
//!   - "[heap]" / "[stack]" / "[vdso]" / "[vvar]" …   → kept verbatim
//!   - anonymous     → "[anon]"
//!
//! Region-level is the honest first rung: it says misses hit the heap vs a
//! specific library's data vs a thread stack. Naming the exact global variable
//! (ELF data symbols) or heap allocation site is a later layer.

const std = @import("std");
const linux = std.os.linux;

pub const Region = struct {
    start: u64,
    end: u64,
    /// Display label, owned by Regions.arena.
    label: []const u8,
};

pub const Regions = struct {
    arena: std.heap.ArenaAllocator,
    items: []Region, // sorted by start, ascending

    pub fn deinit(self: *Regions) void {
        self.arena.deinit();
    }

    /// The region containing `addr`, or null (e.g. an address in a hole, or a
    /// kernel address from a bogus sample).
    pub fn find(self: *const Regions, addr: u64) ?*const Region {
        var lo: usize = 0;
        var hi: usize = self.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            const r = &self.items[mid];
            if (addr < r.start) {
                hi = mid;
            } else if (addr >= r.end) {
                lo = mid + 1;
            } else {
                return r;
            }
        }
        return null;
    }
};

/// Parse `/proc/<pid>/maps`, keeping every mapping with a label. Caller owns the
/// returned Regions and must `deinit` it. /proc files report size 0, so this
/// reads to EOF in chunks.
pub fn parse(gpa: std.mem.Allocator, pid: u32) !Regions {
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

    var items: std.ArrayList(Region) = .empty;
    errdefer items.deinit(gpa);

    // Intern labels so repeated mappings of one file (and the many "[anon]"
    // lines) share a single arena string — keeps lookups cheap to aggregate by.
    var labels = std.StringHashMap([]const u8).init(gpa);
    defer labels.deinit();

    var lines = std.mem.splitScalar(u8, raw.items, '\n');
    while (lines.next()) |line| {
        const p = parseLine(line) orelse continue;
        const gop = try labels.getOrPut(p.label);
        if (!gop.found_existing) {
            const owned = try a.dupe(u8, p.label);
            gop.key_ptr.* = owned;
            gop.value_ptr.* = owned;
        }
        try items.append(gpa, .{ .start = p.start, .end = p.end, .label = gop.value_ptr.* });
    }

    const owned = try a.dupe(Region, items.items);
    items.deinit(gpa);
    return .{ .arena = arena, .items = owned };
}

const Parsed = struct { start: u64, end: u64, label: []const u8 };

/// One maps line: `start-end perms offset dev inode  pathname`. The label is
/// the file's basename for a file-backed mapping, the bracketed name for a
/// special region ("[heap]" …), or "[anon]" for an anonymous mapping. The label
/// slice borrows from `line`; callers must copy it to keep it.
fn parseLine(line: []const u8) ?Parsed {
    var it = std.mem.tokenizeAny(u8, line, " \t");
    const range = it.next() orelse return null;
    _ = it.next() orelse return null; // perms
    _ = it.next() orelse return null; // offset
    _ = it.next() orelse return null; // dev
    _ = it.next() orelse return null; // inode
    const path = it.next(); // pathname (absent for anonymous mappings)

    const dash = std.mem.indexOfScalar(u8, range, '-') orelse return null;
    const start = std.fmt.parseInt(u64, range[0..dash], 16) catch return null;
    const end = std.fmt.parseInt(u64, range[dash + 1 ..], 16) catch return null;

    const label = blk: {
        const pth = path orelse break :blk "[anon]";
        if (pth.len == 0) break :blk "[anon]";
        if (pth[0] == '[') break :blk pth; // [heap] / [stack] / [vdso] / [vvar] / …
        if (pth[0] != '/') break :blk pth; // e.g. "anon_inode:..." — keep verbatim
        const slash = std.mem.lastIndexOfScalar(u8, pth, '/');
        break :blk if (slash) |s| pth[s + 1 ..] else pth;
    };
    return .{ .start = start, .end = end, .label = label };
}

test "parseLine labels a file-backed mapping by basename" {
    const p = parseLine("7f1234500000-7f1234600000 rw-p 00012000 fd:01 1234  /usr/lib/libc.so.6").?;
    try std.testing.expectEqual(@as(u64, 0x7f1234500000), p.start);
    try std.testing.expectEqual(@as(u64, 0x7f1234600000), p.end);
    try std.testing.expectEqualStrings("libc.so.6", p.label);
}

test "parseLine keeps bracketed special regions verbatim" {
    try std.testing.expectEqualStrings("[heap]", parseLine("01d8c000-01dad000 rw-p 00000000 00:00 0  [heap]").?.label);
    try std.testing.expectEqualStrings("[stack]", parseLine("7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0  [stack]").?.label);
}

test "parseLine labels an anonymous mapping [anon]" {
    try std.testing.expectEqualStrings("[anon]", parseLine("7f0000000000-7f0000021000 rw-p 00000000 00:00 0 ").?.label);
    try std.testing.expectEqualStrings("[anon]", parseLine("7f0000000000-7f0000021000 rw-p 00000000 00:00 0").?.label);
}

test "find locates the containing region" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    const a = arena.allocator();
    const items = try a.dupe(Region, &.{
        .{ .start = 0x1000, .end = 0x2000, .label = "[heap]" },
        .{ .start = 0x5000, .end = 0x6000, .label = "libc.so.6" },
    });
    var regions = Regions{ .arena = arena, .items = items };
    defer regions.deinit();
    try std.testing.expectEqualStrings("[heap]", regions.find(0x1500).?.label);
    try std.testing.expectEqualStrings("libc.so.6", regions.find(0x5fff).?.label);
    try std.testing.expect(regions.find(0x3000) == null);
    try std.testing.expect(regions.find(0x6000) == null);
}
