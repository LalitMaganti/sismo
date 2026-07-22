// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.
//
// Zig port of fix.c: zig's linker embeds DWARF straight into the binary
// (no debug map), and markers land in the symtab as fix.sismoFixLeaf etc.

fn sismoFixLeaf(x: u64) u64 {
    var acc: u64 = 0;
    var i: u64 = 0;
    while (i < x) : (i += 1) acc +%= i *% i;
    return acc;
}

fn sismoFixMid(x: u64) u64 {
    return @call(.never_inline, sismoFixLeaf, .{x}) + 1;
}

var seed: u64 = 100;

pub fn main() void {
    // The volatile load keeps the input runtime-only: ReleaseFast otherwise
    // const-folds the whole marker chain out of the binary.
    const p: *volatile u64 = &seed;
    const v = @call(.never_inline, sismoFixMid, .{p.*});
    std.mem.doNotOptimizeAway(v);
}

const std = @import("std");
