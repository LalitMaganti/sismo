// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Zig wrapper for the rust-bridge disassembler (rust-bridge/src/disasm.rs).
//! Streams decoded instructions for the functions containing a module's sampled
//! addresses, one callback per instruction tagged with the function start.

const std = @import("std");

pub const Arch = enum(u32) { x86_64 = 0, aarch64 = 1 };

pub const InsnCallback = *const fn (
    ctx: ?*anyopaque,
    func_start: u64,
    insn_rel_pc: u64,
    bytes: [*]const u8,
    bytes_len: usize,
    text: [*]const u8,
    text_len: usize,
) callconv(.c) void;

extern "c" fn sismo_disasm_module(
    path: [*]const u8,
    path_len: usize,
    arch: u32,
    load_bias: u64,
    rel_pcs: [*]const u64,
    rel_pcs_len: usize,
    cb: InsnCallback,
    ctx: ?*anyopaque,
) c_int;

pub fn currentArch() ?Arch {
    return switch (@import("builtin").cpu.arch) {
        .x86_64 => .x86_64,
        .aarch64 => .aarch64,
        else => null,
    };
}

pub fn disassembleModule(
    path: []const u8,
    arch: Arch,
    load_bias: u64,
    rel_pcs: []const u64,
    cb: InsnCallback,
    ctx: ?*anyopaque,
) bool {
    if (path.len == 0 or rel_pcs.len == 0) return false;
    return sismo_disasm_module(
        path.ptr,
        path.len,
        @intFromEnum(arch),
        load_bias,
        rel_pcs.ptr,
        rel_pcs.len,
        cb,
        ctx,
    ) == 0;
}
