// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Zig-side wrapper for the framehop FFI in `rust-bridge`. Exposes a
//! friendlier API on top of the `sismo_unwinder_*` extern entries
//! declared in `rust-bridge/include/bridge.h`.
//!
//! Zig does not `@cImport` the bridge header today; the C header
//! (`rust-bridge/include/bridge.h`) is the canonical reference, this
//! module is the canonical Zig API.
//!
//! Lifecycle:
//!     const u = try unwinder.create();
//!     defer unwinder.destroy(u);
//!     try unwinder.addModule(u, base_avma, image_bytes);
//!     const n = unwinder.walk(u, regs, readStackCb, user_data, &pcs);
//!
//! The `ReadStackCb` is a C-callable function pointer; Zig closures
//! over an environment can't pass through the C ABI, so callers route
//! their per-call state via the `user_data` `?*anyopaque` slot.

const std = @import("std");

/// Opaque handle. A `*Unwinder` can be passed and stored, never deref'd.
/// The Rust side owns the storage via `Box<Unwinder>`.
pub const Unwinder = opaque {};

/// Stack-read callback shape required by `walk`. Reads 8 bytes from
/// `addr` in the target's address space, writes the value to `*out`.
/// Returns 0 on success, non-zero on failure (e.g. unmapped page).
/// `user_data` is whatever was passed alongside the cb to `walk`.
pub const ReadStackCb = *const fn (
    addr: u64,
    out_value: *u64,
    user_data: ?*anyopaque,
) callconv(.c) c_int;

/// Register snapshot fed to `walk`. Bundle so callers can't get the
/// argument order wrong (4 positional u64s is too easy to flip).
pub const Regs = struct {
    pc: u64,
    fp: u64,
    lr: u64,
    sp: u64,
};

pub const Error = error{
    /// `sismo_unwinder_create_arm64` returned null — allocation failure.
    OutOfMemory,
    /// `add_module` rc=-1: bytes don't parse as a 64-bit mach-o.
    InvalidMachO,
    /// `add_module` rc=-2: parse OK, but no usable unwind sections.
    NoUnwindInfo,
};

// -- Extern decls (must match rust-bridge/include/bridge.h byte-for-byte) -

extern "c" fn sismo_unwinder_create_arm64() ?*Unwinder;
extern "c" fn sismo_unwinder_destroy(u: ?*Unwinder) void;
extern "c" fn sismo_unwinder_add_module(
    u: *Unwinder,
    base_avma: u64,
    mach_o_data: [*]const u8,
    mach_o_len: usize,
) c_int;
extern "c" fn sismo_unwinder_walk(
    u: *Unwinder,
    pc: u64,
    fp: u64,
    lr: u64,
    sp: u64,
    cb: ReadStackCb,
    user_data: ?*anyopaque,
    out_pcs: [*]u64,
    max_pcs: usize,
) usize;
extern "c" fn sismo_unwinder_walk_snapshot(
    u: *Unwinder,
    pc: u64,
    fp: u64,
    lr: u64,
    sp: u64,
    snapshot_bytes: [*]const u8,
    snapshot_len: usize,
    snapshot_sp: u64,
    out_pcs: [*]u64,
    max_pcs: usize,
) usize;

// -- Public Zig API ------------------------------------------------------

pub fn create() Error!*Unwinder {
    return sismo_unwinder_create_arm64() orelse error.OutOfMemory;
}

pub fn destroy(u: *Unwinder) void {
    sismo_unwinder_destroy(u);
}

/// Register a loaded mach-o image. `image` must be the in-memory bytes
/// starting at the LC_SEGMENT_64 __TEXT base (= `base_avma`).
pub fn addModule(u: *Unwinder, base_avma: u64, image: []const u8) Error!void {
    const rc = sismo_unwinder_add_module(u, base_avma, image.ptr, image.len);
    return switch (rc) {
        0 => {},
        -1 => error.InvalidMachO,
        -2 => error.NoUnwindInfo,
        // Rust side returns only {0, -1, -2}; treat anything else as a
        // protocol violation by aliasing to InvalidMachO rather than
        // silently swallowing.
        else => error.InvalidMachO,
    };
}

/// Walk the stack from `regs`. Slot 0 of `out_pcs` is always the
/// snapshot `pc`; subsequent slots are return-address AVMAs. Returns
/// the number of slots written; stops early on iter error or when full.
pub fn walk(
    u: *Unwinder,
    regs: Regs,
    cb: ReadStackCb,
    user_data: ?*anyopaque,
    out_pcs: []u64,
) usize {
    if (out_pcs.len == 0) return 0;
    return sismo_unwinder_walk(
        u,
        regs.pc,
        regs.fp,
        regs.lr,
        regs.sp,
        cb,
        user_data,
        out_pcs.ptr,
        out_pcs.len,
    );
}

/// Walk a captured stack snapshot. `snapshot` is the byte buffer the
/// in-process client memcpy'd starting at `regs.sp`. Out-of-range
/// reads inside the unwinder terminate the walk; the returned count
/// is the partial-but-valid prefix.
pub fn walkSnapshot(
    u: *Unwinder,
    regs: Regs,
    snapshot: []const u8,
    out_pcs: []u64,
) usize {
    if (out_pcs.len == 0) return 0;
    return sismo_unwinder_walk_snapshot(
        u,
        regs.pc,
        regs.fp,
        regs.lr,
        regs.sp,
        snapshot.ptr,
        snapshot.len,
        regs.sp,
        out_pcs.ptr,
        out_pcs.len,
    );
}
