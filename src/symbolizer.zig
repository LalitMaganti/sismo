//! Zig-side wrapper for the wholesym FFI in `rust-bridge` (journal 03).
//! Mirrors `src/unwinder.zig`'s shape: opaque handle, error-union API,
//! slice-based string parameters.
//!
//! Lifecycle:
//!     const s = try symbolizer.create();
//!     defer symbolizer.destroy(s);
//!     try symbolizer.addModule(s, base_avma, end_avma, path);
//!     var buf: [256]u8 = undefined;
//!     const n = symbolizer.resolve(s, pc, &buf);
//!     if (n > 0) std.debug.print("{s}\n", .{buf[0..n]});

const std = @import("std");

pub const Symbolizer = opaque {};

pub const Error = error{
    OutOfMemory,
    BadArgument,
    /// Module range registered, but wholesym couldn't load symbols for
    /// that path. `resolve` will return 0 (no match) for AVMAs in this
    /// module's range. Common for dyld_shared_cache members whose path
    /// wholesym can't locate on disk.
    SymbolLoadFailed,
};

extern "c" fn sismo_symbolizer_create() ?*Symbolizer;
extern "c" fn sismo_symbolizer_destroy(s: ?*Symbolizer) void;
extern "c" fn sismo_symbolizer_add_module(
    s: *Symbolizer,
    base_avma: u64,
    end_avma: u64,
    path_utf8: [*]const u8,
    path_len: usize,
    uuid_bytes: ?[*]const u8,
    arch_utf8: ?[*]const u8,
    arch_len: usize,
) c_int;
extern "c" fn sismo_symbolizer_resolve(
    s: *Symbolizer,
    avma: u64,
    out_utf8: [*]u8,
    cap: usize,
) usize;

pub fn create() Error!*Symbolizer {
    return sismo_symbolizer_create() orelse error.OutOfMemory;
}

pub fn destroy(s: *Symbolizer) void {
    sismo_symbolizer_destroy(s);
}

pub fn addModule(
    s: *Symbolizer,
    base_avma: u64,
    end_avma: u64,
    path: []const u8,
    /// Optional 16-byte UUID from the in-memory image's LC_UUID. Pass
    /// `null` (or all-zeros) if not available — falls back to `arch`.
    uuid: ?*const [16]u8,
    /// Optional architecture string ("arm64", "arm64e", "x86_64",
    /// "x86_64h"). Used as a fallback when UUID isn't available.
    arch: ?[]const u8,
) Error!void {
    if (path.len == 0 or end_avma <= base_avma) return error.BadArgument;
    const uuid_ptr: ?[*]const u8 = if (uuid) |u| @ptrCast(u) else null;
    const arch_ptr: ?[*]const u8 = if (arch) |a| a.ptr else null;
    const arch_len: usize = if (arch) |a| a.len else 0;
    const rc = sismo_symbolizer_add_module(
        s,
        base_avma,
        end_avma,
        path.ptr,
        path.len,
        uuid_ptr,
        arch_ptr,
        arch_len,
    );
    return switch (rc) {
        0 => {},
        1 => error.SymbolLoadFailed,
        else => error.BadArgument,
    };
}

/// Resolve `avma` into `out` as UTF-8 (no NUL). Returns the byte count
/// written (0 if no match). Caller slices the buffer accordingly.
pub fn resolve(s: *Symbolizer, avma: u64, out: []u8) usize {
    if (out.len == 0) return 0;
    return sismo_symbolizer_resolve(s, avma, out.ptr, out.len);
}
