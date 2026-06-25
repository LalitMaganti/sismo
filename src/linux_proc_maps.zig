// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Thin Zig binding over rust-bridge's proc_maps (rust-bridge/src/proc_maps.rs;
//! contract in rust-bridge/include/bridge.h). The parser itself — reading
//! /proc/<pid>/maps, ELF build-ids, the executable-mapping filter — now lives
//! in Rust; this file is just the FFI surface the recorder calls.

/// Mirrors `SismoMapping` in bridge.h. `path`/`build_id` borrow the owning
/// `Maps` and stay valid until `deinit`.
pub const Mapping = extern struct {
    start: u64,
    end: u64,
    offset: u64,
    base_avma: u64,
    path_ptr: [*]const u8,
    path_len: usize,
    build_id_ptr: [*]const u8,
    build_id_len: usize,

    pub fn path(self: *const Mapping) []const u8 {
        return self.path_ptr[0..self.path_len];
    }
    pub fn buildId(self: *const Mapping) []const u8 {
        return self.build_id_ptr[0..self.build_id_len];
    }
};

/// Opaque handle to a parsed address-space map.
pub const Maps = opaque {
    pub fn deinit(self: *Maps) void {
        sismo_proc_maps_destroy(self);
    }

    /// Fill `out` with the executable file-backed mapping containing `addr`.
    /// Returns false (out untouched) when no mapping matches.
    pub fn find(self: *const Maps, addr: u64, out: *Mapping) bool {
        return sismo_proc_maps_find(self, addr, out) != 0;
    }
};

extern fn sismo_proc_maps_parse(pid: u32) ?*Maps;
extern fn sismo_proc_maps_destroy(maps: *Maps) void;
extern fn sismo_proc_maps_find(maps: *const Maps, addr: u64, out: *Mapping) c_int;

/// Parse `/proc/<pid>/maps`. Returns null on failure.
pub fn parse(pid: u32) ?*Maps {
    return sismo_proc_maps_parse(pid);
}
