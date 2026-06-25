// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Thin Zig binding over rust-bridge's data_regions (rust-bridge/src/
//! data_regions.rs; contract in rust-bridge/include/bridge.h). The parser —
//! reading /proc/<pid>/maps and labeling every mapping for the cache focus's
//! data-side attribution — now lives in Rust; this is just the FFI surface.

/// Mirrors `SismoRegion` in bridge.h. `label` borrows the owning `Regions`
/// and stays valid until `deinit`.
pub const Region = extern struct {
    start: u64,
    end: u64,
    label_ptr: [*]const u8,
    label_len: usize,

    pub fn label(self: *const Region) []const u8 {
        return self.label_ptr[0..self.label_len];
    }
};

/// Opaque handle to a parsed, labeled address-space map.
pub const Regions = opaque {
    pub fn deinit(self: *Regions) void {
        sismo_data_regions_destroy(self);
    }

    /// Fill `out` with the region containing `addr`. Returns false (out
    /// untouched) when no region matches.
    pub fn find(self: *const Regions, addr: u64, out: *Region) bool {
        return sismo_data_regions_find(self, addr, out) != 0;
    }
};

extern fn sismo_data_regions_parse(pid: u32) ?*Regions;
extern fn sismo_data_regions_destroy(regions: *Regions) void;
extern fn sismo_data_regions_find(regions: *const Regions, addr: u64, out: *Region) c_int;

/// Parse `/proc/<pid>/maps`. Returns null on failure.
pub fn parse(pid: u32) ?*Regions {
    return sismo_data_regions_parse(pid);
}
