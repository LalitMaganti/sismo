// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Focus presets for `sismo record --focus <preset>`.
//!
//! A focus recording trades breadth for depth: instead of a timer timebase and
//! the general follower set, it samples *on the event of interest* with PEBS
//! precision and a counter set tuned to one question. Each preset is a small
//! data entry — timebase event, precision, sample period, extra followers — so
//! adding one is a data edit, not new collection code. See
//! docs/sismo_focus_mode.md.
//!
//! Only the presets that have a collection path are listed here; the UI shows
//! the full taxonomy (Cache/Branch/Frontend/Backend) and refuses the ones a
//! recording can't yet produce.

const std = @import("std");
const pmu = @import("gen/pmu_events.zig");

pub const FocusPreset = enum {
    // Event timebase: sample on last-level-cache misses, so the histogram over
    // functions/lines is a direct map of where misses happen.
    cache,
    // NB: there is no "stalls" preset — "make the survey PEBS-precise" is a
    // property of the default recording, not a separate event focus.
};

/// What to sample on (the timebase / sampler leader).
pub const Leader = union(enum) {
    // The survey leader: generic HARDWARE cpu-cycles. With PEBS requested the
    // kernel maps this to a precise cycles event (cycles:pp).
    cycles,
    // A model-specific event resolved from the perfmon table by role (e.g.
    // cache_miss → MEM/LLC miss). Used by event-timebase presets.
    role: pmu.Role,
};

pub const FocusSpec = struct {
    leader: Leader,
    /// PEBS request: 0 = arbitrary skid (off), 2 = request 0 skid.
    precise_ip: u2,
    /// Sampler period, in leader events. A prime avoids aliasing.
    period: u64,
    /// Sample the data linear address (PERF_SAMPLE_ADDR) on each overflow, so a
    /// sample carries *which address* the access touched — the data-side
    /// attribution. Only meaningful when the leader is a precise (PEBS) event
    /// that carries Data_LA (the cache focus); requires precise_ip > 0.
    sample_data_addr: bool = false,
    /// Follower roles this preset needs *beyond* the survey set. Empty for
    /// presets that keep the survey followers.
    extra_followers: []const pmu.Role = &.{},
};

pub fn fromName(name: []const u8) ?FocusPreset {
    return std.meta.stringToEnum(FocusPreset, name);
}

pub fn presetName(p: FocusPreset) []const u8 {
    return @tagName(p);
}

pub fn spec(p: FocusPreset) FocusSpec {
    return switch (p) {
        // Sample on retired loads that missed L3 (MEM_LOAD_RETIRED.L3_MISS): a
        // precise event carrying Data_LA, so every sample names *which address*
        // missed. L3 misses are far rarer than cycles, so a much shorter period
        // keeps the rate useful. Per-level (L1/L2/L3) split followers are a
        // follow-up (new roles + careful PMU budgeting).
        .cache => .{
            .leader = .{ .role = .l3_miss_load },
            .precise_ip = 2,
            .period = 2003,
            .sample_data_addr = true,
        },
    };
}
