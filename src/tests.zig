// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Unit-test aggregator. `zig build test` compiles this as a test binary so
//! the `test {}` blocks in the referenced modules run under one invocation.
//!
//! Only OS-portable, link-light modules belong here: nothing that pulls in
//! Perfetto C++ or the rust-bridge staticlib, so the test binary builds with
//! no extra link wiring. perf_symbolize + source_asm_sidecar now live in Rust
//! (rust-bridge/src/perf_symbolize.rs) — their tests run under `cargo test`.

comptime {
    _ = @import("proto_writer.zig");
    _ = @import("perfetto_proto.zig");
    // sismo_config.zig is now a thin FFI facade over rust-bridge (its wire
    // codec + tests live in rust-bridge/src/sismo_config.rs), so it needs the
    // full sismo link — excluded from the link-light test binary.
}
