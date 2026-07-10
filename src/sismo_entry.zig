// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Static-library root. The `sismo` binary's entry and dispatch are Rust
//! (rust-host/src/main.rs) — there is no Zig `main` anymore. This exists only
//! to pull the remaining Zig into libsismo_zig.a: the Linux BPF CPU collector,
//! whose C ABI (sismo_linux_bpf_capture_*) the Rust record runner drives.

comptime {
    _ = @import("linux_bpf_capture.zig");
}
