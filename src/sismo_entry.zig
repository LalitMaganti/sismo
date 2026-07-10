// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Static-library root. sismo's entry, dispatch, and every collector are Rust
//! now; no Zig ships in the binary. This archive exists only to supply Zig's
//! bundled compiler_rt (__zig_probe_stack etc.) to the perfetto C/C++ shims,
//! which rust-host/build.rs compiles with `zig c++`.

comptime {}
