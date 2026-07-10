// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Native C/C++ dependencies for sismo. The Perfetto C++ SDK shims (csrc/) are
//! compiled + linked by the crates that build the final binaries; this crate
//! owns the C sources and hands out the compiled kernel BPF object.

/// The compiled kernel-side BPF object (build.rs, Linux only).
#[cfg(target_os = "linux")]
pub static BPF_OBJ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sched.bpf.o"));
