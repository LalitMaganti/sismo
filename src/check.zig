// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Cross-platform compile sentinel. `zig build check -Dtarget=…` builds this as
//! an object (no link) to catch cross-platform regressions in the remaining
//! OS-portable Zig without a full build. Most of the Zig is now Linux-only
//! (the BPF collector); proto_writer is the portable piece worth checking.

const proto_writer = @import("proto_writer.zig");

comptime {
    _ = proto_writer;
}
