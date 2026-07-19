// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `sismo symbolize <trace>`: run the post-record symbolization pass over a
//! trace on its own — the deferred half of the record/symbolize split (CAP-3).
//!
//! `sismo record --no-symbolize` leaves the trace's native frames as
//! `{build-id, file-offset}` coordinates. This resolves them to names offline —
//! later, or on a different machine — reading the module files from disk (not a
//! live process) and appending the symbols in place, exactly as the inline
//! post-record pass does. It is the same `symbolize_trace` the recorder runs,
//! just decoupled from recording.

use clap::Args;

#[derive(Args)]
pub struct SymbolizeArgs {
    /// The Perfetto trace to symbolize in place (e.g. one from
    /// `sismo record --no-symbolize`).
    trace: String,
}

pub fn run(args: SymbolizeArgs) -> i32 {
    if !std::path::Path::new(&args.trace).is_file() {
        eprintln!("sismo symbolize: no such trace: {}", args.trace);
        return 1;
    }
    #[cfg(not(target_os = "windows"))]
    {
        sismo_core::symbolize::perf_symbolize::symbolize_trace(&args.trace);
        0
    }
    #[cfg(target_os = "windows")]
    {
        eprintln!("sismo symbolize: not supported on this platform");
        1
    }
}
