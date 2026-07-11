// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `sismo snapshot` — clone the running recorder's rolling buffer to a file.
//!
//! Doesn't talk to the recorder process. Connects independently to the
//! in-process tracing service the recorder hosts (its ServiceIPCHost) as a
//! fresh consumer and clones + streams its buffer via
//! [`crate::trace_sink::clone_session_to_file`]. The recorder is uninvolved and
//! keeps recording — multiple snapshots can run concurrently.
//!
//! Usage: `sismo snapshot [--output <path>]`
//! Default output: ./sismo-<UTC-ISO8601>.pftrace in the current dir.
//!
//! `cfg`-gated off Windows only because the surrounding CLI dispatch is still
//! POSIX-only (the socket constants come from the POSIX-gated sismo_paths);
//! Perfetto's CloneTrace itself works on Windows too.

use crate::trace_sink;
use sismo_core::sismo_paths::{CONSUMER_SOCK, PRODUCER_SOCK};

#[derive(clap::Args)]
pub struct SnapshotArgs {
    /// Output trace path (default: ./sismo-<UTC>.pftrace).
    #[arg(long)]
    output: Option<String>,
}

/// `sismo snapshot` subcommand. Returns the process exit code (0 ok, non-zero
/// on error).
pub fn run(args: SnapshotArgs) -> i32 {
    let output_path: String = args.output.unwrap_or_else(trace_sink::timestamped_output_path);

    // Point the C++ SDK at the sockets sismo-record hosts. On Unix set_var calls
    // setenv, so the SDK reads these back via getenv.
    std::env::set_var("PERFETTO_PRODUCER_SOCK_NAME", PRODUCER_SOCK);
    std::env::set_var("PERFETTO_CONSUMER_SOCK_NAME", CONSUMER_SOCK);

    match trace_sink::clone_session_to_file("sismo_record", &output_path) {
        Ok(bytes) => {
            println!("sismo snapshot: wrote {output_path} ({bytes} bytes)");
            0
        }
        Err(e) => {
            eprintln!("sismo snapshot: {e}");
            eprintln!("  is `sismo record` running? (snapshot needs the default rolling-buffer mode, not --long-trace)");
            0
        }
    }
}
