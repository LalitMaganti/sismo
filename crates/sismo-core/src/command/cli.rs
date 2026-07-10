// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Top-level `sismo` CLI, on clap derive. [`run`] parses the process argv into
//! [`Cli`] and dispatches to the matching `cmd_*` module.

use clap::{CommandFactory, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "sismo",
    about = "cross-platform desktop tracing/profiling tool",
    disable_version_flag = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Spawn a command (or attach to --pid) and record sched + CPU samples +
    /// heap into a single Perfetto trace. Stops on SIGINT, target exit, or
    /// --duration. Requires sudo on macOS for kdebug + task_for_pid.
    Record(crate::command::record_args::RecordArgs),

    /// Launch a command with sismo's dormant heap client preloaded, so it can
    /// be attached to later via `sismo record --pid <pid>`.
    Prepare(crate::command::cmd_prepare::PrepareArgs),

    /// Snapshot a running flight-recorder session (`sismo record
    /// --flight-recorder`): clone it as a fresh consumer and write the trace.
    Snapshot(crate::command::cmd_snapshot::SnapshotArgs),

    /// Run a daemonized data-source producer for an external `sismo record`.
    Datasource(crate::command::cmd_datasource::DatasourceArgs),
}

/// Parse the process argv (`args[0]` is the exe) and run the chosen subcommand,
/// returning its exit code. clap prints help/version/errors itself.
pub fn run(args: &[String]) -> i32 {
    let cli = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            return e.exit_code();
        }
    };
    match cli.command {
        None => {
            let _ = Cli::command().print_help();
            0
        }
        Some(Commands::Record(a)) => crate::command::cmd_record::run(a),
        Some(Commands::Prepare(a)) => crate::command::cmd_prepare::run(a),
        Some(Commands::Snapshot(a)) => crate::command::cmd_snapshot::run(a),
        Some(Commands::Datasource(a)) => crate::command::cmd_datasource::run(a),
    }
}
