// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Top-level `sismo` CLI dispatch. Owns the help text, the unknown-subcommand
//! error, and the subcommand routing decision. The Zig `main` extracts the
//! subcommand token (argv[1]) and calls [`sismo_cli_dispatch`]; on a routed
//! subcommand it then invokes the still-Zig command body with its native
//! `std.process.Init`. Help/error output goes to stderr to match the prior
//! Zig behavior (`std.debug.print`).
//!
//! First migrated slice of the Zig->Rust move: the dispatcher only. Per-
//! command argument parsing still lives in the Zig cmd_* modules.

use std::io::Write;

/// Dispatcher handled everything itself (help or unknown subcommand). The
/// out-param `exit_code` carries the process exit status (0 for help, 2 for
/// an unknown subcommand).
pub const SISMO_CLI_HANDLED: i32 = 0;
pub const SISMO_CLI_RECORD: i32 = 1;
pub const SISMO_CLI_PREPARE: i32 = 2;
pub const SISMO_CLI_SNAPSHOT: i32 = 3;
pub const SISMO_CLI_DATASOURCE: i32 = 4;

const HELP_TEXT: &str = r#"sismo - cross-platform desktop tracing/profiling tool

Usage:
  sismo record [--output <path>] [--duration <dur>] <command> [args...]
  sismo record [--output <path>] [--duration <dur>] --pid <pid>
      Spawn <command> (or attach to --pid) and record sched +
      CPU samples + heap into a single Perfetto trace. Stops on
      SIGINT, target exit, or --duration. Default --output:
      ./sismo.pftrace. Requires sudo on macOS for kdebug +
      task_for_pid.

  sismo prepare <command> [args...]
      Launch <command> with sismo's dormant heap client preloaded
      and PERFETTO_PRODUCER_SOCK_NAME set to the well-known path.
      The launched process can be attached to later via
      `sismo record --pid <pid>`.

  sismo snapshot [--output <path>]
      Capture a snapshot of a running flight-recorder session
      (`sismo record --flight-recorder`). Connects to the in-
      process service as a fresh consumer, clones the session,
      writes the trace, exits — the recorder is uninvolved.

  sismo datasource <name>
      Daemonized producer. <name> in {macos_sched, macos_cpu_samples,
      heap}. Connects to PERFETTO_PRODUCER_SOCK_NAME, registers
      sismo.<name>, blocks until killed.

  sismo --help
      Show this help.
"#;

fn print_help() {
    // Help has always gone to stderr (it was std.debug.print on the Zig side);
    // keep it there so existing scripts/goldens don't shift streams.
    let _ = write!(std::io::stderr(), "{}", HELP_TEXT);
}

/// `cmd_ptr` is argv[1] (the subcommand token) or null when absent. `cmd_len`
/// is its byte length. Matching is by raw bytes, mirroring the Zig
/// `std.mem.eql(u8, ...)` comparison, so a non-UTF-8 token is simply an
/// unknown subcommand (rendered lossily in the error).
///
/// # Safety
/// `cmd_ptr` must be null or point to `cmd_len` readable bytes; `exit_code`
/// must point to a writable `i32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_cli_dispatch(
    cmd_ptr: *const u8,
    cmd_len: usize,
    exit_code: *mut i32,
) -> i32 {
    *exit_code = 0;

    let cmd: Option<&[u8]> = if cmd_ptr.is_null() {
        None
    } else {
        Some(std::slice::from_raw_parts(cmd_ptr, cmd_len))
    };

    match cmd {
        None => {
            print_help();
            SISMO_CLI_HANDLED
        }
        Some(b"--help") | Some(b"-h") | Some(b"help") => {
            print_help();
            SISMO_CLI_HANDLED
        }
        Some(b"record") => SISMO_CLI_RECORD,
        Some(b"prepare") => SISMO_CLI_PREPARE,
        Some(b"snapshot") => SISMO_CLI_SNAPSHOT,
        Some(b"datasource") => SISMO_CLI_DATASOURCE,
        Some(other) => {
            let _ = write!(
                std::io::stderr(),
                "sismo: unknown subcommand '{}'\n\n{}",
                String::from_utf8_lossy(other),
                HELP_TEXT,
            );
            *exit_code = 2;
            SISMO_CLI_HANDLED
        }
    }
}
