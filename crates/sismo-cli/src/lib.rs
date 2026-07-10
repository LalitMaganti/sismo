// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! The sismo command layer: argument parsing and the record/datasource/prepare/
//! snapshot runners, plus the temporary privileged-pid marker. Built on the
//! `sismo-core` library; the `sismo` binary is a thin wrapper that calls
//! [`cli::run`].

pub mod cli;
// `sismo record` runners (traced + session + watch threads). macOS + Linux
// runners share the helpers here; each runner body is cfg-gated per OS.
#[cfg(not(target_os = "windows"))]
pub mod cmd_record;
// `sismo datasource` subcommand (daemonized privileged producer). POSIX-only.
#[cfg(not(target_os = "windows"))]
pub mod cmd_datasource;
// `sismo prepare` subcommand (DYLD-insert the heap client + exec). POSIX-only.
#[cfg(not(target_os = "windows"))]
pub mod cmd_prepare;
// `sismo snapshot` subcommand (flight-recorder clone client). POSIX-only.
#[cfg(not(target_os = "windows"))]
pub mod cmd_snapshot;
// Temporary privileged-pid marker (hack; appended to the trace file).
pub mod privileged_marker;
// `sismo record` arg value-parsers (seed of the eventual full record parser).
pub mod record_args;
