// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `sismo snapshot` — flight-recorder snapshot client.
//!
//! Doesn't talk to the recorder process. Connects independently to the
//! in-process tracing service the recorder hosts (its ServiceIPCHost) as a
//! fresh consumer, calls CloneTrace + ReadTrace via the C++ shim
//! (`sismo_consumer_clone_and_stream`), and streams the trace bytes back to a
//! chunk callback that owns the file I/O. The recorder is uninvolved — multiple
//! snapshots can run concurrently while the source keeps recording.
//!
//! Usage: `sismo snapshot [--output <path>]`
//! Default output: ./sismo-<UTC-ISO8601>.pftrace in the current dir.
//!
//! The body is portable — SystemTime for the clock, `std::env::set_var` for the
//! socket env (on Unix that calls setenv, so the C++ SDK sees it via getenv),
//! std for the file I/O — and Perfetto's CloneTrace works on Windows too. The
//! module is `cfg`-gated off Windows only because the surrounding sismo CLI
//! dispatch is still POSIX-only (the other cmd_* use posix_spawnp + flock) and
//! the socket constants come from the POSIX-gated sismo_paths; it's ready to
//! ungate when the CLI does (only the env mechanism may need Windows care).
//!
//! The C++ clone shim is provided in the final binary; `#[cfg(test)]` stubs it
//! so the pure helpers (arg parse, default-path formatting) test standalone.

use sismo_core::sismo_paths::{CONSUMER_SOCK, PRODUCER_SOCK};
use std::io::Write;
use std::os::raw::{c_char, c_void};
use std::time::{SystemTime, UNIX_EPOCH};

use sismo_core::ffi::sismo_consumer_clone_and_stream;

// ---- Snapshot streaming ----------------------------------------------------

/// State the C++ chunk callback writes through. The callback may fire on a
/// Perfetto-internal thread; a single snapshot streams serially so a plain
/// &mut via raw pointer is safe (no concurrent chunk callbacks for one clone).
struct SnapshotCtx {
    file: std::fs::File,
    write_failed: bool,
    bytes_written: u64,
}

extern "C" fn snapshot_chunk_cb(data: *const c_void, size: usize, _has_more: bool, user_arg: *mut c_void) {
    if size == 0 || user_arg.is_null() || data.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(user_arg as *mut SnapshotCtx) };
    if ctx.write_failed {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(data as *const u8, size) };
    if ctx.file.write_all(slice).is_err() {
        ctx.write_failed = true;
        return;
    }
    ctx.bytes_written += size as u64;
}

// ---- Entry point -----------------------------------------------------------

#[derive(clap::Args)]
pub struct SnapshotArgs {
    /// Output trace path (default: ./sismo-<UTC>.pftrace).
    #[arg(long)]
    output: Option<String>,
}

/// `sismo snapshot` subcommand. Returns the process exit code (0 ok, non-zero
/// on error).
pub fn run(args: SnapshotArgs) -> i32 {
    let default_path;
    let output_path: &str = match &args.output {
        Some(p) => p,
        None => {
            default_path = default_output_path();
            &default_path
        }
    };

    // Point the C++ SDK at the well-known sockets sismo-record hosts. On Unix
    // set_var calls setenv, so the SDK reads these back via getenv.
    std::env::set_var("PERFETTO_PRODUCER_SOCK_NAME", PRODUCER_SOCK);
    std::env::set_var("PERFETTO_CONSUMER_SOCK_NAME", CONSUMER_SOCK);

    let file = match std::fs::File::create(output_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("sismo snapshot: failed to create {output_path}: {e}");
            return 0;
        }
    };

    let mut ctx = SnapshotCtx { file, write_failed: false, bytes_written: 0 };
    let name = b"sismo_record\0";
    let rc = unsafe {
        sismo_consumer_clone_and_stream(
            name.as_ptr() as *const c_char,
            snapshot_chunk_cb,
            &mut ctx as *mut SnapshotCtx as *mut c_void,
        )
    };
    if rc != 0 {
        eprintln!("sismo snapshot: clone failed (rc={rc}). Is `sismo record --flight-recorder` running?");
        return 0;
    }
    if ctx.write_failed {
        eprintln!("sismo snapshot: write to {output_path} failed mid-stream");
        return 0;
    }

    println!("sismo snapshot: wrote {output_path} ({} bytes)", ctx.bytes_written);
    0
}

/// Build `./sismo-<UTC>.pftrace` (timestamp like 20250502-171530).
fn default_output_path() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (y, mo, d, h, mi, s) = civil_from_epoch(secs);
    format!("./sismo-{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}.pftrace")
}

/// Break UTC epoch seconds into (year, month, day, hour, min, sec). Uses Howard
/// Hinnant's days_from_civil inverse — no chrono dependency.
fn civil_from_epoch(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = (secs % 86_400) as u32;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;

    // civil_from_days (Hinnant): days since 1970-01-01.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, hour, min, sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_epoch_zero_is_1970() {
        assert_eq!(civil_from_epoch(0), (1970, 1, 1, 0, 0, 0));
    }

    #[test]
    fn civil_known_timestamp() {
        // 2025-05-02 17:15:30 UTC = 1746206130.
        assert_eq!(civil_from_epoch(1_746_206_130), (2025, 5, 2, 17, 15, 30));
    }

    #[test]
    fn civil_leap_day() {
        // 2024-02-29 00:00:00 UTC = 1709164800.
        assert_eq!(civil_from_epoch(1_709_164_800), (2024, 2, 29, 0, 0, 0));
    }

    #[test]
    fn default_path_shape() {
        let p = default_output_path();
        assert!(p.starts_with("./sismo-"));
        assert!(p.ends_with(".pftrace"));
        // ./sismo-YYYYMMDD-HHMMSS.pftrace = 8 + 8 + 1 + 6 + 8 = 31 chars.
        assert_eq!(p.len(), "./sismo-20260502-171530.pftrace".len());
    }
}
