// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Shared trace-output plumbing: cloning a running session's buffer to a file,
//! and the default timestamped output path. Used by `sismo snapshot` (an
//! on-demand clone while recording continues) and by `sismo record`'s
//! dump-on-exit (the final clone of the rolling buffer before stop).
//!
//! The caller is responsible for pointing the C++ SDK at the recorder's sockets
//! (via `PERFETTO_CONSUMER_SOCK_NAME` / `PERFETTO_PRODUCER_SOCK_NAME`) before
//! calling `clone_session_to_file`; the in-process recorder already has them set.

use std::ffi::CString;
use std::io::Write;
use std::os::raw::{c_char, c_void};
use std::time::{SystemTime, UNIX_EPOCH};

use sismo_core::ffi::sismo_consumer_clone_and_stream;

/// State the C++ chunk callback writes through. The callback may fire on a
/// Perfetto-internal thread; a single clone streams serially, so a plain `&mut`
/// via raw pointer is safe (no concurrent chunk callbacks for one clone).
struct SinkCtx {
    file: std::fs::File,
    write_failed: bool,
    bytes_written: u64,
}

extern "C" fn chunk_cb(data: *const c_void, size: usize, _has_more: bool, user_arg: *mut c_void) {
    if size == 0 || user_arg.is_null() || data.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(user_arg as *mut SinkCtx) };
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

/// Clone the running session named `session_name` and stream its buffer to
/// `output_path`, returning the number of bytes written. The source session
/// keeps recording. Assumes the caller has set the consumer socket env var.
pub fn clone_session_to_file(session_name: &str, output_path: &str) -> Result<u64, String> {
    let file = std::fs::File::create(output_path)
        .map_err(|e| format!("failed to create {output_path}: {e}"))?;
    let mut ctx = SinkCtx { file, write_failed: false, bytes_written: 0 };
    let name = CString::new(session_name).map_err(|_| "session name has an interior NUL".to_string())?;
    let rc = unsafe {
        sismo_consumer_clone_and_stream(name.as_ptr() as *const c_char, chunk_cb, &mut ctx as *mut SinkCtx as *mut c_void)
    };
    if rc != 0 {
        return Err(format!("clone failed (rc={rc})"));
    }
    if ctx.write_failed {
        return Err(format!("write to {output_path} failed mid-stream"));
    }
    Ok(ctx.bytes_written)
}

/// Build `./sismo-<UTC>.pftrace` (timestamp like 20250502-171530).
pub fn timestamped_output_path() -> String {
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
        let p = timestamped_output_path();
        assert!(p.starts_with("./sismo-"));
        assert!(p.ends_with(".pftrace"));
        // ./sismo-YYYYMMDD-HHMMSS.pftrace
        assert_eq!(p.len(), "./sismo-20260502-171530.pftrace".len());
    }
}
