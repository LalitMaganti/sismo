// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Value-parsing helpers for `sismo record`'s argument parser (migrated from the
//! pure leaves of cmd_record.zig — parseScaled / parseBufferKb /
//! parseDurationSeconds). These convert `--buffer 256MB` and `--duration 5m`
//! style strings to their scalar values; the Zig parser calls them over the C
//! ABI. They're the self-contained, OS-independent, byte-testable part of the
//! record parser — the rest (RecordArgs assembly, the consumer-session runner)
//! is entangled with the C++ shim + focus_presets and migrates with the runner.
//!
//! This module is the seed of the eventual full Rust `sismo record` parser.

/// Parse `s` as a base-10 integer, scale by `multiplier`, and fit into u64.
/// Returns None on non-numeric input, overflow, a zero result, or exceeding
/// `max` (the target integer's max).
fn parse_scaled(s: &[u8], multiplier: u64, max: u64) -> Option<u64> {
    let text = std::str::from_utf8(s).ok()?;
    let n: u64 = text.parse().ok()?;
    let total = n.checked_mul(multiplier)?;
    if total == 0 || total > max {
        return None;
    }
    Some(total)
}

/// Parse a buffer-size argument like "256MB" / "1GB" / "512KB" into KB
/// (build_config takes uint32 buffer_size_kb). The suffix is required — bare
/// integers are rejected to avoid the bytes-vs-KB ambiguity.
fn parse_buffer_kb(s: &[u8]) -> Option<u32> {
    if s.len() < 3 {
        return None;
    }
    let (num, suffix) = s.split_at(s.len() - 2);
    let multiplier_kb: u64 = match suffix {
        b if b.eq_ignore_ascii_case(b"kb") => 1,
        b if b.eq_ignore_ascii_case(b"mb") => 1024,
        b if b.eq_ignore_ascii_case(b"gb") => 1024 * 1024,
        _ => return None,
    };
    parse_scaled(num, multiplier_kb, u32::MAX as u64).map(|v| v as u32)
}

/// Parse a duration argument: a bare integer (seconds) or an integer with a
/// single-letter 's' / 'm' / 'h' suffix. Returns total seconds (fits u32).
fn parse_duration_seconds(s: &[u8]) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    let last = s[s.len() - 1];
    let (num, multiplier): (&[u8], u64) = match last {
        b's' => (&s[..s.len() - 1], 1),
        b'm' => (&s[..s.len() - 1], 60),
        b'h' => (&s[..s.len() - 1], 3600),
        b'0'..=b'9' => (s, 1),
        _ => return None,
    };
    parse_scaled(num, multiplier, u32::MAX as u64).map(|v| v as u32)
}

// ---- C ABI (called by the Zig record parser) -------------------------------

/// Parse a `--buffer` value into KB. Returns true and writes `*out` on success;
/// false (out untouched) on any invalid input.
///
/// # Safety
/// `s` must be valid for `s_len` bytes; `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_parse_buffer_kb(s: *const u8, s_len: usize, out: *mut u32) -> bool {
    let bytes = unsafe { std::slice::from_raw_parts(s, s_len) };
    match parse_buffer_kb(bytes) {
        Some(v) => {
            unsafe { *out = v };
            true
        }
        None => false,
    }
}

/// Parse a `--duration` value into seconds. Returns true and writes `*out` on
/// success; false (out untouched) on any invalid input.
///
/// # Safety
/// `s` must be valid for `s_len` bytes; `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_parse_duration_seconds(s: *const u8, s_len: usize, out: *mut u32) -> bool {
    let bytes = unsafe { std::slice::from_raw_parts(s, s_len) };
    match parse_duration_seconds(bytes) {
        Some(v) => {
            unsafe { *out = v };
            true
        }
        None => false,
    }
}

// ===========================================================================
// Full `sismo record` argument parser (macOS flag set).
//
// Mirrors cmd_record.zig::parseRecordArgs for the macOS platform (--pid
// supported; --focus / --sample-density are Linux-only and rejected here). The
// Linux parser stays in Zig until P5. Produces a `#[repr(C)] RecordArgsC` the
// Zig `runRecordMacos` consumes — a transitional boundary that collapses when
// the runner itself moves to Rust. The workload command is the argv tail from
// `workload_start`; output_path points into argv (or the static default).
// ===========================================================================

// SourceMode wire values (match cmd_record.zig SourceMode ordering).
const MODE_IN_PROCESS: u8 = 0;
const MODE_EXTERNAL: u8 = 1;
const MODE_OFF: u8 = 2;

// NUL-terminated so `output_path_ptr` is usable as a C string (the Zig runner
// passes it to unlink()); `output_path_len` excludes the NUL. argv-derived
// paths are already NUL-terminated (they come from CStr).
const DEFAULT_OUTPUT: &[u8] = b"./sismo.pftrace\0";
const DEFAULT_OUTPUT_LEN: usize = DEFAULT_OUTPUT.len() - 1;
const DEFAULT_BUFFER_KB: u32 = 128 * 1024;

/// Fully-parsed `sismo record` arguments, C-ABI for the Zig macOS runner.
/// Layout: 8-byte fields first, then 4-byte, then 1-byte — identical to the
/// Zig `extern struct RecordArgsC`.
#[repr(C)]
pub struct RecordArgsC {
    /// Into argv (from `--output`) or the static default. Not NUL-terminated.
    pub output_path_ptr: *const u8,
    pub output_path_len: usize,
    /// argv index where the workload command begins; == argc if none.
    pub workload_start: usize,
    pub attach_pid: i32,
    pub duration_secs: u32,
    pub buffer_kb: u32,
    pub sched_mode: u8,
    pub cpu_mode: u8,
    pub heap_mode: u8,
    pub has_attach_pid: bool,
    pub has_duration: bool,
    pub flight_recorder: bool,
    pub buffer_set: bool,
    pub no_instrumentation: bool,
}

impl Default for RecordArgsC {
    fn default() -> Self {
        RecordArgsC {
            output_path_ptr: DEFAULT_OUTPUT.as_ptr(),
            output_path_len: DEFAULT_OUTPUT_LEN,
            workload_start: 0,
            attach_pid: 0,
            duration_secs: 0,
            buffer_kb: DEFAULT_BUFFER_KB,
            sched_mode: MODE_IN_PROCESS,
            cpu_mode: MODE_IN_PROCESS,
            heap_mode: MODE_IN_PROCESS,
            has_attach_pid: false,
            has_duration: false,
            flight_recorder: false,
            buffer_set: false,
            no_instrumentation: false,
        }
    }
}

/// Set a data source's mode, rejecting a conflicting second flag (e.g.
/// `--no-cpu --external-cpu`). Returns false (and prints) on conflict.
fn set_source_mode(slot: &mut u8, slot_name: &str, flag_name: &str, want: u8) -> bool {
    if *slot != MODE_IN_PROCESS && *slot != want {
        let cur = match *slot {
            MODE_EXTERNAL => "external",
            MODE_OFF => "off",
            _ => "in_process",
        };
        eprintln!("sismo record: conflicting flags for '{slot_name}' ({flag_name} vs already-set {cur})");
        return false;
    }
    *slot = want;
    true
}

/// The macOS `sismo record` help text (mirrors printRecordHelp with macOS caps).
fn print_record_help() {
    print!(
        "usage: sismo record [--output <path>] [--duration <dur>]\n\
         \x20                   [--flight-recorder [--buffer <size>]]\n\
         \x20                   [--no-instrumentation]\n\
         \x20                   [--no-sched | --external-sched]\n\
         \x20                   [--no-cpu | --external-cpu]\n\
         \x20                   [--no-heap | --external-heap]\n\
         \x20                   [--all-external]\n\
         \x20                   (--pid <pid> | <command> [args...])\n\n  \
         --no-X         disable data source X entirely.\n  \
         --external-X   data source X comes from a sidecar\n  \
         \x20              `sudo sismo datasource X` (no sudo on this process).\n  \
         --all-external shorthand for --external for every privileged source.\n"
    );
}

/// A value-taking flag reads args[i+1], advancing `i`. Prints `missing` and
/// returns None if the value is absent.
fn next_value<'a>(args: &[&'a str], i: &mut usize, missing: &str) -> Option<&'a str> {
    if *i + 1 >= args.len() {
        eprintln!("{missing}");
        return None;
    }
    *i += 1;
    Some(args[*i])
}

/// Parse `sismo record` args (macOS). `args` is argv[2..] (after exe +
/// "record"); `base` is the absolute argv index of args[0] (i.e. 2). Fills
/// `out` and returns true to proceed, or false if help / an error was printed.
fn parse_record_args(args: &[&str], base: usize, out: &mut RecordArgsC) -> bool {
    *out = RecordArgsC::default();
    out.workload_start = base + args.len(); // none, unless a workload is found

    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i];

        // `--` ends option parsing; the rest is the workload command.
        if arg == "--" {
            out.workload_start = base + i + 1;
            break;
        }
        // A non-`--` token is the workload command; the rest is its args.
        if !arg.starts_with("--") {
            out.workload_start = base + i;
            break;
        }

        match arg {
            "--output" => {
                match next_value(args, &mut i, "sismo record: --output needs a value") {
                    Some(v) => {
                        out.output_path_ptr = v.as_ptr();
                        out.output_path_len = v.len();
                    }
                    None => return false,
                }
            }
            "--flight-recorder" => out.flight_recorder = true,
            "--buffer" => {
                let v = match next_value(args, &mut i, "sismo record: --buffer needs a value (e.g. 256MB)") {
                    Some(v) => v,
                    None => return false,
                };
                match parse_buffer_kb(v.as_bytes()) {
                    Some(kb) => {
                        out.buffer_kb = kb;
                        out.buffer_set = true;
                    }
                    None => {
                        eprintln!("sismo record: invalid --buffer '{v}' (use 256MB / 1GB / 512KB)");
                        return false;
                    }
                }
            }
            "--pid" => {
                let v = match next_value(args, &mut i, "sismo record: --pid needs a value") {
                    Some(v) => v,
                    None => return false,
                };
                match v.parse::<i32>() {
                    Ok(p) => {
                        out.attach_pid = p;
                        out.has_attach_pid = true;
                    }
                    Err(_) => {
                        eprintln!("sismo record: --pid '{v}' is not a number");
                        return false;
                    }
                }
            }
            "--duration" => {
                let v = match next_value(args, &mut i, "sismo record: --duration needs a value (e.g. 30s, 5m, 1h)") {
                    Some(v) => v,
                    None => return false,
                };
                match parse_duration_seconds(v.as_bytes()) {
                    Some(s) => {
                        out.duration_secs = s;
                        out.has_duration = true;
                    }
                    None => {
                        eprintln!("sismo record: invalid --duration '{v}' (use 30s / 5m / 1h)");
                        return false;
                    }
                }
            }
            "--no-sched" => {
                if !set_source_mode(&mut out.sched_mode, "sched", "--no-sched", MODE_OFF) {
                    return false;
                }
            }
            "--no-cpu" => {
                if !set_source_mode(&mut out.cpu_mode, "cpu", "--no-cpu", MODE_OFF) {
                    return false;
                }
            }
            "--no-heap" => {
                if !set_source_mode(&mut out.heap_mode, "heap", "--no-heap", MODE_OFF) {
                    return false;
                }
            }
            "--external-sched" => {
                if !set_source_mode(&mut out.sched_mode, "sched", "--external-sched", MODE_EXTERNAL) {
                    return false;
                }
            }
            "--external-cpu" => {
                if !set_source_mode(&mut out.cpu_mode, "cpu", "--external-cpu", MODE_EXTERNAL) {
                    return false;
                }
            }
            "--external-heap" => {
                if !set_source_mode(&mut out.heap_mode, "heap", "--external-heap", MODE_EXTERNAL) {
                    return false;
                }
            }
            "--all-external" => {
                for m in [&mut out.sched_mode, &mut out.cpu_mode, &mut out.heap_mode] {
                    if *m == MODE_IN_PROCESS {
                        *m = MODE_EXTERNAL;
                    }
                }
            }
            "--no-instrumentation" => out.no_instrumentation = true,
            "--focus" => {
                eprintln!("sismo record: --focus needs the Linux BPF/PEBS path (not supported on macos)");
                return false;
            }
            "--sample-density" => {
                // Parsed for parity, but macOS has no focus path so it always
                // fails the "only applies with --focus" validation below.
                match next_value(args, &mut i, "sismo record: --sample-density needs a value (e.g. 8 for 8x the samples)") {
                    Some(_) => {
                        eprintln!("sismo record: --sample-density only applies with --focus");
                        return false;
                    }
                    None => return false,
                }
            }
            "--help" => {
                print_record_help();
                return false;
            }
            other => {
                eprintln!("sismo record: unknown flag '{other}'");
                return false;
            }
        }
        i += 1;
    }

    // Cross-cutting validation: exactly one workload-acquisition mode.
    let have_pid = out.has_attach_pid;
    let have_cmd = out.workload_start < base + args.len();
    if have_pid && have_cmd {
        eprintln!("sismo record: --pid and <command> are mutually exclusive");
        return false;
    }
    if !have_pid && !have_cmd {
        eprintln!("sismo record: need either --pid <pid> or a workload <command>");
        return false;
    }

    // FILE mode default buffer is 128 MB; flight-recorder bumps to 256 MB
    // unless the user set --buffer explicitly.
    if out.flight_recorder && !out.buffer_set {
        out.buffer_kb = 256 * 1024;
    }
    true
}

/// C ABI: parse `argv[0..argc]` (macOS) into `*out`. Returns true to proceed,
/// false if help / an error was already printed (caller should exit).
///
/// # Safety
/// `argv` must point to `argc` valid NUL-terminated C strings; `out` writable.
/// `out.output_path_ptr` borrows either argv or a static — valid for the
/// process lifetime.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_parse_record_args(
    argc: usize,
    argv: *const *const std::os::raw::c_char,
    out: *mut RecordArgsC,
) -> bool {
    let all: Vec<&str> = (0..argc)
        .map(|i| unsafe { std::ffi::CStr::from_ptr(*argv.add(i)) }.to_str().unwrap_or(""))
        .collect();
    // Skip argv[0] (exe) + argv[1] ("record"); base index is 2.
    let (args, base): (&[&str], usize) = if all.len() > 2 { (&all[2..], 2) } else { (&[], all.len()) };
    parse_record_args(args, base, unsafe { &mut *out })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: parse args (argv[2..]) with base=2 into a fresh RecordArgsC.
    fn parse(args: &[&str]) -> Option<RecordArgsC> {
        let mut out = RecordArgsC::default();
        if parse_record_args(args, 2, &mut out) {
            Some(out)
        } else {
            None
        }
    }

    #[test]
    fn defaults_with_just_a_command() {
        let a = parse(&["./app"]).unwrap();
        assert_eq!(a.workload_start, 2); // args[0] is the command → abs index 2
        assert!(!a.has_attach_pid);
        assert_eq!(a.buffer_kb, DEFAULT_BUFFER_KB);
        assert_eq!(a.sched_mode, MODE_IN_PROCESS);
        assert_eq!(a.output_path_len, DEFAULT_OUTPUT_LEN);
        // default path ptr is NUL-terminated at [len] for C-string use.
        let s = unsafe { std::slice::from_raw_parts(a.output_path_ptr, a.output_path_len + 1) };
        assert_eq!(s, b"./sismo.pftrace\0");
    }

    #[test]
    fn record_args_c_layout_is_48_bytes() {
        // Must match the Zig `extern struct RecordArgsC` (guarded there too).
        assert_eq!(std::mem::size_of::<RecordArgsC>(), 48);
        assert_eq!(std::mem::align_of::<RecordArgsC>(), 8);
    }

    #[test]
    fn pid_attach_and_flags() {
        let a = parse(&["--pid", "4242", "--no-heap", "--external-cpu"]).unwrap();
        assert!(a.has_attach_pid);
        assert_eq!(a.attach_pid, 4242);
        assert_eq!(a.heap_mode, MODE_OFF);
        assert_eq!(a.cpu_mode, MODE_EXTERNAL);
        assert_eq!(a.workload_start, 2 + 4); // no workload → base+len
    }

    #[test]
    fn all_external_only_promotes_in_process() {
        let a = parse(&["--no-sched", "--all-external", "--pid", "1"]).unwrap();
        assert_eq!(a.sched_mode, MODE_OFF); // stays off, not promoted
        assert_eq!(a.cpu_mode, MODE_EXTERNAL);
        assert_eq!(a.heap_mode, MODE_EXTERNAL);
    }

    #[test]
    fn double_dash_starts_workload() {
        // `--` at args index 0 → workload starts at abs index 2+0+1 = 3, so the
        // command can carry its own --flags. (No --pid: it's mutually exclusive
        // with a workload, even via `--`, matching the Zig parser.)
        let a = parse(&["--", "./app", "--weird-workload-flag"]).unwrap();
        assert_eq!(a.workload_start, 3);
        assert!(!a.has_attach_pid);
    }

    #[test]
    fn flight_recorder_bumps_buffer() {
        let a = parse(&["--flight-recorder", "--pid", "1"]).unwrap();
        assert_eq!(a.buffer_kb, 256 * 1024);
        // explicit --buffer wins.
        let b = parse(&["--flight-recorder", "--buffer", "512MB", "--pid", "1"]).unwrap();
        assert_eq!(b.buffer_kb, 512 * 1024);
    }

    #[test]
    fn rejections() {
        assert!(parse(&["--pid", "1", "./app"]).is_none()); // pid + cmd exclusive
        assert!(parse(&[]).is_none()); // neither pid nor cmd
        assert!(parse(&["--no-cpu", "--external-cpu", "--pid", "1"]).is_none()); // conflict
        assert!(parse(&["--pid", "notanum"]).is_none());
        assert!(parse(&["--focus", "cache", "--pid", "1"]).is_none()); // macOS rejects focus
        assert!(parse(&["--sample-density", "8", "--pid", "1"]).is_none());
        assert!(parse(&["--bogus", "--pid", "1"]).is_none());
        assert!(parse(&["--output"]).is_none()); // missing value
    }

    #[test]
    fn output_path_override() {
        let a = parse(&["--output", "/tmp/x.pftrace", "--pid", "1"]).unwrap();
        let s = unsafe { std::slice::from_raw_parts(a.output_path_ptr, a.output_path_len) };
        assert_eq!(s, b"/tmp/x.pftrace");
    }

    #[test]
    fn buffer_kb_suffixes() {
        assert_eq!(parse_buffer_kb(b"512KB"), Some(512));
        assert_eq!(parse_buffer_kb(b"256MB"), Some(256 * 1024));
        assert_eq!(parse_buffer_kb(b"1GB"), Some(1024 * 1024));
        assert_eq!(parse_buffer_kb(b"2gb"), Some(2 * 1024 * 1024)); // case-insensitive
    }

    #[test]
    fn buffer_kb_rejects_bare_and_bad() {
        assert_eq!(parse_buffer_kb(b"256"), None); // no suffix
        assert_eq!(parse_buffer_kb(b"MB"), None); // too short / no number
        assert_eq!(parse_buffer_kb(b"0KB"), None); // zero rejected
        assert_eq!(parse_buffer_kb(b"xxMB"), None); // non-numeric
    }

    #[test]
    fn buffer_kb_overflow_rejected() {
        // 5 GB in KB = 5*1024*1024 = 5_242_880 (fits u32), but 5000GB overflows.
        assert_eq!(parse_buffer_kb(b"5000GB"), None);
        // exactly at the u32 boundary in KB is fine; wildly over is not.
        assert_eq!(parse_buffer_kb(b"99999999999999999999GB"), None);
    }

    #[test]
    fn duration_suffixes_and_bare() {
        assert_eq!(parse_duration_seconds(b"30"), Some(30)); // bare int = seconds
        assert_eq!(parse_duration_seconds(b"30s"), Some(30));
        assert_eq!(parse_duration_seconds(b"5m"), Some(300));
        assert_eq!(parse_duration_seconds(b"1h"), Some(3600));
    }

    #[test]
    fn duration_rejects_bad() {
        assert_eq!(parse_duration_seconds(b""), None);
        assert_eq!(parse_duration_seconds(b"0"), None); // zero rejected
        assert_eq!(parse_duration_seconds(b"5d"), None); // unsupported suffix
        assert_eq!(parse_duration_seconds(b"abc"), None);
        assert_eq!(parse_duration_seconds(b"h"), None); // suffix, no number
    }

    #[test]
    fn c_abi_writes_out_only_on_success() {
        let mut out: u32 = 12345;
        assert!(unsafe { sismo_parse_buffer_kb(b"256MB".as_ptr(), 5, &mut out) });
        assert_eq!(out, 256 * 1024);
        // failure leaves out untouched.
        assert!(!unsafe { sismo_parse_buffer_kb(b"256".as_ptr(), 3, &mut out) });
        assert_eq!(out, 256 * 1024);

        let mut d: u32 = 0;
        assert!(unsafe { sismo_parse_duration_seconds(b"5m".as_ptr(), 2, &mut d) });
        assert_eq!(d, 300);
    }
}
