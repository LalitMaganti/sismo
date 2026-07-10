// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! The single `sismo record` argument parser (all platforms), built on clap.
//!
//! One parser, one flag set everywhere — platform differences are a small
//! post-parse capability check (`--pid` is macOS-only, `--focus` /
//! `--sample-density` are Linux-only), NOT a separate per-OS parser. It produces
//! a C-ABI `RecordArgsC` consumed by both the Rust macOS runner
//! (rust-bridge/src/cmd_record.rs) and the Zig Linux runner (cmd_record.zig).
//!
//! The workload command is the trailing argv tail (`workload_start` is its
//! absolute argv index); `--output` / `--focus` values are leaked as
//! NUL-terminated C strings (the record process is one-shot, so the bounded
//! leak of the final args is fine). Focus is passed as its preset *name* — the
//! Linux runner resolves it via focus_presets, keeping this parser decoupled.

use clap::{Arg, ArgAction, Command};

// ---- Scalar value parsers (also clap value_parsers) ------------------------

/// Parse `s` as a base-10 integer, scale by `multiplier`, fit into u64. None on
/// non-numeric input, overflow, a zero result, or exceeding `max`.
fn parse_scaled(s: &[u8], multiplier: u64, max: u64) -> Option<u64> {
    let text = std::str::from_utf8(s).ok()?;
    let n: u64 = text.parse().ok()?;
    let total = n.checked_mul(multiplier)?;
    if total == 0 || total > max {
        return None;
    }
    Some(total)
}

/// Parse a buffer-size argument like "256MB" / "1GB" / "512KB" into KB. Suffix
/// required — bare integers are rejected (bytes-vs-KB ambiguity).
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

/// Parse a duration argument: bare integer (seconds) or integer + 's'/'m'/'h'.
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

fn clap_buffer(s: &str) -> Result<u32, String> {
    parse_buffer_kb(s.as_bytes()).ok_or_else(|| format!("invalid --buffer '{s}' (use 256MB / 1GB / 512KB)"))
}
fn clap_duration(s: &str) -> Result<u32, String> {
    parse_duration_seconds(s.as_bytes()).ok_or_else(|| format!("invalid --duration '{s}' (use 30s / 5m / 1h)"))
}
fn clap_density(s: &str) -> Result<f64, String> {
    let v: f64 = s.parse().map_err(|_| format!("--sample-density must be a positive number, got '{s}'"))?;
    if v > 0.0 {
        Ok(v)
    } else {
        Err(format!("--sample-density must be a positive number, got '{s}'"))
    }
}

// ---- Value parsers still exposed to the Zig build --------------------------
// (Kept for any transitional Zig caller; the Rust parser uses the fns above.)

/// # Safety
/// `s` valid for `s_len`; `out` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_parse_buffer_kb(s: *const u8, s_len: usize, out: *mut u32) -> bool {
    match parse_buffer_kb(unsafe { std::slice::from_raw_parts(s, s_len) }) {
        Some(v) => {
            unsafe { *out = v };
            true
        }
        None => false,
    }
}

/// # Safety
/// `s` valid for `s_len`; `out` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_parse_duration_seconds(s: *const u8, s_len: usize, out: *mut u32) -> bool {
    match parse_duration_seconds(unsafe { std::slice::from_raw_parts(s, s_len) }) {
        Some(v) => {
            unsafe { *out = v };
            true
        }
        None => false,
    }
}

// ---- RecordArgsC + defaults ------------------------------------------------

// SourceMode wire values (match cmd_record.zig SourceMode ordering).
pub(crate) const MODE_IN_PROCESS: u8 = 0;
pub(crate) const MODE_EXTERNAL: u8 = 1;
const MODE_OFF: u8 = 2;

// NUL-terminated default so `output_path_ptr` works as a C string (unlink);
// `output_path_len` excludes the NUL. argv-derived / leaked values are too.
const DEFAULT_OUTPUT: &[u8] = b"./sismo.pftrace\0";
const DEFAULT_OUTPUT_LEN: usize = DEFAULT_OUTPUT.len() - 1;
const DEFAULT_BUFFER_KB: u32 = 128 * 1024;

/// Fully-parsed `sismo record` arguments, C-ABI for both runners. Layout: 8-byte
/// fields first, then 4-byte, then 1-byte — identical to the Zig `extern struct
/// RecordArgsC` (size-guarded on both sides).
#[repr(C)]
pub struct RecordArgsC {
    pub output_path_ptr: *const u8, // NUL-terminated at [output_path_len]
    pub output_path_len: usize,
    pub workload_start: usize, // absolute argv index of the workload cmd; == argc if none
    pub focus_preset_ptr: *const u8, // preset name (Linux); null if none
    pub focus_preset_len: usize,
    pub sample_density: f64,
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
    pub has_focus: bool,
    pub has_sample_density: bool,
}

impl Default for RecordArgsC {
    fn default() -> Self {
        RecordArgsC {
            output_path_ptr: DEFAULT_OUTPUT.as_ptr(),
            output_path_len: DEFAULT_OUTPUT_LEN,
            workload_start: 0,
            focus_preset_ptr: std::ptr::null(),
            focus_preset_len: 0,
            sample_density: 0.0,
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
            has_focus: false,
            has_sample_density: false,
        }
    }
}

/// Leak a NUL-terminated copy of `s`, returning (ptr, len-excluding-NUL). The
/// record process is one-shot, so leaking the final args is bounded + fine.
fn leak_cstr(s: &str) -> (*const u8, usize) {
    let mut v = s.as_bytes().to_vec();
    let len = v.len();
    v.push(0);
    let boxed = v.into_boxed_slice();
    let ptr = boxed.as_ptr();
    std::mem::forget(boxed);
    (ptr, len)
}

// ---- The parser ------------------------------------------------------------

fn command() -> Command {
    Command::new("sismo record")
        .no_binary_name(true)
        .override_usage(
            "sismo record [--output <path>] [--duration <dur>] [--flight-recorder [--buffer <size>]]\n         \
             [--no-instrumentation] [--no-sched|--external-sched] [--no-cpu|--external-cpu]\n         \
             [--no-heap|--external-heap] [--all-external] [--focus <preset>] [--sample-density <x>]\n         \
             (--pid <pid> | <command> [args...])",
        )
        .arg(Arg::new("output").long("output").num_args(1))
        .arg(Arg::new("duration").long("duration").num_args(1).value_parser(clap_duration))
        .arg(Arg::new("flight-recorder").long("flight-recorder").action(ArgAction::SetTrue))
        .arg(Arg::new("buffer").long("buffer").num_args(1).value_parser(clap_buffer))
        .arg(Arg::new("no-instrumentation").long("no-instrumentation").action(ArgAction::SetTrue))
        .arg(
            Arg::new("pid")
                .long("pid")
                .num_args(1)
                .value_parser(clap::value_parser!(i32))
                .conflicts_with("command"),
        )
        .arg(Arg::new("no-sched").long("no-sched").action(ArgAction::SetTrue).conflicts_with("external-sched"))
        .arg(Arg::new("external-sched").long("external-sched").action(ArgAction::SetTrue))
        .arg(Arg::new("no-cpu").long("no-cpu").action(ArgAction::SetTrue).conflicts_with("external-cpu"))
        .arg(Arg::new("external-cpu").long("external-cpu").action(ArgAction::SetTrue))
        .arg(Arg::new("no-heap").long("no-heap").action(ArgAction::SetTrue).conflicts_with("external-heap"))
        .arg(Arg::new("external-heap").long("external-heap").action(ArgAction::SetTrue))
        .arg(Arg::new("all-external").long("all-external").action(ArgAction::SetTrue))
        .arg(Arg::new("focus").long("focus").num_args(1))
        .arg(Arg::new("sample-density").long("sample-density").num_args(1).value_parser(clap_density))
        // trailing_var_arg captures the workload + its own flags once the
        // command token is seen; a leading unknown `--flag` still errors (it's
        // not allow_hyphen_values, so it isn't silently taken as the command).
        .arg(Arg::new("command").num_args(0..).trailing_var_arg(true))
}

/// Parse `sismo record` args. `record_args` is argv[2..] (after exe + "record");
/// `all_argc` is the full argv length (so `workload_start` is absolute). Fills
/// `out`, returns true to proceed or false if help / an error was printed.
pub(crate) fn parse_record_args(record_args: &[&str], all_argc: usize, out: &mut RecordArgsC) -> bool {
    *out = RecordArgsC::default();
    out.workload_start = all_argc; // none unless a workload is found

    let m = match command().try_get_matches_from(record_args) {
        Ok(m) => m,
        Err(e) => {
            // --help prints to stdout (success kind); errors to stderr. Either
            // way this parse is done and the caller stops.
            let _ = e.print();
            return false;
        }
    };

    // Source-mode resolution. --no-X/--external-X conflicts are enforced by
    // clap; --all-external only promotes the still-in_process ones.
    let resolve = |no: &str, ext: &str| -> u8 {
        if m.get_flag(no) {
            MODE_OFF
        } else if m.get_flag(ext) {
            MODE_EXTERNAL
        } else {
            MODE_IN_PROCESS
        }
    };
    out.sched_mode = resolve("no-sched", "external-sched");
    out.cpu_mode = resolve("no-cpu", "external-cpu");
    out.heap_mode = resolve("no-heap", "external-heap");
    if m.get_flag("all-external") {
        for md in [&mut out.sched_mode, &mut out.cpu_mode, &mut out.heap_mode] {
            if *md == MODE_IN_PROCESS {
                *md = MODE_EXTERNAL;
            }
        }
    }

    out.flight_recorder = m.get_flag("flight-recorder");
    out.no_instrumentation = m.get_flag("no-instrumentation");
    if let Some(&kb) = m.get_one::<u32>("buffer") {
        out.buffer_kb = kb;
        out.buffer_set = true;
    }
    if let Some(&secs) = m.get_one::<u32>("duration") {
        out.duration_secs = secs;
        out.has_duration = true;
    }
    if let Some(p) = m.get_one::<String>("output") {
        let (ptr, len) = leak_cstr(p);
        out.output_path_ptr = ptr;
        out.output_path_len = len;
    }

    // --pid is a macOS-only capability (Linux would need a pidfd exit watcher).
    if let Some(&pid) = m.get_one::<i32>("pid") {
        if !cfg!(target_os = "macos") {
            eprintln!("sismo record: --pid attach is not supported on this platform");
            return false;
        }
        out.attach_pid = pid;
        out.has_attach_pid = true;
    }
    // --focus / --sample-density are Linux-only (BPF/PEBS path).
    if let Some(f) = m.get_one::<String>("focus") {
        if !cfg!(target_os = "linux") {
            eprintln!("sismo record: --focus needs the Linux BPF/PEBS path (not supported on this platform)");
            return false;
        }
        let (ptr, len) = leak_cstr(f);
        out.focus_preset_ptr = ptr;
        out.focus_preset_len = len;
        out.has_focus = true;
    }
    if let Some(&sd) = m.get_one::<f64>("sample-density") {
        out.sample_density = sd;
        out.has_sample_density = true;
    }

    // Workload = the trailing "command" values, which are the argv tail.
    let workload_len = m.get_many::<String>("command").map(|v| v.len()).unwrap_or(0);
    let have_cmd = workload_len > 0;
    if have_cmd {
        out.workload_start = all_argc - workload_len;
    }

    // Validation. (--pid vs command is enforced by clap conflicts_with.)
    if !out.has_attach_pid && !have_cmd {
        eprintln!("sismo record: need either --pid <pid> or a workload <command>");
        return false;
    }
    if out.has_sample_density && !out.has_focus {
        eprintln!("sismo record: --sample-density only applies with --focus");
        return false;
    }
    if out.flight_recorder && !out.buffer_set {
        out.buffer_kb = 256 * 1024;
    }
    true
}

/// C ABI: parse `argv[0..argc]` into `*out`. Used by the Zig Linux runner; the
/// Rust macOS runner calls `parse_record_args` directly.
///
/// # Safety
/// `argv` must point to `argc` valid NUL-terminated C strings; `out` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_parse_record_args(
    argc: usize,
    argv: *const *const std::os::raw::c_char,
    out: *mut RecordArgsC,
) -> bool {
    let all: Vec<&str> = (0..argc)
        .map(|i| unsafe { std::ffi::CStr::from_ptr(*argv.add(i)) }.to_str().unwrap_or(""))
        .collect();
    let args: &[&str] = if all.len() > 2 { &all[2..] } else { &[] };
    parse_record_args(args, all.len(), unsafe { &mut *out })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Parse argv[2..] with a total argc of `2 + args.len()` (no real exe/subcmd
    // tokens needed — clap has no_binary_name).
    fn parse(args: &[&str]) -> Option<RecordArgsC> {
        let mut out = RecordArgsC::default();
        if parse_record_args(args, 2 + args.len(), &mut out) {
            Some(out)
        } else {
            None
        }
    }

    #[test]
    fn defaults_with_just_a_command() {
        let a = parse(&["./app"]).unwrap();
        assert_eq!(a.workload_start, 2); // command is the last (only) arg → abs idx 2
        assert!(!a.has_attach_pid);
        assert_eq!(a.buffer_kb, DEFAULT_BUFFER_KB);
        assert_eq!(a.sched_mode, MODE_IN_PROCESS);
        assert_eq!(a.output_path_len, DEFAULT_OUTPUT_LEN);
        let s = unsafe { std::slice::from_raw_parts(a.output_path_ptr, a.output_path_len + 1) };
        assert_eq!(s, b"./sismo.pftrace\0"); // NUL-terminated for C use
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn pid_attach_and_modes() {
        let a = parse(&["--pid", "4242", "--no-heap", "--external-cpu"]).unwrap();
        assert!(a.has_attach_pid);
        assert_eq!(a.attach_pid, 4242);
        assert_eq!(a.heap_mode, MODE_OFF);
        assert_eq!(a.cpu_mode, MODE_EXTERNAL);
        assert_eq!(a.workload_start, 2 + 4); // no workload → all_argc
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn all_external_only_promotes_in_process() {
        let a = parse(&["--no-sched", "--all-external", "--pid", "1"]).unwrap();
        assert_eq!(a.sched_mode, MODE_OFF);
        assert_eq!(a.cpu_mode, MODE_EXTERNAL);
        assert_eq!(a.heap_mode, MODE_EXTERNAL);
    }

    #[test]
    fn double_dash_workload_is_the_argv_tail() {
        // `-- ./app --weird`: 3 tokens; workload = ["./app","--weird"] (the `--`
        // is consumed). all_argc = 2+3 = 5; workload_start = 5 - 2 = 3.
        let a = parse(&["--", "./app", "--weird"]).unwrap();
        assert_eq!(a.workload_start, 3);
        assert!(!a.has_attach_pid);
    }

    #[test]
    fn flight_recorder_bumps_buffer() {
        let a = parse(&["--flight-recorder", "sleep", "1"]).unwrap();
        assert_eq!(a.buffer_kb, 256 * 1024);
        let b = parse(&["--flight-recorder", "--buffer", "512MB", "sleep", "1"]).unwrap();
        assert_eq!(b.buffer_kb, 512 * 1024);
    }

    #[test]
    fn rejections() {
        assert!(parse(&[]).is_none()); // neither pid nor command
        assert!(parse(&["--no-cpu", "--external-cpu", "sleep"]).is_none()); // clap conflict
        assert!(parse(&["--buffer", "xx", "sleep"]).is_none());
        assert!(parse(&["--bogus", "sleep"]).is_none());
        assert!(parse(&["--output"]).is_none()); // missing value
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn macos_rejects_pid_with_command_and_focus() {
        assert!(parse(&["--pid", "1", "./app"]).is_none()); // clap conflicts_with
        assert!(parse(&["--focus", "cache", "./app"]).is_none()); // focus is Linux-only
    }

    #[test]
    fn output_override_leaks_a_cstring() {
        let a = parse(&["--output", "/tmp/x.pftrace", "sleep"]).unwrap();
        let s = unsafe { std::slice::from_raw_parts(a.output_path_ptr, a.output_path_len) };
        assert_eq!(s, b"/tmp/x.pftrace");
        // NUL terminator present for C use.
        assert_eq!(unsafe { *a.output_path_ptr.add(a.output_path_len) }, 0);
    }

    #[test]
    fn buffer_and_duration_value_parsers() {
        assert_eq!(parse_buffer_kb(b"256MB"), Some(256 * 1024));
        assert_eq!(parse_buffer_kb(b"256"), None);
        assert_eq!(parse_duration_seconds(b"5m"), Some(300));
        assert_eq!(parse_duration_seconds(b"5d"), None);
    }
}
