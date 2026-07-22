// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `sismo record` argument parsing (all platforms), on clap derive.
//!
//! One flag set everywhere — platform differences are a small post-parse
//! capability check (`--pid` is macOS-only, `--focus` / `--sample-density` are
//! Linux-only), NOT a separate per-OS parser. [`RecordArgs`] is the raw clap
//! struct (a subcommand payload); [`RecordArgs::resolve`] validates it and
//! produces the native [`RecordConfig`] both runners consume.

use clap::Args;
use sismo_core::cpu::module_registry::KeepPolicy;

// ---- Scalar value parsers --------------------------------------------------

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
fn clap_keep_policy(s: &str) -> Result<KeepPolicy, String> {
    KeepPolicy::parse(s)
        .ok_or_else(|| format!("--keep-module-files must be all, auto, or none, got '{s}'"))
}
fn clap_density(s: &str) -> Result<f64, String> {
    let v: f64 = s.parse().map_err(|_| format!("--sample-density must be a positive number, got '{s}'"))?;
    if v > 0.0 {
        Ok(v)
    } else {
        Err(format!("--sample-density must be a positive number, got '{s}'"))
    }
}

/// Default rolling ring buffer for the dump-on-exit mode (the default).
const RING_BUFFER_KB: u32 = 256 * 1024;
/// In-flight buffer for `--long-trace` streaming to disk (flushed continuously,
/// so it need not hold the whole trace).
const STREAM_BUFFER_KB: u32 = 128 * 1024;

// ---- Parsed + resolved args ------------------------------------------------

/// How a data source is captured: in this process, in an external `sismo
/// datasource` producer, or not at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceMode {
    InProcess,
    External,
    Off,
}

/// Raw `sismo record` flags as clap parses them. Resolve into a [`RecordConfig`]
/// before use — that folds the `--no-*`/`--external-*`/`--all-external` flags
/// into per-source modes and enforces the cross-flag rules.
#[derive(Args, Debug)]
#[command(override_usage = "\
sismo record [--output <path>] [--duration <dur>] [--long-trace] [--buffer <size>]\n         \
[--no-instrumentation] [--no-sched|--external-sched] [--no-cpu|--external-cpu]\n         \
[--no-heap|--external-heap] [--all-external] [--focus <preset>] [--sample-density <x>]\n         \
(--pid <pid> | <command> [args...])")]
pub struct RecordArgs {
    #[arg(long)]
    output: Option<String>,
    #[arg(long, value_parser = clap_duration)]
    duration: Option<u32>,
    #[arg(long)]
    long_trace: bool,
    #[arg(long, value_parser = clap_buffer)]
    buffer: Option<u32>,
    #[arg(long)]
    no_instrumentation: bool,
    /// Skip the post-record symbolization pass, leaving the trace's native
    /// frames as `{build-id, file-offset}` for a later offline pass. Cuts the
    /// recorder's stop-time CPU/memory; the profile is symbolized elsewhere.
    #[arg(long)]
    no_symbolize: bool,
    #[arg(long, conflicts_with = "command")]
    pid: Option<i32>,
    #[arg(long, conflicts_with = "external_sched")]
    no_sched: bool,
    #[arg(long)]
    external_sched: bool,
    #[arg(long, conflicts_with = "external_cpu")]
    no_cpu: bool,
    #[arg(long)]
    external_cpu: bool,
    #[arg(long, conflicts_with = "external_heap")]
    no_heap: bool,
    #[arg(long)]
    external_heap: bool,
    /// Skip off-CPU (blocking-stack) capture, sampling on-CPU only.
    #[arg(long)]
    no_offcpu: bool,
    #[arg(long)]
    all_external: bool,
    /// Capture only these sources (comma list of cpu,sched,heap,instrumentation),
    /// turning every other source off. `--only cpu` is the CPU-sampling-only
    /// recording — the apples-to-apples config to compare against `perf record`.
    /// Overrides the per-source --no-*/--external-* flags.
    #[arg(long)]
    only: Option<String>,
    /// Deepen one analysis (default is the lightweight vitals profile: stacks +
    /// cycles/instructions). Presets: `cpu` (microarchitecture counter set —
    /// why the core stalls), `cpu.cache_miss` (precise cache-miss data
    /// addresses — where accesses stall), `memory.dump` (heap dump; macOS).
    #[arg(long)]
    focus: Option<String>,
    #[arg(long, value_parser = clap_density)]
    sample_density: Option<f64>,
    /// Which sampled module files to hold open so a binary deleted or rebuilt
    /// mid-recording still symbolizes: `auto` (default) holds fds only for files
    /// on unstable paths (home/tmp/build dirs) and reopens system files by path;
    /// `all` holds every module; `none` holds nothing (open by path at the end).
    #[arg(long, value_parser = clap_keep_policy, default_value = "auto")]
    keep_module_files: KeepPolicy,
    // The workload + its own flags: everything after the first positional token.
    // Not allow_hyphen_values, so a *leading* unknown `--flag` still errors.
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

/// Fully-resolved `sismo record` config, consumed by both runners.
pub struct RecordConfig {
    /// Explicit `--output`, or None to default to a timestamped path at record time.
    pub output: Option<String>,
    /// The workload command + args; empty when attaching via `--pid`.
    pub workload: Vec<String>,
    pub attach_pid: Option<i32>,
    pub duration_secs: Option<u32>,
    /// Stream continuously to disk (unbounded) instead of the default rolling
    /// ring buffer dumped on exit.
    pub long_trace: bool,
    pub buffer_kb: u32,
    pub sched_mode: SourceMode,
    pub cpu_mode: SourceMode,
    pub heap_mode: SourceMode,
    pub no_instrumentation: bool,
    /// Capture off-CPU (blocking-stack) samples alongside on-CPU sampling.
    pub capture_offcpu: bool,
    /// Skip the post-record symbolization pass (leave native frames unresolved).
    pub no_symbolize: bool,
    pub focus: Option<String>,
    pub sample_density: Option<f64>,
    /// CAP-3(b): which sampled module files to hold open for symbolization.
    pub keep_module_files: KeepPolicy,
}

impl RecordArgs {
    /// Validate + fold into a [`RecordConfig`]. On a violated rule it prints the
    /// message and returns `Err(exit_code)` (the caller returns it).
    pub fn resolve(self) -> Result<RecordConfig, i32> {
        let mode = |off: bool, ext: bool| {
            if off {
                SourceMode::Off
            } else if ext {
                SourceMode::External
            } else {
                SourceMode::InProcess
            }
        };
        let mut sched = mode(self.no_sched, self.external_sched);
        let mut cpu = mode(self.no_cpu, self.external_cpu);
        let mut heap = mode(self.no_heap, self.external_heap);
        if self.all_external {
            for m in [&mut sched, &mut cpu, &mut heap] {
                if *m == SourceMode::InProcess {
                    *m = SourceMode::External;
                }
            }
        }

        // --only <sources>: keep exactly the listed sources, everything else off
        // — the CPU-only config that matches `perf record`. Takes precedence over
        // the granular flags above.
        let mut no_instr = self.no_instrumentation;
        let mut capture_offcpu = !self.no_offcpu;
        if let Some(only) = self.only.as_deref() {
            let mut keep: std::collections::HashSet<&str> = std::collections::HashSet::new();
            for s in only.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                if !matches!(s, "cpu" | "offcpu" | "sched" | "heap" | "instrumentation") {
                    eprintln!("sismo record: --only: unknown source {s:?} (want cpu, offcpu, sched, heap, instrumentation)");
                    return Err(0);
                }
                keep.insert(s);
            }
            if keep.is_empty() {
                eprintln!("sismo record: --only needs at least one source");
                return Err(0);
            }
            let on = |name| if keep.contains(name) { SourceMode::InProcess } else { SourceMode::Off };
            sched = on("sched");
            cpu = on("cpu");
            heap = on("heap");
            no_instr = !keep.contains("instrumentation");
            capture_offcpu = keep.contains("offcpu");
        }

        // --pid is a macOS-only capability (Linux would need a pidfd exit watcher).
        if self.pid.is_some() && !cfg!(target_os = "macos") {
            eprintln!("sismo record: --pid attach is not supported on this platform");
            return Err(0);
        }
        // --focus preset availability is per-OS: the PEBS presets need the
        // Linux BPF path; `memory.dump` (single heap dump at stop/snapshot)
        // works everywhere. Linux validates its own presets in the runner.
        if self.focus.is_some() && !cfg!(target_os = "linux") && self.focus.as_deref() != Some("memory.dump") {
            eprintln!(
                "sismo record: unsupported focus preset '{}' on this platform (supported here: memory.dump)",
                self.focus.as_deref().unwrap_or_default()
            );
            return Err(0);
        }

        let have_cmd = !self.command.is_empty();
        if self.pid.is_none() && !have_cmd {
            eprintln!("sismo record: need either --pid <pid> or a workload <command>");
            return Err(0);
        }
        if self.sample_density.is_some() && self.focus.is_none() {
            eprintln!("sismo record: --sample-density only applies with --focus");
            return Err(0);
        }

        let buffer_kb = match self.buffer {
            Some(kb) => kb,
            None if self.long_trace => STREAM_BUFFER_KB,
            None => RING_BUFFER_KB,
        };

        Ok(RecordConfig {
            output: self.output,
            workload: self.command,
            attach_pid: self.pid,
            duration_secs: self.duration,
            long_trace: self.long_trace,
            buffer_kb,
            sched_mode: sched,
            cpu_mode: cpu,
            heap_mode: heap,
            no_instrumentation: no_instr,
            capture_offcpu,
            no_symbolize: self.no_symbolize,
            focus: self.focus,
            sample_density: self.sample_density,
            keep_module_files: self.keep_module_files,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    // A tiny Parser wrapper so tests can parse a bare RecordArgs flag list.
    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        r: RecordArgs,
    }

    fn parse(args: &[&str]) -> Option<RecordConfig> {
        let argv = std::iter::once("record").chain(args.iter().copied());
        let cli = TestCli::try_parse_from(argv).ok()?;
        cli.r.resolve().ok()
    }

    #[test]
    fn defaults_with_just_a_command() {
        let a = parse(&["./app"]).unwrap();
        assert_eq!(a.workload, vec!["./app"]);
        assert!(a.attach_pid.is_none());
        assert_eq!(a.buffer_kb, RING_BUFFER_KB);
        assert_eq!(a.sched_mode, SourceMode::InProcess);
        assert_eq!(a.output, None);
        assert!(!a.long_trace);
        assert!(!a.no_symbolize);
    }

    #[test]
    fn no_symbolize_flag() {
        assert!(parse(&["--no-symbolize", "./app"]).unwrap().no_symbolize);
    }

    #[test]
    fn only_cpu_turns_the_rest_off() {
        let a = parse(&["--only", "cpu", "./app"]).unwrap();
        assert_eq!(a.cpu_mode, SourceMode::InProcess);
        assert_eq!(a.sched_mode, SourceMode::Off);
        assert_eq!(a.heap_mode, SourceMode::Off);
        assert!(a.no_instrumentation);
        assert!(!a.capture_offcpu); // on-CPU only, no blocking stacks
        // off-CPU is on by default, and opt-in-able alongside cpu.
        assert!(parse(&["./app"]).unwrap().capture_offcpu);
        assert!(parse(&["--only", "cpu,offcpu", "./app"]).unwrap().capture_offcpu);
        assert!(!parse(&["--no-offcpu", "./app"]).unwrap().capture_offcpu);
    }

    #[test]
    fn only_multi_source_and_bad_source() {
        let a = parse(&["--only", "cpu,sched", "./app"]).unwrap();
        assert_eq!(a.cpu_mode, SourceMode::InProcess);
        assert_eq!(a.sched_mode, SourceMode::InProcess);
        assert_eq!(a.heap_mode, SourceMode::Off);
        assert!(parse(&["--only", "bogus", "./app"]).is_none());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn pid_attach_and_modes() {
        let a = parse(&["--pid", "4242", "--no-heap", "--external-cpu"]).unwrap();
        assert_eq!(a.attach_pid, Some(4242));
        assert_eq!(a.heap_mode, SourceMode::Off);
        assert_eq!(a.cpu_mode, SourceMode::External);
        assert!(a.workload.is_empty());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn all_external_only_promotes_in_process() {
        let a = parse(&["--no-sched", "--all-external", "--pid", "1"]).unwrap();
        assert_eq!(a.sched_mode, SourceMode::Off);
        assert_eq!(a.cpu_mode, SourceMode::External);
        assert_eq!(a.heap_mode, SourceMode::External);
    }

    #[test]
    fn double_dash_workload_is_the_argv_tail() {
        let a = parse(&["--", "./app", "--weird"]).unwrap();
        assert_eq!(a.workload, vec!["./app", "--weird"]);
        assert!(a.attach_pid.is_none());
    }

    #[test]
    fn long_trace_uses_stream_buffer_default_uses_ring() {
        let a = parse(&["--long-trace", "sleep", "1"]).unwrap();
        assert_eq!(a.buffer_kb, STREAM_BUFFER_KB);
        assert!(a.long_trace);
        // Default (no --long-trace) uses the larger rolling ring buffer.
        let b = parse(&["sleep", "1"]).unwrap();
        assert_eq!(b.buffer_kb, RING_BUFFER_KB);
        assert!(!b.long_trace);
        // --buffer overrides either mode.
        let c = parse(&["--long-trace", "--buffer", "512MB", "sleep", "1"]).unwrap();
        assert_eq!(c.buffer_kb, 512 * 1024);
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
    fn output_override() {
        let a = parse(&["--output", "/tmp/x.pftrace", "sleep"]).unwrap();
        assert_eq!(a.output.as_deref(), Some("/tmp/x.pftrace"));
    }

    #[test]
    fn buffer_and_duration_value_parsers() {
        assert_eq!(parse_buffer_kb(b"256MB"), Some(256 * 1024));
        assert_eq!(parse_buffer_kb(b"256"), None);
        assert_eq!(parse_duration_seconds(b"5m"), Some(300));
        assert_eq!(parse_duration_seconds(b"5d"), None);
    }
}
