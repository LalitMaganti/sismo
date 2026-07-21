// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `sismo datasource <id> [<id>...]` — daemonized producer hosting one or more
//! sismo data sources in this single process.
//!
//! Connects to PERFETTO_PRODUCER_SOCK_NAME (set by whoever hosts traced —
//! typically `sismo record` in privsep mode), registers each requested data
//! source, and blocks until killed (SIGINT / SIGTERM).
//!
//! Identifiers are platform-independent — sismo maps them to the actual
//! `sismo.*` name for the running OS. `all-privileged` expands per-platform
//! (macOS: sched + cpu + heap). Bundling many in one invocation shares the sudo
//! prompt. Config (target_pid etc.) arrives via on_setup when a session enables
//! a DS — the producer CLI takes no tracing-config flags.
//!
//! This module holds the platform-neutral CLI surface (identifier parsing and
//! expansion); the run loop that drives the capture workers is per-platform
//! ([`macos`] today — the Linux producers aren't wired in this binary yet).

#[cfg(target_os = "macos")]
mod macos;

/// Platform-independent data-source identifier.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Sched,
    Cpu,
    Heap,
}

const USAGE: &str = "usage: sismo datasource <id> [<id>...]\n\n  \
     <id>: sched | cpu | heap | all-privileged\n\n  \
     Connects to PERFETTO_PRODUCER_SOCK_NAME, registers the requested\n  \
     data source(s) in this single process, blocks until SIGINT/SIGTERM.\n  \
     Multiple ids in one invocation share the sudo prompt.\n\n  \
     Identifiers are platform-independent — sismo picks the right\n  \
     `sismo.*` data source name for the running OS internally.\n";

fn parse_kind(name: &str) -> Option<Kind> {
    match name {
        "sched" => Some(Kind::Sched),
        "cpu" => Some(Kind::Cpu),
        "heap" => Some(Kind::Heap),
        _ => None,
    }
}

/// Per-platform expansion of `all-privileged`. macOS: all three need elevation.
fn all_privileged() -> &'static [Kind] {
    #[cfg(target_os = "macos")]
    {
        &[Kind::Sched, Kind::Cpu, Kind::Heap]
    }
    #[cfg(not(target_os = "macos"))]
    {
        &[] // No Linux/Windows producers wired in this binary yet.
    }
}

/// Parse args (everything after "datasource") into a deduped kind list, or
/// `Err(true)` if usage was already printed (help / unknown / empty).
fn collect_kinds(rest: &[&str]) -> Result<Vec<Kind>, ()> {
    let mut kinds: Vec<Kind> = Vec::new();
    let push = |k: Kind, kinds: &mut Vec<Kind>| {
        if !kinds.contains(&k) {
            kinds.push(k);
        }
    };
    for &arg in rest {
        if arg == "all-privileged" {
            for &k in all_privileged() {
                push(k, &mut kinds);
            }
            continue;
        }
        match parse_kind(arg) {
            Some(k) => push(k, &mut kinds),
            None => {
                eprint!("sismo datasource: unknown identifier '{arg}'\n\n{USAGE}");
                return Err(());
            }
        }
    }
    if kinds.is_empty() {
        eprint!("{USAGE}");
        return Err(());
    }
    Ok(kinds)
}

// ---- Entry point -----------------------------------------------------------

#[derive(clap::Args)]
pub struct DatasourceArgs {
    /// One or more of: sched, cpu, heap, all-privileged.
    #[arg(required = true)]
    names: Vec<String>,
}

/// `sismo datasource` subcommand.
pub fn run(args: DatasourceArgs) -> i32 {
    let rest: Vec<&str> = args.names.iter().map(String::as_str).collect();

    let kinds = match collect_kinds(&rest) {
        Ok(k) => k,
        Err(()) => return 0, // usage already printed
    };

    #[cfg(target_os = "macos")]
    {
        macos::run(&kinds)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = kinds;
        eprintln!("sismo datasource: not yet implemented on this platform");
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kind_maps_ids() {
        assert!(matches!(parse_kind("sched"), Some(Kind::Sched)));
        assert!(matches!(parse_kind("cpu"), Some(Kind::Cpu)));
        assert!(matches!(parse_kind("heap"), Some(Kind::Heap)));
        assert!(parse_kind("bogus").is_none());
    }

    #[test]
    fn collect_dedups_and_rejects() {
        let k = collect_kinds(&["cpu", "cpu", "sched"]).unwrap();
        assert_eq!(k.len(), 2); // cpu deduped
        assert!(collect_kinds(&["bogus"]).is_err());
        assert!(collect_kinds(&[]).is_err()); // empty prints usage
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn all_privileged_expands_to_three_on_macos() {
        let k = collect_kinds(&["all-privileged"]).unwrap();
        assert_eq!(k.len(), 3);
    }
}
