// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Linux setup checks: the setcap'd launcher, tracefs access (the
//! reboot-resets-it-to-root-only trap), perf paranoia, kernel vintage, and
//! debuginfod.

use super::DoctorArgs;

/// Diagnose the things that make Linux recording fail or silently degrade.
/// Exit non-zero if a check that blocks recording fails.
pub fn run(_args: DoctorArgs) -> i32 {
    println!("sismo doctor (Linux)");
    // Only capability and tracefs access actually block recording; the rest are
    // advisory (they change symbolization quality or explain a slow start).
    let mut blocked = false;
    blocked |= !check_sismo_run_caps();
    blocked |= !check_tracefs();
    check_perf_paranoid();
    check_kernel_version();
    check_debuginfod();
    if blocked {
        1
    } else {
        0
    }
}

/// The setcap'd `sismo-run` launcher relative to this `sismo` binary: it lives
/// at `<root>/crates/sismo-run/target/<profile>/sismo-run`, a sibling of
/// `<root>/crates/sismo/target/<profile>/sismo`.
fn sismo_run_path() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let profile = exe.parent()?.file_name()?.to_owned(); // debug | release
    let crates = exe.parent()?.parent()?.parent()?.parent()?; // <root>/crates
    let p = crates
        .join("sismo-run")
        .join("target")
        .join(&profile)
        .join("sismo-run");
    p.exists().then_some(p)
}

fn check_sismo_run_caps() -> bool {
    const NEEDED: [&str; 3] = ["cap_bpf", "cap_perfmon", "cap_sys_resource"];
    let path = match sismo_run_path() {
        Some(p) => p,
        None => {
            println!("  ! sismo-run: not found next to this binary");
            println!("    recording needs the setcap'd launcher (or root). If it is installed");
            println!("    elsewhere, ensure it carries cap_bpf,cap_perfmon,cap_sys_resource.");
            return true; // an install/root workflow may be fine — don't hard-fail
        }
    };
    match std::process::Command::new("getcap").arg(&path).output() {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            if NEEDED.iter().all(|c| text.contains(c)) {
                println!("  ✓ sismo-run: {} has {}", path.display(), NEEDED.join(","));
                true
            } else {
                println!("  ✗ sismo-run: {} is missing required capabilities", path.display());
                println!(
                    "    fix: sudo setcap {}=eip {}",
                    NEEDED.join(","),
                    path.display()
                );
                false
            }
        }
        _ => {
            println!("  ? sismo-run: found {}, but `getcap` is unavailable to verify caps", path.display());
            println!("    ensure it carries {} (setcap …=eip)", NEEDED.join(","));
            true
        }
    }
}

/// sismo's off-CPU futex tracking and the ftrace data source read tracepoint
/// ids from tracefs. A reboot resets `/sys/kernel/tracing` to root-only (0700);
/// without access, recording hangs ~20s on the ftrace source and loses off-CPU.
fn check_tracefs() -> bool {
    for base in ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"] {
        if !std::path::Path::new(base).exists() {
            continue;
        }
        let probe = format!("{base}/events/syscalls/sys_enter_futex/id");
        match std::fs::File::open(&probe) {
            Ok(_) => {
                println!("  ✓ tracefs: {base} is readable (off-CPU + ftrace available)");
                return true;
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                println!("  ✗ tracefs: {base} is not readable by this user");
                println!("    off-CPU/futex tracking and ftrace will hang ~20s, then record on-CPU only.");
                println!("    fix: sudo chmod -R o+rX {base}");
                return false;
            }
            Err(_) => continue, // e.g. the probe tracepoint is absent; try next base
        }
    }
    println!("  ? tracefs: not mounted at /sys/kernel/tracing (off-CPU tracing unavailable)");
    true
}

fn check_perf_paranoid() {
    match std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid") {
        Ok(s) => {
            let v: i32 = s.trim().parse().unwrap_or(99);
            if v <= 1 {
                println!("  ✓ perf_event_paranoid = {v} (permissive)");
            } else {
                println!("  ! perf_event_paranoid = {v} (restrictive)");
                println!("    sismo bypasses this via cap_perfmon on sismo-run; if you record");
                println!("    without caps, lower it: sudo sysctl kernel.perf_event_paranoid=1");
            }
        }
        Err(_) => println!("  ? perf_event_paranoid: could not read /proc/sys/kernel/perf_event_paranoid"),
    }
}

fn check_kernel_version() {
    let rel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_owned());
    match rel {
        Some(rel) => match parse_kernel_major_minor(&rel) {
            Some((maj, min)) if (maj, min) >= (5, 8) => {
                println!("  ✓ kernel {rel} (cap_bpf + BPF stack walking supported)");
            }
            Some((maj, min)) => {
                println!("  ! kernel {rel} ({maj}.{min} < 5.8)");
                println!("    cap_bpf and some BPF features need 5.8+; recording may require root.");
            }
            None => println!("  ✓ kernel {rel}"),
        },
        None => println!("  ? kernel version: could not read /proc/sys/kernel/osrelease"),
    }
}

/// Parse `major.minor` from a `uname -r` string like `6.0.14-201.fc44.x86_64`.
fn parse_kernel_major_minor(rel: &str) -> Option<(u32, u32)> {
    let mut it = rel.split(['.', '-']);
    let maj = it.next()?.parse().ok()?;
    let min = it.next()?.parse().ok()?;
    Some((maj, min))
}

fn check_debuginfod() {
    match std::env::var_os("DEBUGINFOD_URLS") {
        Some(v) if !v.is_empty() => {
            println!("  ✓ DEBUGINFOD_URLS set — stripped distro libraries can fetch debug info");
        }
        _ => {
            println!("  ! DEBUGINFOD_URLS not set");
            println!("    stripped system libraries won't symbolize; to enable, e.g.:");
            println!("    export DEBUGINFOD_URLS=https://debuginfod.fedoraproject.org/");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kernel_major_minor() {
        assert_eq!(parse_kernel_major_minor("6.0.14-201.fc44.x86_64"), Some((6, 0)));
        assert_eq!(parse_kernel_major_minor("5.15.0-generic"), Some((5, 15)));
        assert_eq!(parse_kernel_major_minor("7.0.14"), Some((7, 0)));
        assert_eq!(parse_kernel_major_minor("garbage"), None);
        // (5,8) is the cap_bpf floor the check compares against.
        assert!((6, 0) >= (5, 8));
        assert!((5, 4) < (5, 8));
    }
}
