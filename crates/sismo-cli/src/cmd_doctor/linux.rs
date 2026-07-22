// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Linux setup checks: file capabilities on this binary, tracefs access (the
//! reboot-resets-it-to-root-only trap), perf paranoia, kernel vintage, and
//! debuginfod. `--fix` re-executes itself under sudo and applies the fixes:
//! the capability grant (a setcap-style `security.capability` xattr on this
//! binary — rebuilds shed it, so this recurs) and the tracefs chown (reboots
//! shed that one). It never touches sudoers; install a NOPASSWD rule for
//! `sismo doctor` yourself if you want the re-fixes passwordless.

use super::DoctorArgs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// cap_sys_resource (24), cap_perfmon (38), cap_bpf (39) as a 64-bit mask —
/// the caps the BPF collector needs to record unprivileged.
const CAP_MASK: u64 = (1 << 24) | (1 << 38) | (1 << 39);
const CAP_NAMES: &str = "cap_bpf,cap_perfmon,cap_sys_resource";

const TRACEFS_BASES: [&str; 2] = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];

/// Diagnose the things that make Linux recording fail or silently degrade.
/// Exit non-zero if a check that blocks recording fails.
pub fn run(args: DoctorArgs) -> i32 {
    println!("sismo doctor (Linux)");
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("sismo doctor: failed to resolve current executable: {e}");
            return 1;
        }
    };

    let caps_ok = check_caps(&exe);
    let tracefs_fix: Option<&str> = tracefs_needing_fix();
    if let Some(base) = tracefs_fix {
        println!("  ✗ tracefs: {base} is not writable by your user");
        println!("    sched + off-CPU tracking need it; record falls back to on-CPU only.");
        println!("    a reboot resets this — fix: sudo sismo doctor --fix");
    } else {
        println!("  ✓ tracefs: writable (sched + off-CPU available)");
    }
    check_perf_paranoid();
    check_kernel_version();
    check_debuginfod();

    let root = unsafe { libc::geteuid() } == 0;

    if args.fix {
        if caps_ok && tracefs_fix.is_none() {
            println!("  nothing to fix");
            return 0;
        }
        if !root {
            return escalate_fix(&exe, &args);
        }
        return apply_fixes(&exe, caps_ok, tracefs_fix);
    }

    if caps_ok && tracefs_fix.is_none() {
        0
    } else {
        1
    }
}

// ---- checks -----------------------------------------------------------------

/// Whether this binary's `security.capability` xattr grants the three caps
/// with the effective bit set (what `setcap …=ep` writes). Checked on the
/// file, not the process, so it stays meaningful under sudo.
fn check_caps(exe: &Path) -> bool {
    if read_file_caps(exe).is_some_and(|p| p & CAP_MASK == CAP_MASK) {
        println!("  ✓ capabilities: {} carries {CAP_NAMES}", exe.display());
        return true;
    }
    println!("  ✗ capabilities: {} does not carry {CAP_NAMES}", exe.display());
    println!("    recording needs them (or root). Rebuilds shed the grant.");
    println!("    fix: sudo sismo doctor --fix");
    false
}

/// Permitted-caps mask from the file's `security.capability` xattr, `None`
/// when absent/unparseable or the effective flag is unset. Handles the v2
/// (20-byte) and v3 (24-byte, adds a root-namespace id) layouts.
fn read_file_caps(path: &Path) -> Option<u64> {
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut buf = [0u8; 24];
    let n = unsafe {
        libc::getxattr(
            c.as_ptr(),
            c"security.capability".as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if n < 20 {
        return None;
    }
    let magic_etc = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if magic_etc & 0x0000_0001 == 0 {
        return None; // permitted but not effective — recording would still fail
    }
    let lo = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as u64;
    let hi = u32::from_le_bytes(buf[12..16].try_into().unwrap()) as u64;
    Some(lo | (hi << 32))
}

/// The mounted tracefs base the recording user cannot write, or `None` when
/// access is fine. Write access is the bar: Perfetto's ftrace controller
/// writes `tracing_on`/`set_event`, and read-only access makes it crash
/// mid-setup rather than fail cleanly. Ownership + mode bits (what the chown
/// grants) rather than an access() probe, so the answer is the same under
/// sudo — the user to check is `SUDO_UID` when root.
fn tracefs_needing_fix() -> Option<&'static str> {
    let uid = recording_uid();
    for base in TRACEFS_BASES {
        let probe = format!("{base}/tracing_on");
        let Ok(meta) = std::fs::metadata(&probe) else { continue };
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = meta.permissions().mode();
        let writable = (meta.uid() == uid && mode & 0o200 != 0) || mode & 0o002 != 0;
        return if writable { None } else { Some(base) };
    }
    None // not mounted — nothing a chown can do
}

/// The uid recording will run as: the invoking user under sudo, else us.
fn recording_uid() -> u32 {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return euid;
    }
    std::env::var("SUDO_UID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn check_perf_paranoid() {
    match std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid") {
        Ok(s) => {
            let v: i32 = s.trim().parse().unwrap_or(99);
            if v <= 1 {
                println!("  ✓ perf_event_paranoid = {v} (permissive)");
            } else {
                println!("  ! perf_event_paranoid = {v} (restrictive)");
                println!("    sismo bypasses this via cap_perfmon on the sismo binary; if you");
                println!("    record without caps, lower it: sudo sysctl kernel.perf_event_paranoid=1");
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

// ---- fixes ------------------------------------------------------------------

/// Unprivileged `--fix`: describe what will run as root, confirm, then replace
/// this process with `sudo <exe> doctor --fix -y`.
fn escalate_fix(exe: &Path, args: &DoctorArgs) -> i32 {
    println!();
    println!("--fix will re-run this command under sudo to:");
    println!("  - grant {CAP_NAMES} to {} (setcap-style xattr)", exe.display());
    println!("  - chown the tracefs mount to your user (re-applied after each reboot)");
    if !args.yes && !confirm("Continue? [y/N] ") {
        println!("    skipped");
        return 1;
    }
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new("sudo")
        .arg(exe)
        .args(["doctor", "--fix", "-y"])
        .exec();
    eprintln!("sismo doctor: failed to exec sudo: {err}");
    1
}

/// Root side of `--fix`: apply whatever the checks flagged, then re-verify.
fn apply_fixes(exe: &Path, caps_ok: bool, tracefs_fix: Option<&str>) -> i32 {
    let mut failed = false;

    if !caps_ok {
        match write_file_caps(exe) {
            Ok(()) => println!("  ✓ granted {CAP_NAMES} to {}", exe.display()),
            Err(e) => {
                eprintln!("  ✗ failed to grant capabilities: {e}");
                failed = true;
            }
        }
    }

    if let Some(base) = tracefs_fix {
        let uid = recording_uid();
        let ok = uid != 0
            && std::process::Command::new("chown")
                .args(["-R", &uid.to_string(), base])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
        if ok {
            println!("  ✓ chowned {base} to uid {uid} (until next reboot)");
        } else {
            eprintln!("  ✗ chown -R {uid} {base} failed");
            failed = true;
        }
    }

    if failed {
        1
    } else {
        0
    }
}

/// `setcap cap_bpf,cap_perfmon,cap_sys_resource=ep <path>` without depending
/// on libcap: write the VFS_CAP_REVISION_2 xattr directly.
fn write_file_caps(path: &Path) -> Result<(), String> {
    let bytes = caps_xattr_bytes();
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "path contains NUL".to_string())?;
    let rc = unsafe {
        libc::setxattr(
            c.as_ptr(),
            c"security.capability".as_ptr(),
            bytes.as_ptr() as *const libc::c_void,
            bytes.len(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    match read_file_caps(path) {
        Some(p) if p & CAP_MASK == CAP_MASK => Ok(()),
        _ => Err("xattr written but re-read did not show the caps".into()),
    }
}

/// The `security.capability` value for `=ep`: VFS_CAP_REVISION_2 with the
/// effective flag, permitted = CAP_MASK, inheritable = 0.
fn caps_xattr_bytes() -> [u8; 20] {
    let magic_etc: u32 = 0x0200_0000 | 0x0000_0001; // VFS_CAP_REVISION_2 | EFFECTIVE
    let lo = (CAP_MASK & 0xffff_ffff) as u32;
    let hi = (CAP_MASK >> 32) as u32;
    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&magic_etc.to_le_bytes());
    out[4..8].copy_from_slice(&lo.to_le_bytes()); // data[0].permitted
    out[12..16].copy_from_slice(&hi.to_le_bytes()); // data[1].permitted
    out
}

fn confirm(prompt: &str) -> bool {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim(), "y" | "Y" | "yes" | "YES")
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

    // VFS_CAP_REVISION_2 | EFFECTIVE, permitted lo = cap_sys_resource (bit 24),
    // permitted hi = cap_perfmon | cap_bpf (bits 6,7 of the second word).
    #[test]
    fn caps_xattr_layout() {
        assert_eq!(
            caps_xattr_bytes(),
            [
                0x01, 0x00, 0x00, 0x02, // magic_etc
                0x00, 0x00, 0x00, 0x01, // data[0].permitted
                0x00, 0x00, 0x00, 0x00, // data[0].inheritable
                0xC0, 0x00, 0x00, 0x00, // data[1].permitted
                0x00, 0x00, 0x00, 0x00, // data[1].inheritable
            ]
        );
    }

}
