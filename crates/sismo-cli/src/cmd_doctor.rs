// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `sismo doctor` — diagnose local setup problems and optionally apply safe
//! fixes. The first concrete use is macOS task access: like samply, we can
//! self-sign the current `sismo` binary with the debugger entitlement so
//! `task_for_pid` works for attach-style profiling without running the whole
//! recorder under sudo.

use clap::Args;
#[cfg(target_os = "macos")]
use sismo_core::sismo_paths::resolve_heap_dylib_path;
#[cfg(target_os = "macos")]
use std::io::Write;
#[cfg(target_os = "macos")]
use std::path::PathBuf;

#[derive(Args)]
pub struct DoctorArgs {
    /// Apply safe local fixes. On macOS this self-signs the current sismo binary
    /// with com.apple.security.cs.debugger if that entitlement is missing.
    #[arg(long)]
    fix: bool,

    /// Do not prompt before applying fixes. Only meaningful with --fix.
    #[arg(long, short = 'y')]
    yes: bool,
}

const DEBUGGER_ENTITLEMENT: &str = "com.apple.security.cs.debugger";

const ENTITLEMENTS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.cs.debugger</key>
	<true/>
</dict>
</plist>
"#;

pub fn run(args: DoctorArgs) -> i32 {
    #[cfg(target_os = "macos")]
    {
        run_macos(args)
    }
    #[cfg(target_os = "linux")]
    {
        run_linux(args)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        run_generic(args)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn run_generic(_args: DoctorArgs) -> i32 {
    println!("sismo doctor");
    println!("  ✓ no platform-specific setup checks implemented for this OS yet");
    0
}

// ---- Linux setup checks ----------------------------------------------------

/// Diagnose the things that make Linux recording fail or silently degrade: the
/// setcap'd launcher, tracefs access (the reboot-resets-it-to-root-only trap),
/// perf paranoia, kernel vintage, and debuginfod. Exit non-zero if a check that
/// blocks recording fails.
#[cfg(target_os = "linux")]
fn run_linux(_args: DoctorArgs) -> i32 {
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
#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
fn parse_kernel_major_minor(rel: &str) -> Option<(u32, u32)> {
    let mut it = rel.split(['.', '-']);
    let maj = it.next()?.parse().ok()?;
    let min = it.next()?.parse().ok()?;
    Some((maj, min))
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "macos")]
fn run_macos(args: DoctorArgs) -> i32 {
    let mut failed = false;
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("sismo doctor: failed to resolve current executable: {e}");
            return 1;
        }
    };

    println!("sismo doctor (macOS)");

    match has_debugger_entitlement(&exe) {
        Ok(true) => println!("  ✓ task access: {} is signed with {DEBUGGER_ENTITLEMENT}", exe.display()),
        Ok(false) => {
            println!("  ✗ task access: {} is missing {DEBUGGER_ENTITLEMENT}", exe.display());
            println!("    fix: sismo doctor --fix");
            failed = true;
            if args.fix {
                if args.yes || confirm_codesign(&exe) {
                    match codesign_with_debugger_entitlement(&exe) {
                        Ok(()) => {
                            println!("    ✓ self-signing succeeded");
                            failed = false;
                        }
                        Err(e) => {
                            eprintln!("    ✗ self-signing failed: {e}");
                            failed = true;
                        }
                    }
                } else {
                    println!("    skipped");
                }
            }
        }
        Err(e) => {
            println!("  ? task access: could not inspect codesign entitlements: {e}");
            println!("    fix: sismo doctor --fix");
            failed = true;
        }
    }

    match resolve_heap_dylib_path() {
        Some(path) if std::path::Path::new(&path).exists() => {
            println!("  ✓ heap preload: found {path}");
        }
        Some(path) => {
            println!("  ✗ heap preload: expected {path}, but it does not exist");
            println!("    fix: rebuild sismo so build.rs installs libsismo_heap.dylib");
            failed = true;
        }
        None => {
            println!("  ✗ heap preload: could not resolve libsismo_heap.dylib");
            failed = true;
        }
    }

    check_privileged_capture(&exe);

    if failed { 1 } else { 0 }
}

// ---- privileged capture (kdebug/kperf) --------------------------------------

/// Diagnose how sched + CPU-sample capture will get root. xnu gates kdebug and
/// kperf on euid 0 and Apple's kperf entitlement is private, so unlike Linux
/// (setcap on sismo-run) there is no capability to grant — every option is a
/// flavor of sudo. Advisory: name the options with exact commands rather than
/// fail, since `sudo sismo record` always works.
#[cfg(target_os = "macos")]
fn check_privileged_capture(exe: &PathBuf) {
    if unsafe { libc::geteuid() } == 0 {
        println!("  ✓ privileged capture: running as root — kdebug/kperf available");
        return;
    }
    if passwordless_sudo_covers(exe) {
        println!("  ✓ privileged capture: sudo runs {} without a password", exe.display());
        println!("    record with: sudo {} record …", exe.display());
        return;
    }

    println!("  ! privileged capture: kdebug/kperf (sched + CPU samples) need root");
    println!("    xnu gates them on euid 0 and Apple's kperf entitlement is private —");
    println!("    there is no macOS analog of Linux's setcap. Pick one:");
    println!("      per-run   sudo sismo record …");
    println!("                (sudo caches your password ~5 min per terminal)");
    println!("      session   sudo sismo datasource all-privileged   # separate terminal");
    println!("                sismo record --all-external …          # then, unprivileged");
    println!("      always    a sudoers rule for this binary — grants your account");
    println!("                passwordless root through a path you can overwrite, the");
    println!("                usual dev-machine trade for profiling tools:");
    match sudoers_suggestion(exe) {
        Ok(cmd) => {
            println!("                  {cmd}");
            println!("                revoke anytime: sudo rm {SUDOERS_FILE}");
        }
        Err(why) => println!("                  (cannot suggest a rule here: {why})"),
    }
}

#[cfg(target_os = "macos")]
const SUDOERS_FILE: &str = "/etc/sudoers.d/sismo";

/// Whether sudo will run `exe` as root without a password right now. `-k` first
/// discards cached credentials, so a fresh terminal is what's tested; `-n -l
/// <cmd>` then succeeds only if a NOPASSWD rule (ours or the user's own)
/// covers the command.
#[cfg(target_os = "macos")]
fn passwordless_sudo_covers(exe: &PathBuf) -> bool {
    std::process::Command::new("sudo")
        .args(["-k", "-n", "-l"])
        .arg(exe)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A copy-pasteable install command for the sudoers drop-in: writes the rule,
/// validates it with `visudo -c`, and removes it again if invalid, so a typo'd
/// path can never wedge sudo. Errors instead of escaping when the username or
/// paths carry sudoers metacharacters.
#[cfg(target_os = "macos")]
fn sudoers_suggestion(exe: &std::path::Path) -> Result<String, String> {
    let user = current_user().ok_or("could not resolve the current user")?;
    let paths = sudoers_paths(exe);
    if !sudoers_safe(&user) || !paths.iter().all(|p| sudoers_safe(p)) {
        return Err(format!(
            "user {user:?} or path contains sudoers metacharacters (e.g. spaces); \
             write {SUDOERS_FILE} by hand"
        ));
    }
    let rule = sudoers_rule(&user, &paths);
    Ok(format!(
        "sudo sh -c 'echo \"{rule}\" > {SUDOERS_FILE} && chmod 440 {SUDOERS_FILE} \
         && visudo -c -f {SUDOERS_FILE} || rm -f {SUDOERS_FILE}'"
    ))
}

/// The rule names this build's binary and its release/debug sibling — sudoers
/// matches by path, not inode, so rebuilds keep working without re-blessing
/// (the reason Linux needs the separate seldom-relinked sismo-run launcher
/// does not apply here).
#[cfg(target_os = "macos")]
fn sudoers_paths(exe: &std::path::Path) -> Vec<String> {
    let mut paths = vec![exe.display().to_string()];
    if let (Some(dir), Some(name)) = (exe.parent(), exe.file_name()) {
        if let Some(profile) = dir.file_name().and_then(|p| p.to_str()) {
            let sibling = match profile {
                "debug" => Some("release"),
                "release" => Some("debug"),
                _ => None,
            };
            if let Some(s) = sibling {
                paths.push(dir.with_file_name(s).join(name).display().to_string());
            }
        }
    }
    paths
}

/// Render the one-line sudoers rule. Pure so the syntax is unit-testable.
#[cfg(target_os = "macos")]
fn sudoers_rule(user: &str, paths: &[String]) -> String {
    format!("{user} ALL=(root) NOPASSWD: {}", paths.join(", "))
}

/// sudoers treats spaces/commas/backslashes/#/:/= specially; a path or user
/// carrying one would change the rule's meaning (and the suggestion embeds the
/// rule in a double-quoted shell string, so quotes are out too). Refuse rather
/// than escape.
#[cfg(target_os = "macos")]
fn sudoers_safe(s: &str) -> bool {
    !s.is_empty() && !s.contains([' ', '\t', ',', '\\', '#', ':', '=', '"', '\'', '\n'])
}

#[cfg(target_os = "macos")]
fn current_user() -> Option<String> {
    // getpwuid over $USER: correct even under su/sudo-altered environments.
    let uid = unsafe { libc::getuid() };
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return std::env::var("USER").ok();
    }
    let name = unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) };
    name.to_str().ok().map(str::to_owned)
}

#[cfg(target_os = "macos")]
fn has_debugger_entitlement(exe: &PathBuf) -> Result<bool, String> {
    let output = std::process::Command::new("codesign")
        .args(["-d", "--entitlements", ":-"])
        .arg(exe)
        .output()
        .map_err(|e| format!("failed to run codesign: {e}"))?;

    // `codesign -d` writes diagnostics and entitlements to stderr on macOS.
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(&output.stdout));
    text.push_str(&String::from_utf8_lossy(&output.stderr));

    if !output.status.success() && text.trim().is_empty() {
        return Err(format!("codesign exited with {}", output.status));
    }
    Ok(text.contains(DEBUGGER_ENTITLEMENT))
}

#[cfg(target_os = "macos")]
fn confirm_codesign(exe: &PathBuf) -> bool {
    print!(
        r#"
This will self-sign the current sismo binary for this machine only, using the
same approach as `samply setup`:

    codesign --force --options runtime --sign - \
      --entitlements entitlements.xml {}

entitlements.xml contains:

{}

Continue? [y/N] "#,
        exe.display(),
        ENTITLEMENTS_XML
    );
    let _ = std::io::stdout().flush();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim(), "y" | "Y" | "yes" | "YES")
}

#[cfg(target_os = "macos")]
fn codesign_with_debugger_entitlement(exe: &PathBuf) -> Result<(), String> {
    let entitlements_path = std::env::temp_dir().join(format!(
        "sismo_entitlements_{}_{}.xml",
        std::process::id(),
        chrono_like_timestamp()
    ));
    std::fs::write(&entitlements_path, ENTITLEMENTS_XML)
        .map_err(|e| format!("write {}: {e}", entitlements_path.display()))?;

    let output = std::process::Command::new("codesign")
        .arg("--force")
        .arg("--options")
        .arg("runtime")
        .arg("--sign")
        .arg("-")
        .arg("--entitlements")
        .arg(&entitlements_path)
        .arg(exe)
        .output()
        .map_err(|e| format!("failed to run codesign: {e}"));

    let _ = std::fs::remove_file(&entitlements_path);
    let output = output?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "codesign exited with {}\n{}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

#[cfg(target_os = "macos")]
fn chrono_like_timestamp() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[cfg(all(test, target_os = "macos"))]
mod mac_tests {
    use super::*;

    #[test]
    fn sudoers_rule_covers_both_profiles() {
        let paths = sudoers_paths(std::path::Path::new("/r/crates/sismo/target/debug/sismo"));
        assert_eq!(
            paths,
            vec![
                "/r/crates/sismo/target/debug/sismo".to_string(),
                "/r/crates/sismo/target/release/sismo".to_string(),
            ]
        );
        assert_eq!(
            sudoers_rule("lalit", &paths),
            "lalit ALL=(root) NOPASSWD: /r/crates/sismo/target/debug/sismo, \
             /r/crates/sismo/target/release/sismo"
        );
    }

    #[test]
    fn sudoers_rejects_metacharacters() {
        assert!(sudoers_safe("/ok/path/sismo"));
        assert!(sudoers_safe("lalit"));
        for bad in ["/has space/x", "a,b", "a#b", "a\\b", "a=b", "a\"b", ""] {
            assert!(!sudoers_safe(bad), "{bad:?} should be rejected");
        }
    }

    // A non-cargo layout (no debug/release parent) still yields a valid
    // single-path rule rather than inventing a bogus sibling.
    #[test]
    fn sudoers_paths_without_profile_dir() {
        let paths = sudoers_paths(std::path::Path::new("/usr/local/bin/sismo"));
        assert_eq!(paths, vec!["/usr/local/bin/sismo".to_string()]);
    }
}

#[cfg(all(test, target_os = "linux"))]
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
