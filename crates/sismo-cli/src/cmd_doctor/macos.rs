// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! macOS setup checks. Task access works like samply: self-sign the current
//! `sismo` binary with the debugger entitlement so `task_for_pid` works for
//! attach-style profiling without running the whole recorder under sudo.
//! Privileged capture (kdebug/kperf) has no capability to grant — every
//! option is a flavor of sudo, and the check names them with exact commands.

use super::DoctorArgs;
use sismo_core::sismo_paths::resolve_heap_dylib_path;
use std::io::Write;
use std::path::PathBuf;

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

const SUDOERS_FILE: &str = "/etc/sudoers.d/sismo";

/// Whether sudo will run `exe` as root without a password right now. `-k` first
/// discards cached credentials, so a fresh terminal is what's tested; `-n -l
/// <cmd>` then succeeds only if a NOPASSWD rule (ours or the user's own)
/// covers the command.
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
fn sudoers_rule(user: &str, paths: &[String]) -> String {
    format!("{user} ALL=(root) NOPASSWD: {}", paths.join(", "))
}

/// sudoers treats spaces/commas/backslashes/#/:/= specially; a path or user
/// carrying one would change the rule's meaning (and the suggestion embeds the
/// rule in a double-quoted shell string, so quotes are out too). Refuse rather
/// than escape.
fn sudoers_safe(s: &str) -> bool {
    !s.is_empty() && !s.contains([' ', '\t', ',', '\\', '#', ':', '=', '"', '\'', '\n'])
}

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

fn chrono_like_timestamp() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
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
