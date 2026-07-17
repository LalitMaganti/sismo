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
    #[cfg(not(target_os = "macos"))]
    {
        run_generic(args)
    }
}

#[cfg(not(target_os = "macos"))]
fn run_generic(_args: DoctorArgs) -> i32 {
    println!("sismo doctor");
    println!("  ✓ no platform-specific setup checks implemented for this OS yet");
    0
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

    println!("  ! scheduler tracing: macOS kdebug still requires root or an external privileged datasource");
    println!("    workaround: sudo sismo datasource sched + sismo record --external-sched ...");

    if failed { 1 } else { 0 }
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
