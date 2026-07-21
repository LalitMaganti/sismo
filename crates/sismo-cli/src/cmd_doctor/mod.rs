// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! `sismo doctor` — diagnose local setup problems and optionally apply safe
//! fixes. The checks are per-platform (each OS gates recording differently);
//! this module holds the shared CLI surface and dispatches to the platform's
//! implementation.

use clap::Args;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

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

pub fn run(args: DoctorArgs) -> i32 {
    #[cfg(target_os = "macos")]
    {
        macos::run(args)
    }
    #[cfg(target_os = "linux")]
    {
        linux::run(args)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = args;
        println!("sismo doctor");
        println!("  ✓ no platform-specific setup checks implemented for this OS yet");
        0
    }
}
