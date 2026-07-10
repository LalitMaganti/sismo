// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! sismo-run: a capability-stable launcher for the BPF collector.
//!
//! `sismo` needs CAP_BPF/CAP_PERFMON/CAP_SYS_RESOURCE to load its BPF program
//! (the thread_ctrs task-storage map fails -EINVAL without CAP_BPF). File caps
//! attach to an inode and `sismo` relinks on every change, so caps granted with
//! `setcap` evaporate on the next build.
//!
//! This launcher breaks that cycle: setcap the caps onto THIS binary once (it's
//! dependency-free, so it relinks only when this file changes, ~never). At
//! startup it raises the three caps into the *ambient* set — ambient caps
//! survive execve into a binary that carries no file caps — then exec's the
//! freshly built `sismo`. Net: `sismo-run record …` works with no sudo and no
//! re-setcap, ever.
//!
//!   sudo setcap cap_bpf,cap_perfmon,cap_sys_resource=eip \
//!       sismo-run/target/debug/sismo-run
//!   sismo-run/target/debug/sismo-run record --output trace.pftrace ./workload

use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_long, c_ulong};
use std::os::unix::ffi::OsStrExt;

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

// uapi/linux/capability.h capability numbers (CAP_PERFMON/CAP_BPF live in the
// second 32-bit word, so this uses the v3 64-bit ABI with a two-element array).
const CAP_SYS_RESOURCE: u32 = 24;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;
const CAPS: [u32; 3] = [CAP_SYS_RESOURCE, CAP_PERFMON, CAP_BPF];

// linux/prctl.h
const PR_CAP_AMBIENT: c_int = 47;
const PR_CAP_AMBIENT_RAISE: c_ulong = 2;

#[cfg(target_arch = "x86_64")]
const SYS_CAPGET: c_long = 125;
#[cfg(target_arch = "x86_64")]
const SYS_CAPSET: c_long = 126;
#[cfg(target_arch = "aarch64")]
const SYS_CAPGET: c_long = 90;
#[cfg(target_arch = "aarch64")]
const SYS_CAPSET: c_long = 91;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

extern "C" {
    fn syscall(num: c_long, ...) -> c_long;
    fn prctl(option: c_int, ...) -> c_int;
    fn execv(path: *const c_char, argv: *const *const c_char) -> c_int;
}

/// File caps land in PERMITTED but execve leaves INHERITABLE empty, and
/// PR_CAP_AMBIENT_RAISE needs each cap in both. So copy them into inheritable
/// first, then raise into ambient — the set that survives the exec into `sismo`.
fn raise_caps() {
    let mut hdr = CapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let mut data = [CapData { effective: 0, permitted: 0, inheritable: 0 }; 2];
    unsafe {
        if syscall(SYS_CAPGET, &mut hdr as *mut CapHeader, data.as_mut_ptr()) != 0 {
            return;
        }
    }
    for &cap in &CAPS {
        data[(cap >> 5) as usize].inheritable |= 1u32 << (cap & 31);
    }
    unsafe {
        if syscall(SYS_CAPSET, &mut hdr as *mut CapHeader, data.as_ptr()) != 0 {
            return;
        }
        for &cap in &CAPS {
            prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap as c_ulong, 0 as c_ulong, 0 as c_ulong);
        }
    }
}

fn main() {
    raise_caps();

    // `sismo` is the cargo-built binary (crates/sismo/). This launcher lives at
    // crates/sismo-run/target/debug/sismo-run, so sismo is three dirs up then
    // into sismo/target/debug. execve resolves the `..` components.
    let exe = std::fs::read_link("/proc/self/exe").expect("readlink /proc/self/exe");
    let dir = exe.parent().expect("exe has no parent dir");
    let sismo = dir.join("../../../sismo/target/debug/sismo");
    let sismo_c = CString::new(sismo.as_os_str().as_bytes()).expect("sismo path has interior NUL");

    // Forward our argv to sismo, replacing argv[0] with sismo's own path.
    let mut owned: Vec<CString> = vec![sismo_c.clone()];
    for arg in std::env::args_os().skip(1) {
        owned.push(CString::new(arg.as_bytes()).expect("arg has interior NUL"));
    }
    let mut argv: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    argv.push(std::ptr::null());

    unsafe { execv(sismo_c.as_ptr(), argv.as_ptr()) };
    eprintln!("sismo-run: exec {} failed", sismo.display());
    std::process::exit(127);
}
