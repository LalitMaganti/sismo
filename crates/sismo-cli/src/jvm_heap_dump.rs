// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! JVM heap-dump trigger for the `memory.dump` focus preset.
//!
//! `jcmd <pid> GC.heap_dump` makes HotSpot write the `.hprof` itself (the
//! attach mechanism is cooperative — no task port / ptrace needed), so the raw
//! dump lands on disk with zero conversion; trace_processor reads `.hprof`
//! natively. The dump is stop-the-world: callers only trigger it at explicit
//! materialization points (record stop, `sismo snapshot`), and only when the
//! session opted in via `--focus memory.dump`.
//!
//! HotSpot's attach handshake requires the initiating euid to match the JVM's
//! (root is rejected too — "well-known file is not secure"). The recorder
//! usually runs as root (kperf) while the JVM is the user's, so when we are
//! root, jcmd is exec'd with setuid/setgid to the target's identity.

use std::process::Command;

/// The (uid, gid) of `pid`, via libproc PROC_PIDTBSDINFO.
#[cfg(target_os = "macos")]
fn creds_of_pid(pid: i32) -> Option<(u32, u32)> {
    // sys/proc_info.h `struct proc_bsdinfo` (stable libproc ABI); only the
    // leading fields matter here, but the buffer must be full-sized.
    #[repr(C)]
    #[derive(Default)]
    struct ProcBsdInfo {
        pbi_flags: u32,
        pbi_status: u32,
        pbi_xstatus: u32,
        pbi_pid: u32,
        pbi_ppid: u32,
        pbi_uid: u32,
        pbi_gid: u32,
        pbi_ruid: u32,
        pbi_rgid: u32,
        pbi_svuid: u32,
        pbi_svgid: u32,
        rfu_1: u32,
        pbi_comm: [u8; 16],
        pbi_name: [u8; 32],
        pbi_nfiles: u32,
        pbi_pgid: u32,
        pbi_pjobc: u32,
        e_tdev: u32,
        e_tpgid: u32,
        pbi_nice: i32,
        pbi_start_tvsec: u64,
        pbi_start_tvusec: u64,
    }
    const PROC_PIDTBSDINFO: i32 = 3;
    extern "C" {
        fn proc_pidinfo(pid: i32, flavor: i32, arg: u64, buffer: *mut std::os::raw::c_void, buffersize: i32) -> i32;
    }
    let mut info = ProcBsdInfo::default();
    let size = std::mem::size_of::<ProcBsdInfo>() as i32;
    let n = unsafe { proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &mut info as *mut _ as *mut _, size) };
    if n < size {
        return None;
    }
    Some((info.pbi_uid, info.pbi_gid))
}

#[cfg(target_os = "linux")]
fn creds_of_pid(pid: i32) -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(format!("/proc/{pid}")).ok()?;
    Some((meta.uid(), meta.gid()))
}

/// Exec `cmd` as `pid`'s owner when we are root (HotSpot rejects cross-uid
/// attach); no-op otherwise.
fn run_as_pid_owner(cmd: &mut Command, pid: i32) {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let Some((uid, gid)) = creds_of_pid(pid) else { return };
    if uid == 0 {
        return;
    }
    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(move || {
            if libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// `jcmd` candidates, most reliable first: the jcmd next to the target's own
/// java binary (right JDK, and immune to sudo's env stripping), then
/// $JAVA_HOME/bin/jcmd, then whatever PATH resolves.
fn jcmd_candidates(pid: i32) -> Vec<String> {
    let mut v = Vec::new();
    if let Some(exe) = crate::heap_dump::exe_path(pid) {
        if let Some(dir) = exe.rsplit_once('/').map(|(d, _)| d) {
            let p = format!("{dir}/jcmd");
            if std::path::Path::new(&p).exists() {
                v.push(p);
            }
        }
    }
    if let Ok(home) = std::env::var("JAVA_HOME") {
        let p = format!("{home}/bin/jcmd");
        if std::path::Path::new(&p).exists() {
            v.push(p);
        }
    }
    v.push("jcmd".to_string());
    v
}

/// Run `jcmd <pid> <args...>`; Some(stdout) on success, None if jcmd is
/// missing or the target isn't an attachable JVM.
fn jcmd(pid: i32, args: &[&str]) -> Option<String> {
    for cand in jcmd_candidates(pid) {
        let mut cmd = Command::new(&cand);
        cmd.arg(pid.to_string()).args(args);
        run_as_pid_owner(&mut cmd, pid);
        let out = match cmd.output() {
            Ok(o) => o,
            Err(_) => continue, // binary not found — try the next candidate
        };
        if out.status.success() {
            return Some(String::from_utf8_lossy(&out.stdout).into_owned());
        }
        return None; // jcmd ran but the attach failed: not a JVM (or not ours)
    }
    None
}

/// Whether `pid` is an attachable JVM (jcmd VM.version probe).
pub fn is_jvm(pid: i32) -> bool {
    jcmd(pid, &["VM.version"]).is_some()
}

/// Trigger a heap dump of `pid` to `dest` (absolute path; any existing file is
/// removed first — HotSpot refuses to overwrite). Returns the dump size on
/// success.
pub fn take_heap_dump(pid: i32, dest: &str) -> Option<u64> {
    let _ = std::fs::remove_file(dest);
    jcmd(pid, &["GC.heap_dump", dest])?;
    std::fs::metadata(dest).ok().map(|m| m.len())
}
