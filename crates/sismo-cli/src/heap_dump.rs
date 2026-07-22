// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Runtime dispatch for the `memory-deep` single heap dump.
//!
//! One materialization point (record stop, `sismo snapshot`) asks this module
//! for the target's dump: detect the runtime, trigger its native dumper, and
//! say how the artifact ships. JVM dumps (`.hprof`) bundle into the output tar
//! because trace_processor reads hprof natively; V8 snapshots
//! (`.heapsnapshot`) ship as a sibling file next to the trace, because TP has
//! no V8 importer yet and its tar reader force-parses every member (an
//! unparseable member fails the whole bundle — verified empirically).
//!
//! Runtimes without an externally-triggerable dump (CPython, Go, .NET without
//! dotnet tooling) are out of scope here; their memory story is the streaming
//! allocation profile.

/// A managed runtime we can pull a heap dump out of.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DumpRuntime {
    Jvm,
    Node,
}

impl DumpRuntime {
    pub fn label(self) -> &'static str {
        match self {
            DumpRuntime::Jvm => "JVM",
            DumpRuntime::Node => "Node",
        }
    }

    /// The dump artifact's file extension.
    pub fn ext(self) -> &'static str {
        match self {
            DumpRuntime::Jvm => "hprof",
            DumpRuntime::Node => "heapsnapshot",
        }
    }

    /// Whether the artifact can be bundled into the output tar (i.e. TP can
    /// parse it). Non-bundleable artifacts ship as a sibling file.
    pub fn bundleable(self) -> bool {
        match self {
            DumpRuntime::Jvm => true,
            DumpRuntime::Node => false,
        }
    }
}

/// The target's executable path, for runtime detection and for finding JDK
/// tools next to the target's own binary.
pub(crate) fn exe_path(pid: i32) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        // libproc proc_pidpath.
        extern "C" {
            fn proc_pidpath(pid: i32, buffer: *mut std::os::raw::c_void, buffersize: u32) -> i32;
        }
        let mut buf = [0u8; 4096];
        let n = unsafe { proc_pidpath(pid, buf.as_mut_ptr() as *mut _, buf.len() as u32) };
        if n <= 0 {
            return None;
        }
        Some(String::from_utf8_lossy(&buf[..n as usize]).into_owned())
    }
    #[cfg(target_os = "linux")]
    {
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
        Some(exe.to_string_lossy().into_owned())
    }
}

fn exe_basename(pid: i32) -> Option<String> {
    exe_path(pid)?.rsplit('/').next().map(str::to_string)
}

/// Detect the target's dumpable runtime: executable basename first (cheap,
/// catches the common `java` / `node` launchers), then a jcmd probe as the
/// fallback for embedded JVMs.
pub fn detect(pid: i32) -> Option<DumpRuntime> {
    if let Some(base) = exe_basename(pid) {
        let lower = base.to_ascii_lowercase();
        if lower == "java" || lower == "java.exe" {
            return Some(DumpRuntime::Jvm);
        }
        if crate::v8_heap_dump::is_node_exe(&base) {
            return Some(DumpRuntime::Node);
        }
    }
    if crate::jvm_heap_dump::is_jvm(pid) {
        return Some(DumpRuntime::Jvm);
    }
    None
}

/// Trigger the dump into `dest`; size in bytes on success.
pub fn take(rt: DumpRuntime, pid: i32, dest: &str) -> Option<u64> {
    match rt {
        DumpRuntime::Jvm => crate::jvm_heap_dump::take_heap_dump(pid, dest),
        DumpRuntime::Node => crate::v8_heap_dump::take_heap_snapshot(pid, dest),
    }
}
