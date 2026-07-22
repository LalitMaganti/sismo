// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Live Python-frame recovery (PY-1): given a running CPython 3.13+
//! interpreter's `_PyRuntime` address and its parsed `_Py_DebugOffsets`
//! ([`crate::python_offsets`]), walks the target's own thread/frame linked
//! list through `/proc/<pid>/mem` to recover the Python-level call chain —
//! the frames a native frame-pointer walk can never see, since CPython 3.11+
//! runs the bytecode interpreter loop without one native frame per Python
//! call.
//!
//! Two entry points: [`locate_py_runtime`] (or the file-level
//! [`py_runtime_in_file`]) resolves `_PyRuntime`'s runtime address once per
//! target, and [`walk_python_stack`] performs the live per-sample walk. The
//! walk itself is memory-source-generic over [`RemoteMem`] — `/proc/<pid>/mem`
//! on Linux, `mach_vm_read_overwrite` on macOS, `ReadProcessMemory` on
//! Windows — so only the few lines that open the source are per-OS. Every
//! read is best-effort: a target that has moved on, freed a frame, or simply
//! raced the reader yields a short (possibly empty) result, never a panic.

use object::{Object, ObjectSegment};

use crate::python_offsets::{self, PyDebugOffsets};
use crate::proc_maps::ProcMaps;

/// Longest qualname this reader will trust; anything longer is treated as
/// unreadable (bad data, not a real Python identifier).
const MAX_NAME_LEN: i64 = 512;

/// Frames walked before giving up, bounding a corrupted/racing linked list.
const MAX_FRAMES: usize = 64;

/// A source of another process's memory. The only operation the Python walk
/// needs: read exactly `buf.len()` bytes at an absolute address, or say no.
pub trait RemoteMem {
    fn read_exact_at(&self, addr: u64, buf: &mut [u8]) -> Option<()>;
}

/// `/proc/<pid>/mem`-backed [`RemoteMem`] (Linux).
#[cfg(target_os = "linux")]
pub struct ProcMem(std::fs::File);

#[cfg(target_os = "linux")]
impl ProcMem {
    pub fn open(pid: u32) -> Option<Self> {
        std::fs::File::open(format!("/proc/{pid}/mem")).ok().map(ProcMem)
    }
}

#[cfg(target_os = "linux")]
impl RemoteMem for ProcMem {
    fn read_exact_at(&self, addr: u64, buf: &mut [u8]) -> Option<()> {
        use std::os::unix::fs::FileExt;
        self.0.read_exact_at(buf, addr).ok()
    }
}

/// Find the loaded `libpython*.so`'s `_PyRuntime` dynamic symbol and resolve
/// it to a runtime (avma) address in the target process, using its already-
/// parsed `/proc/<pid>/maps`. `None` when no libpython is loaded, the symbol
/// isn't exported, or the file can't be read/parsed — a native, non-Python
/// process is the common `None` case.
pub fn locate_py_runtime(_pid: u32, maps: &ProcMaps) -> Option<u64> {
    let (base_avma, path) = maps.modules().into_iter().find(|(_, path)| {
        let base = path.rsplit('/').next().unwrap_or(path);
        base.starts_with("libpython")
    })?;
    py_runtime_in_file(path, base_avma)
}

/// Whether a loaded image path looks like the one carrying `_PyRuntime`:
/// `libpython3.14.so.1` (ELF), `libpython3.14.dylib`, a framework build's
/// `.../Python.framework/Versions/3.14/Python`, or a `python3.x` binary
/// (static builds carry the runtime in the executable).
pub fn is_python_image(path: &[u8]) -> bool {
    let base = path.rsplit(|&b| b == b'/').next().unwrap_or(path);
    base.starts_with(b"libpython")
        || base.starts_with(b"python")
        || path.windows(17).any(|w| w == b"Python.framework/")
}

/// Find `_PyRuntime` in the on-disk image at `path` (ELF or mach-o — mach-o
/// exports carry a leading underscore) and rebase it onto the image's actual
/// load address. `None` when the file can't be read/parsed or exports no
/// `_PyRuntime` — a native, non-Python image is the common `None` case.
pub fn py_runtime_in_file(path: &str, base_avma: u64) -> Option<u64> {
    let data = std::fs::read(path).ok()?;
    let obj = object::File::parse(&*data).ok()?;
    let link_addr = obj
        .exports()
        .ok()?
        .into_iter()
        .find(|e| e.name() == b"_PyRuntime" || e.name() == b"__PyRuntime")
        .map(|e| e.address())?;

    // Rebase the symbol's link-time address onto this run's actual load
    // address: `slide = base_avma - image_base`, where image_base is the
    // lowest real segment vaddr — 0 for a normally linked .so/.dylib, the
    // __TEXT base for a mach-o executable (whose __PAGEZERO must not count).
    let image_base = obj
        .segments()
        .filter(|s| s.name().ok().flatten() != Some("__PAGEZERO"))
        .map(|s| s.address())
        .min()
        .unwrap_or(0);
    let slide = base_avma.wrapping_sub(image_base);
    Some(link_addr.wrapping_add(slide))
}

/// Read the `_Py_DebugOffsets` blob at `_PyRuntime + 0` from the target's
/// memory. `None` on any read failure (target gone, permission, bad address).
pub fn read_debug_offsets_blob_mem(mem: &impl RemoteMem, py_runtime_avma: u64) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; python_offsets::BLOB_LEN];
    mem.read_exact_at(py_runtime_avma, &mut buf)?;
    Some(buf)
}

/// [`read_debug_offsets_blob_mem`] over `/proc/<pid>/mem` (Linux).
#[cfg(target_os = "linux")]
pub fn read_debug_offsets_blob(pid: u32, py_runtime_avma: u64) -> Option<Vec<u8>> {
    read_debug_offsets_blob_mem(&ProcMem::open(pid)?, py_runtime_avma)
}

/// Walk the running interpreter's current-thread frame chain and return the
/// recovered Python qualnames, leaf (innermost call) first. Empty when the
/// interpreter/thread/frame pointers are unset or any read fails — the
/// caller treats that exactly like "no Python frames to add".
///
/// Follows the single-threaded fast path: `interpreters_head`'s first
/// interpreter's `threads_head` is taken as *the* running thread, with no
/// TSS-key lookup. Correct for a single-threaded target; a multi-threaded
/// target may attribute to the wrong thread (a known limitation, not a bug
/// to fix here).
#[cfg(target_os = "linux")]
pub fn walk_python_stack(pid: u32, py_runtime_avma: u64, offs: &PyDebugOffsets) -> Vec<String> {
    match ProcMem::open(pid) {
        Some(mem) => walk_python_stack_mem(&mem, py_runtime_avma, offs),
        None => Vec::new(),
    }
}

/// [`walk_python_stack`] over any [`RemoteMem`] source.
pub fn walk_python_stack_mem(
    mem: &impl RemoteMem,
    py_runtime_avma: u64,
    offs: &PyDebugOffsets,
) -> Vec<String> {
    let mut out = Vec::new();
    let read_u64 = |addr: u64| -> Option<u64> {
        let mut buf = [0u8; 8];
        mem.read_exact_at(addr, &mut buf)?;
        Some(u64::from_le_bytes(buf))
    };
    let read_bytes = |addr: u64, len: usize| -> Option<Vec<u8>> {
        let mut buf = vec![0u8; len];
        mem.read_exact_at(addr, &mut buf)?;
        Some(buf)
    };

    let Some(interp) = read_u64(py_runtime_avma.wrapping_add(offs.interpreters_head)) else {
        return out;
    };
    if interp == 0 {
        return out;
    }
    let Some(tstate) = read_u64(interp.wrapping_add(offs.threads_head)) else {
        return out;
    };
    if tstate == 0 {
        return out;
    }
    let Some(mut frame) = read_u64(tstate.wrapping_add(offs.current_frame)) else {
        return out;
    };

    for _ in 0..MAX_FRAMES {
        if frame == 0 {
            break;
        }
        let Some(code) = read_u64(frame.wrapping_add(offs.frame_executable)) else {
            break;
        };
        if code == 0 {
            // A non-Python (C shim) frame — skip it, keep walking.
            let Some(prev) = read_u64(frame.wrapping_add(offs.frame_previous)) else {
                break;
            };
            frame = prev;
            continue;
        }
        let Some(qual) = read_u64(code.wrapping_add(offs.code_qualname)) else {
            break;
        };
        if qual == 0 {
            break;
        }
        let Some(name) = read_py_unicode(qual, offs, &read_u64, &read_bytes) else {
            break;
        };
        out.push(name);

        let Some(prev) = read_u64(frame.wrapping_add(offs.frame_previous)) else {
            break;
        };
        frame = prev;
    }
    out
}

/// Read a compact-ASCII `PyUnicodeObject`'s text: its `length` field bounds
/// the read, and the character data starts right after the `PyASCIIObject`
/// header (`asciiobject_size` bytes in). Non-ASCII/non-compact strings aren't
/// handled — qualnames are compact-ASCII in practice, and a malformed length
/// or unreadable data yields `None` rather than a wrong name.
fn read_py_unicode(
    obj: u64,
    offs: &PyDebugOffsets,
    read_u64: &impl Fn(u64) -> Option<u64>,
    read_bytes: &impl Fn(u64, usize) -> Option<Vec<u8>>,
) -> Option<String> {
    let len = read_u64(obj.wrapping_add(offs.unicode_length))? as i64;
    if len <= 0 || len > MAX_NAME_LEN {
        return None;
    }
    let bytes = read_bytes(obj.wrapping_add(offs.unicode_asciiobject_size), len as usize)?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}
