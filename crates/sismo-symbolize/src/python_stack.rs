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
//! Two entry points: [`locate_py_runtime`] resolves `_PyRuntime`'s runtime
//! address once per target (found via the loaded `libpython*.so`'s dynamic
//! symbol table), and [`walk_python_stack`] performs the live per-sample
//! walk. Every read is best-effort: a target that has moved on, freed a
//! frame, or simply raced the reader yields a short (possibly empty) result,
//! never a panic.

use std::os::unix::fs::FileExt;

use object::{Object, ObjectSegment, ObjectSymbol};

use crate::python_offsets::{self, PyDebugOffsets};
use crate::proc_maps::ProcMaps;

/// Longest qualname this reader will trust; anything longer is treated as
/// unreadable (bad data, not a real Python identifier).
const MAX_NAME_LEN: i64 = 512;

/// Frames walked before giving up, bounding a corrupted/racing linked list.
const MAX_FRAMES: usize = 64;

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
    let path = path.to_string();

    let data = std::fs::read(&path).ok()?;
    let obj = object::File::parse(&*data).ok()?;
    let sym = obj
        .dynamic_symbols()
        .find(|s| s.name() == Ok("_PyRuntime"))?;

    // Rebase the symbol's link-time address onto this run's actual load
    // address, same as disasm.rs: `slide = base_avma - image_base`, where
    // image_base is the lowest segment vaddr (0 for a normally linked .so).
    let image_base = obj.segments().map(|s| s.address()).min().unwrap_or(0);
    let slide = base_avma.wrapping_sub(image_base);
    Some(sym.address().wrapping_add(slide))
}

/// Read the `_Py_DebugOffsets` blob at `_PyRuntime + 0` from the target's
/// memory. `None` on any read failure (target gone, permission, bad address).
pub fn read_debug_offsets_blob(pid: u32, py_runtime_avma: u64) -> Option<Vec<u8>> {
    let mem = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    let mut buf = vec![0u8; python_offsets::BLOB_LEN];
    mem.read_exact_at(&mut buf, py_runtime_avma).ok()?;
    Some(buf)
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
pub fn walk_python_stack(pid: u32, py_runtime_avma: u64, offs: &PyDebugOffsets) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(mem) = std::fs::File::open(format!("/proc/{pid}/mem")) else {
        return out;
    };
    let read_u64 = |addr: u64| -> Option<u64> {
        let mut buf = [0u8; 8];
        mem.read_exact_at(&mut buf, addr).ok()?;
        Some(u64::from_le_bytes(buf))
    };
    let read_bytes = |addr: u64, len: usize| -> Option<Vec<u8>> {
        let mut buf = vec![0u8; len];
        mem.read_exact_at(&mut buf, addr).ok()?;
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
