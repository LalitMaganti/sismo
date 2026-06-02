// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Disassembly FFI for the source/asm view. Given a binary path and the set of
//! sampled module-relative addresses, finds each containing function in the ELF
//! symbol table, reads its code bytes, and streams decoded instructions back to
//! Zig via a callback — one call per instruction, tagged with the function's
//! start address so the caller can group them.
//!
//! Pure-Rust decoders (the yaxpeax family) so this links into the staticlib with
//! no C dependency. The decode loop reads a `U8Reader` whose `total_offset()`
//! delta gives each instruction's length.

use std::collections::HashSet;
use std::os::raw::{c_int, c_void};
use std::slice;

use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};
use yaxpeax_arch::{Decoder, Reader, U8Reader};

/// Per-instruction callback. `func_start` identifies the function (its
/// module-relative start address); `insn_rel_pc` is the instruction's address;
/// `bytes`/`text` are its raw bytes and its rendered mnemonic+operands.
type InsnCb = extern "C" fn(
    ctx: *mut c_void,
    func_start: u64,
    insn_rel_pc: u64,
    bytes: *const u8,
    bytes_len: usize,
    text: *const u8,
    text_len: usize,
);

const ARCH_X86_64: u32 = 0;
const ARCH_AARCH64: u32 = 1;

/// Disassemble the functions containing `rel_pcs` in the binary at `path`.
/// Returns 0 on success, -1 on bad arguments / unreadable / unparseable file.
/// Each distinct containing function is decoded once.
///
/// # Safety
/// `path_utf8`/`rel_pcs` must be valid for their stated lengths, and `cb` must
/// be a valid function pointer for the lifetime of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_disasm_module(
    path_utf8: *const u8,
    path_len: usize,
    arch: u32,
    rel_pcs: *const u64,
    rel_pcs_len: usize,
    cb: InsnCb,
    ctx: *mut c_void,
) -> c_int {
    if path_utf8.is_null() || rel_pcs.is_null() || path_len == 0 {
        return -1;
    }
    if arch != ARCH_X86_64 && arch != ARCH_AARCH64 {
        return -1;
    }
    let path_bytes = unsafe { slice::from_raw_parts(path_utf8, path_len) };
    let path = match std::str::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return -1,
    };
    let obj = match object::File::parse(&*data) {
        Ok(o) => o,
        Err(_) => return -1,
    };

    let mut syms: Vec<(u64, u64)> = obj
        .symbols()
        .filter(|s| s.kind() == SymbolKind::Text && s.size() > 0)
        .map(|s| (s.address(), s.size()))
        .collect();
    syms.sort_by_key(|x| x.0);

    let pcs = unsafe { slice::from_raw_parts(rel_pcs, rel_pcs_len) };
    let mut done: HashSet<u64> = HashSet::new();
    for &pc in pcs {
        let containing = syms.iter().find(|(a, sz)| pc >= *a && pc < a + *sz);
        let (start, size) = match containing {
            Some(&(a, s)) => (a, s),
            None => continue,
        };
        if !done.insert(start) {
            continue;
        }
        let code = match read_code(&obj, start, size) {
            Some(c) => c,
            None => continue,
        };
        match arch {
            ARCH_X86_64 => decode_x86(code, start, cb, ctx),
            ARCH_AARCH64 => decode_arm(code, start, cb, ctx),
            _ => {}
        }
    }
    0
}

fn read_code<'a>(obj: &'a object::File, start: u64, size: u64) -> Option<&'a [u8]> {
    for sect in obj.sections() {
        let addr = sect.address();
        let sz = sect.size();
        if addr == 0 || sz == 0 {
            continue;
        }
        if start >= addr && start + size <= addr + sz {
            let data = sect.data().ok()?;
            let off = (start - addr) as usize;
            let end = off.checked_add(size as usize)?;
            if end <= data.len() {
                return Some(&data[off..end]);
            }
        }
    }
    None
}

fn emit(cb: InsnCb, ctx: *mut c_void, func_start: u64, insn_rel_pc: u64, bytes: &[u8], text: &str) {
    cb(
        ctx,
        func_start,
        insn_rel_pc,
        bytes.as_ptr(),
        bytes.len(),
        text.as_ptr(),
        text.len(),
    );
}

// Instruction length is the reader's total_offset delta.
fn decode_x86(bytes: &[u8], func_start: u64, cb: InsnCb, ctx: *mut c_void) {
    let decoder = yaxpeax_x86::amd64::InstDecoder::default();
    let mut reader = U8Reader::new(bytes);
    loop {
        let before = u64::from(<U8Reader as Reader<u64, u8>>::total_offset(&mut reader)) as usize;
        if before >= bytes.len() {
            break;
        }
        match decoder.decode(&mut reader) {
            Ok(inst) => {
                let after = u64::from(<U8Reader as Reader<u64, u8>>::total_offset(&mut reader)) as usize;
                if after <= before {
                    break;
                }
                let text = inst.to_string();
                emit(cb, ctx, func_start, func_start + before as u64, &bytes[before..after], &text);
            }
            Err(_) => break,
        }
    }
}

fn decode_arm(bytes: &[u8], func_start: u64, cb: InsnCb, ctx: *mut c_void) {
    let decoder = yaxpeax_arm::armv8::a64::InstDecoder::default();
    let mut reader = U8Reader::new(bytes);
    loop {
        let before = u64::from(<U8Reader as Reader<u64, yaxpeax_arch::U32le>>::total_offset(&mut reader)) as usize;
        if before >= bytes.len() {
            break;
        }
        match decoder.decode(&mut reader) {
            Ok(inst) => {
                let after = u64::from(<U8Reader as Reader<u64, yaxpeax_arch::U32le>>::total_offset(&mut reader)) as usize;
                if after <= before {
                    break;
                }
                let text = inst.to_string();
                emit(cb, ctx, func_start, func_start + before as u64, &bytes[before..after], &text);
            }
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    thread_local! {
        static SEEN: RefCell<Vec<(u64, String)>> = RefCell::new(Vec::new());
    }

    extern "C" fn collect(
        _ctx: *mut c_void,
        _func_start: u64,
        rel_pc: u64,
        _bytes: *const u8,
        _bytes_len: usize,
        text: *const u8,
        text_len: usize,
    ) {
        let t = unsafe { std::slice::from_raw_parts(text, text_len) };
        let s = String::from_utf8_lossy(t).into_owned();
        SEEN.with(|v| v.borrow_mut().push((rel_pc, s)));
    }

    #[test]
    fn decodes_x86_ret_and_nop() {
        SEEN.with(|v| v.borrow_mut().clear());
        // 0x90 = nop, 0xc3 = ret.
        decode_x86(&[0x90, 0xc3], 0x1000, collect, std::ptr::null_mut());
        SEEN.with(|v| {
            let v = v.borrow();
            assert_eq!(v.len(), 2);
            assert_eq!(v[0].0, 0x1000);
            assert!(v[0].1.contains("nop"));
            assert_eq!(v[1].0, 0x1001);
            assert!(v[1].1.contains("ret"));
        });
    }

    #[test]
    fn decodes_aarch64_ret() {
        SEEN.with(|v| v.borrow_mut().clear());
        // 0xd65f03c0 = ret (little-endian bytes).
        decode_arm(&[0xc0, 0x03, 0x5f, 0xd6], 0x2000, collect, std::ptr::null_mut());
        SEEN.with(|v| {
            let v = v.borrow();
            assert_eq!(v.len(), 1);
            assert_eq!(v[0].0, 0x2000);
            assert!(v[0].1.contains("ret"));
        });
    }
}
