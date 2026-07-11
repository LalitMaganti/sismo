// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Disassembly for the source/asm view. Given a binary path and the set of
//! sampled addresses, finds each containing function in the ELF symbol table,
//! reads its code bytes, and returns the decoded instructions, each tagged with
//! its function's start address so the caller can group them.
//!
//! The sampled `rel_pc`s arrive as absolute runtime virtual addresses (the same
//! convention the wholesym symbolizer is fed). ELF symbol/section addresses, by
//! contrast, are link-time virtual addresses. For a non-PIE `ET_EXEC` the two
//! coincide (no relocation slide); for a PIE `ET_DYN` they differ by the load
//! slide, so a raw comparison finds no containing symbol and nothing decodes.
//! `load_bias` lets us recover the slide (`load_bias - image_base`) and map each
//! avma to its link-time address before the lookup, then map decoded addresses
//! back to avma so the caller's addresses still match the trace's `rel_pc`.
//!
//! Pure-Rust decoders (the yaxpeax family) so this links with no C dependency.
//! The decode loop reads a `U8Reader` whose `total_offset()`
//! delta gives each instruction's length.

use std::collections::HashSet;
use std::path::Path;

use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol, SymbolKind};
use yaxpeax_arch::{Decoder, Reader, U8Reader};

/// One decoded instruction. `func_start` identifies the containing function (its
/// avma start); `rel_pc` is the instruction's avma; `bytes`/`text` are its raw
/// bytes and rendered mnemonic+operands.
pub struct DisasmInsn {
    pub func_start: u64,
    pub rel_pc: u64,
    pub bytes: Vec<u8>,
    pub text: String,
}

/// Target architecture for the decoder.
#[derive(Clone, Copy)]
pub enum Arch {
    X86_64,
    Aarch64,
}

/// Disassemble the functions containing `rel_pcs` in the binary at `path`.
/// `rel_pcs` are absolute runtime virtual addresses; `load_bias` is the mapping's
/// load bias, used to translate them to the link-time addresses the ELF symbol
/// table uses (see the module doc). Returns the decoded instructions (empty on an
/// unreadable / unparseable file). Each distinct containing function is decoded
/// once. Instruction addresses are mapped back to avma space so they match the
/// caller's `rel_pcs`.
pub fn disasm_module(path: &Path, arch: Arch, load_bias: u64, rel_pcs: &[u64]) -> Vec<DisasmInsn> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let obj = match object::File::parse(&*data) {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    // Runtime slide between an avma and the ELF's link-time addresses. The image
    // base is the lowest loadable-segment vaddr (0 for a PIE, the link base for a
    // non-PIE), so `load_bias - image_base` is 0 for a non-PIE EXEC — leaving its
    // already-working path untouched — and the true slide for a PIE.
    let image_base = obj.segments().map(|s| s.address()).min().unwrap_or(0);
    let slide = load_bias.wrapping_sub(image_base);

    let mut syms: Vec<(u64, u64)> = obj
        .symbols()
        .filter(|s| s.kind() == SymbolKind::Text && s.size() > 0)
        .map(|s| (s.address(), s.size()))
        .collect();
    syms.sort_by_key(|x| x.0);

    let mut out = Vec::new();
    let mut done: HashSet<u64> = HashSet::new();
    for &pc in rel_pcs {
        let svma = pc.wrapping_sub(slide); // link-time address of the sample
        let containing = syms.iter().find(|(a, sz)| svma >= *a && svma < a + *sz);
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
        // Decode in link-time space (matches read_code/the symbol table) but tag
        // each instruction with its avma, so the caller's addresses line up with
        // the trace's rel_pc and resolve back through the same symbolizer.
        let func_avma = start.wrapping_add(slide);
        match arch {
            Arch::X86_64 => decode_x86(code, func_avma, &mut out),
            Arch::Aarch64 => decode_arm(code, func_avma, &mut out),
        }
    }
    out
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

fn push_insn(out: &mut Vec<DisasmInsn>, func_start: u64, rel_pc: u64, bytes: &[u8], text: String) {
    out.push(DisasmInsn { func_start, rel_pc, bytes: bytes.to_vec(), text });
}

// Instruction length is the reader's total_offset delta.
fn decode_x86(bytes: &[u8], func_start: u64, out: &mut Vec<DisasmInsn>) {
    let decoder = yaxpeax_x86::amd64::InstDecoder::default();
    let mut reader = U8Reader::new(bytes);
    loop {
        let before = <U8Reader as Reader<u64, u8>>::total_offset(&mut reader) as usize;
        if before >= bytes.len() {
            break;
        }
        match decoder.decode(&mut reader) {
            Ok(inst) => {
                let after = <U8Reader as Reader<u64, u8>>::total_offset(&mut reader) as usize;
                if after <= before {
                    break;
                }
                push_insn(out, func_start, func_start + before as u64, &bytes[before..after], inst.to_string());
            }
            Err(_) => break,
        }
    }
}

fn decode_arm(bytes: &[u8], func_start: u64, out: &mut Vec<DisasmInsn>) {
    let decoder = yaxpeax_arm::armv8::a64::InstDecoder::default();
    let mut reader = U8Reader::new(bytes);
    loop {
        let before = <U8Reader as Reader<u64, yaxpeax_arch::U32le>>::total_offset(&mut reader) as usize;
        if before >= bytes.len() {
            break;
        }
        match decoder.decode(&mut reader) {
            Ok(inst) => {
                let after = <U8Reader as Reader<u64, yaxpeax_arch::U32le>>::total_offset(&mut reader) as usize;
                if after <= before {
                    break;
                }
                push_insn(out, func_start, func_start + before as u64, &bytes[before..after], inst.to_string());
            }
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_x86_ret_and_nop() {
        // 0x90 = nop, 0xc3 = ret.
        let mut out = Vec::new();
        decode_x86(&[0x90, 0xc3], 0x1000, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].rel_pc, 0x1000);
        assert!(out[0].text.contains("nop"));
        assert_eq!(out[1].rel_pc, 0x1001);
        assert!(out[1].text.contains("ret"));
    }

    #[test]
    fn decodes_aarch64_ret() {
        // 0xd65f03c0 = ret (little-endian bytes).
        let mut out = Vec::new();
        decode_arm(&[0xc0, 0x03, 0x5f, 0xd6], 0x2000, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rel_pc, 0x2000);
        assert!(out[0].text.contains("ret"));
    }
}
