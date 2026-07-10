// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Post-record symbolization for `sismo record`.
//!
//! Reads the unsymbolized frames out of a finished trace (via the C++
//! trace_processor shim `sismo_trace_query_unsymbolized`), resolves each
//! module's sampled addresses with wholesym (the Rust symbolizer sibling),
//! and appends `ModuleSymbols` TracePackets back to the same file. It then
//! bundles the referenced source-file text and per-function disassembly as a
//! TrackEvent "sidecar" (the same HACK as sismo_privileged_marker — see the
//! block comment on `append_sidecar`).
//!
//! Only invoked on the Linux bpf path (cmd_record), so its *runtime* is
//! Linux-only and rides the LINUX-UNVALIDATED flag; it compiles + links on
//! macOS and its pure helpers are unit-tested here. The trace query is bound
//! to the C++ shim; the symbolizer, disassembler, and proto writer are Rust
//! siblings (direct calls, no FFI round-trip). POSIX-only (file append).

use crate::disasm::sismo_disasm_module;
use sismo_proto::ProtoWriter;
use crate::symbolizer::{
    sismo_symbolizer_add_module, sismo_symbolizer_create, sismo_symbolizer_destroy,
    sismo_symbolizer_resolve, Symbolizer,
};
use std::collections::HashSet;
use std::io::Write;
use std::os::raw::{c_int, c_void};

// ---- Field tags (protos/perfetto/trace/{trace_packet,profiling/profile_common}) ----
const TP_FIELD_TRACE_PACKET: u32 = 1;
const TP_FIELD_MODULE_SYMBOLS: u32 = 61;
const MS_FIELD_PATH: u32 = 1;
const MS_FIELD_BUILD_ID: u32 = 2;
const MS_FIELD_ADDRESS_SYMBOLS: u32 = 3;
const AS_FIELD_ADDRESS: u32 = 1;
const AS_FIELD_LINES: u32 = 2;
const LINE_FIELD_FUNCTION_NAME: u32 = 1;
const LINE_FIELD_SOURCE_FILE_NAME: u32 = 2;
const LINE_FIELD_LINE_NUMBER: u32 = 3;

// disasm arch tags (crate::disasm).
const ARCH_X86_64: u32 = 0;
const ARCH_AARCH64: u32 = 1;

// ---- C++ trace_processor shim ----------------------------------------------

type RowCb = extern "C" fn(
    ctx: *mut c_void,
    name: *const u8,
    name_len: usize,
    build_id: *const u8,
    build_id_len: usize,
    rel_pc: u64,
    load_bias: u64,
);

#[cfg(not(test))]
extern "C" {
    fn sismo_trace_query_unsymbolized(trace_path: *const u8, cb: RowCb, ctx: *mut c_void) -> c_int;
}

// cargo test links the rlib standalone with no C++ shim — stub it (the pure
// helpers are what the tests exercise; the query itself is Linux-runtime only).
#[cfg(test)]
unsafe extern "C" fn sismo_trace_query_unsymbolized(
    _trace_path: *const u8,
    _cb: RowCb,
    _ctx: *mut c_void,
) -> c_int {
    0
}

// ---- Module collection -----------------------------------------------------

struct Module {
    name: Vec<u8>,
    build_id_hex: Vec<u8>,
    load_bias: u64,
    rel_pcs: Vec<u64>,
    seen: HashSet<u64>,
}

#[derive(Default)]
struct Collector {
    modules: Vec<Module>,
}

/// Per-row callback: rows arrive grouped by (name, build_id, load_bias), so the
/// trailing module is extended while the key matches and a new one starts when
/// it changes. Duplicate rel_pcs (many samples hitting one address) collapse via
/// `seen`.
extern "C" fn on_row(
    ctx: *mut c_void,
    name_ptr: *const u8,
    name_len: usize,
    build_id_ptr: *const u8,
    build_id_len: usize,
    rel_pc: u64,
    load_bias: u64,
) {
    let self_ = unsafe { &mut *(ctx as *mut Collector) };
    let name = unsafe { std::slice::from_raw_parts(name_ptr, name_len) };
    let build_id = unsafe { std::slice::from_raw_parts(build_id_ptr, build_id_len) };

    let same = self_.modules.last().is_some_and(|m| {
        m.load_bias == load_bias && m.name == name && m.build_id_hex == build_id
    });
    if !same {
        self_.modules.push(Module {
            name: name.to_vec(),
            build_id_hex: build_id.to_vec(),
            load_bias,
            rel_pcs: Vec::new(),
            seen: HashSet::new(),
        });
    }
    let m = self_.modules.last_mut().unwrap();
    if m.seen.insert(rel_pc) {
        m.rel_pcs.push(rel_pc);
    }
}

// ---- Entry point -----------------------------------------------------------

/// Read the unsymbolized frames from `trace_path`, resolve them, and append
/// `ModuleSymbols` packets + the source/asm sidecar to the same file.
/// Best-effort: any failure is logged and swallowed so a symbolization problem
/// never loses a recording.
pub fn symbolize_trace(trace_path: &str) {
    let mut path_z: Vec<u8> = trace_path.as_bytes().to_vec();
    path_z.push(0);

    let mut collector = Collector::default();
    let rc = unsafe {
        sismo_trace_query_unsymbolized(
            path_z.as_ptr(),
            on_row,
            &mut collector as *mut Collector as *mut c_void,
        )
    };
    if rc != 0 {
        eprintln!("sismo record: symbolization skipped (QueryFailed)");
        return;
    }
    if collector.modules.is_empty() {
        return; // nothing to symbolize
    }

    let sym = sismo_symbolizer_create();
    if sym.is_null() {
        eprintln!("sismo record: symbolization skipped (symbolizer create failed)");
        return;
    }

    let mut out = ProtoWriter::new();
    let mut stats: Vec<ModuleStat> = Vec::new();

    // Unique source-file paths referenced by sampled addresses, bundled after.
    let mut src_set: Vec<Vec<u8>> = Vec::new();
    let mut src_seen: HashSet<Vec<u8>> = HashSet::new();

    // Per-function disassembly listings to bundle (only on a supported arch).
    let mut asm_records: Vec<AsmRecord> = Vec::new();
    let host_arch = current_arch();

    let mut n_funcs: usize = 0;
    let mut n_addrs: usize = 0;

    for m in &collector.modules {
        if m.rel_pcs.is_empty() {
            continue;
        }
        let mut stat = ModuleStat::new(m.name.clone(), m.build_id_hex.clone());
        let ms = build_module_symbols(sym, m, &mut stat, &mut src_set, &mut src_seen);
        n_addrs += stat.n_addrs;
        n_funcs += stat.n_resolved;
        stats.push(stat);
        // Disassemble this module's hot functions while `sym` is scoped exactly
        // as build_module_symbols saw it (line resolution reuses the lookups).
        if let Some(arch) = host_arch {
            collect_module_disasm(sym, m, arch, &mut asm_records);
        }
        if ms.is_empty() {
            continue;
        }
        let mut tp = ProtoWriter::new();
        tp.write_message(TP_FIELD_MODULE_SYMBOLS, &ms);
        out.write_message(TP_FIELD_TRACE_PACKET, tp.bytes());
    }

    if !out.bytes().is_empty() {
        if let Err(e) = append_bytes(trace_path, out.bytes()) {
            eprintln!("sismo record: symbolization skipped ({e})");
            unsafe { sismo_symbolizer_destroy(sym) };
            return;
        }
    }

    append_source_asm_sidecar(trace_path, &src_set, &asm_records);
    report(&stats, n_addrs, n_funcs);

    unsafe { sismo_symbolizer_destroy(sym) };
}

/// Append `bytes` at the end of the file at `path`.
fn append_bytes(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new().append(true).open(path)?;
    f.write_all(bytes)
}

fn current_arch() -> Option<u32> {
    if cfg!(target_arch = "x86_64") {
        Some(ARCH_X86_64)
    } else if cfg!(target_arch = "aarch64") {
        Some(ARCH_AARCH64)
    } else {
        None
    }
}

// ---- Symbolizer resolve helper ---------------------------------------------

struct Resolved {
    name: Vec<u8>,
    file: Vec<u8>,
    line: u32,
}

fn resolve(sym: *mut Symbolizer, avma: u64) -> Resolved {
    let mut name_buf = [0u8; 1024];
    let mut file_buf = [0u8; 1024];
    let mut file_len: usize = 0;
    let mut line: u32 = 0;
    let n = unsafe {
        sismo_symbolizer_resolve(
            sym,
            avma,
            name_buf.as_mut_ptr(),
            name_buf.len(),
            file_buf.as_mut_ptr(),
            file_buf.len(),
            &mut file_len,
            &mut line,
        )
    };
    Resolved {
        name: name_buf[..n].to_vec(),
        file: file_buf[..file_len].to_vec(),
        line,
    }
}

// ---- ModuleSymbols building ------------------------------------------------

/// Build one ModuleSymbols message for `m`, or return an empty vec if no address
/// resolved. Field order (path, build_id, then the repeated AddressSymbols).
fn build_module_symbols(
    sym: *mut Symbolizer,
    m: &Module,
    stat: &mut ModuleStat,
    src_set: &mut Vec<Vec<u8>>,
    src_seen: &mut HashSet<Vec<u8>>,
) -> Vec<u8> {
    // base_avma = load_bias so the bridge's `rel = avma - base_avma` equals
    // `rel_pc - load_bias`. end_avma just has to be past every rel_pc.
    let mut max_pc = m.load_bias;
    for &pc in &m.rel_pcs {
        max_pc = max_pc.max(pc);
    }
    let end_avma = max_pc + 1;

    let mut symbol_count: u64 = 0;
    let mut err_buf = [0u8; 256];
    let rc = unsafe {
        sismo_symbolizer_add_module(
            sym,
            m.load_bias,
            end_avma,
            m.name.as_ptr(),
            m.name.len(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            &mut symbol_count,
            err_buf.as_mut_ptr(),
            err_buf.len(),
        )
    };
    stat.symbols_loaded = rc == 0;
    stat.symbol_count = symbol_count;
    let err_len = err_buf.iter().position(|&b| b == 0).unwrap_or(err_buf.len());
    stat.err = err_buf[..err_len].to_vec();

    // Accumulate the repeated AddressSymbols bodies; emit nothing if none match.
    let mut address_symbols: Vec<Vec<u8>> = Vec::new();
    for &rel_pc in &m.rel_pcs {
        stat.n_addrs += 1;
        let r = resolve(sym, rel_pc);
        let func = strip_offset(&r.name);
        if func.is_empty() {
            continue;
        }
        stat.n_resolved += 1;

        let mut line = ProtoWriter::new();
        line.write_string(LINE_FIELD_FUNCTION_NAME, func);
        // Source file + line come from DWARF; absent for symtab-only modules.
        if !r.file.is_empty() {
            line.write_string(LINE_FIELD_SOURCE_FILE_NAME, &r.file);
            if src_seen.insert(r.file.clone()) {
                src_set.push(r.file.clone());
            }
        }
        if r.line > 0 {
            line.write_uint32(LINE_FIELD_LINE_NUMBER, r.line);
        }

        let mut as_ = ProtoWriter::new();
        as_.write_uint64(AS_FIELD_ADDRESS, rel_pc);
        as_.write_message(AS_FIELD_LINES, line.bytes());
        address_symbols.push(as_.bytes().to_vec());
    }
    if address_symbols.is_empty() {
        return Vec::new();
    }

    let mut build_id_raw = [0u8; 64];
    let bid = hex_to_bytes(&m.build_id_hex, &mut build_id_raw);

    let mut ms = ProtoWriter::new();
    ms.write_string(MS_FIELD_PATH, &m.name);
    if !bid.is_empty() {
        ms.write_string(MS_FIELD_BUILD_ID, bid);
    }
    for a in &address_symbols {
        ms.write_message(MS_FIELD_ADDRESS_SYMBOLS, a);
    }
    ms.bytes().to_vec()
}

// ==== BEGIN HACK: disassembly collection over the sidecar channel ====
// Mirrors the source-bundling hack; delete with sismo_privileged_marker when the
// real sidecar lands. The disasm bridge itself (disasm.rs) is reusable infra —
// only this trace-injection path is the hack.

struct DisasmInsn {
    rel_pc: u64,
    bytes_hex: Vec<u8>,
    text: Vec<u8>,
}

struct DisasmCtx {
    // Insertion-ordered func_start -> instructions (matches Zig's ArrayHashMap).
    funcs: Vec<(u64, Vec<DisasmInsn>)>,
}

extern "C" fn on_insn(
    ctx_opaque: *mut c_void,
    func_start: u64,
    insn_rel_pc: u64,
    bytes_ptr: *const u8,
    bytes_len: usize,
    text_ptr: *const u8,
    text_len: usize,
) {
    let ctx = unsafe { &mut *(ctx_opaque as *mut DisasmCtx) };
    let bytes = unsafe { std::slice::from_raw_parts(bytes_ptr, bytes_len) };
    let text = unsafe { std::slice::from_raw_parts(text_ptr, text_len) };
    let insn = DisasmInsn { rel_pc: insn_rel_pc, bytes_hex: bytes_to_hex(bytes), text: text.to_vec() };
    match ctx.funcs.iter_mut().find(|(k, _)| *k == func_start) {
        Some((_, v)) => v.push(insn),
        None => ctx.funcs.push((func_start, vec![insn])),
    }
}

fn collect_module_disasm(sym: *mut Symbolizer, m: &Module, arch: u32, out: &mut Vec<AsmRecord>) {
    let mut ctx = DisasmCtx { funcs: Vec::new() };
    // rel_pcs are absolute avmas; disasm needs load_bias to reach the link-time
    // addresses. It tags decoded instructions back in avma space, so func_start
    // and insn rel_pcs still resolve and match the trace's rel_pc.
    let rc = unsafe {
        sismo_disasm_module(
            m.name.as_ptr(),
            m.name.len(),
            arch,
            m.load_bias,
            m.rel_pcs.as_ptr(),
            m.rel_pcs.len(),
            on_insn,
            &mut ctx as *mut DisasmCtx as *mut c_void,
        )
    };
    if rc != 0 {
        return;
    }

    for (func_start, insns) in &ctx.funcs {
        if insns.is_empty() {
            continue;
        }
        let r = resolve(sym, *func_start);
        let fname = strip_offset(&r.name);
        if fname.is_empty() {
            continue;
        }

        let mut js: Vec<u8> = Vec::new();
        js.push(b'[');
        for (i, insn) in insns.iter().enumerate() {
            if i > 0 {
                js.push(b',');
            }
            let lr = resolve(sym, insn.rel_pc);
            append_insn_json(&mut js, insn, lr.line);
        }
        js.push(b']');

        out.push(AsmRecord {
            func: fname.to_vec(),
            module: m.name.clone(),
            build_id_hex: m.build_id_hex.clone(),
            json: js,
        });
    }
}

fn bytes_to_hex(bytes: &[u8]) -> Vec<u8> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        hex.push(DIGITS[(b >> 4) as usize]);
        hex.push(DIGITS[(b & 0xf) as usize]);
    }
    hex
}

fn append_insn_json(js: &mut Vec<u8>, insn: &DisasmInsn, line: u32) {
    js.extend_from_slice(b"{\"a\":\"");
    js.extend_from_slice(insn.rel_pc.to_string().as_bytes());
    js.extend_from_slice(b"\",\"b\":\"");
    js.extend_from_slice(&insn.bytes_hex);
    js.extend_from_slice(b"\",\"t\":\"");
    append_json_escaped(js, &insn.text);
    js.extend_from_slice(b"\"");
    if line > 0 {
        js.extend_from_slice(b",\"l\":");
        js.extend_from_slice(line.to_string().as_bytes());
    }
    js.push(b'}');
}

fn append_json_escaped(js: &mut Vec<u8>, s: &[u8]) {
    for &c in s {
        match c {
            b'"' => js.extend_from_slice(b"\\\""),
            b'\\' => js.extend_from_slice(b"\\\\"),
            b'\n' => js.extend_from_slice(b"\\n"),
            b'\t' => js.extend_from_slice(b"\\t"),
            _ if c >= 0x20 => js.push(c),
            _ => {}
        }
    }
}

// ==== END HACK ====

// ---- Reporting -------------------------------------------------------------

#[derive(PartialEq)]
enum Status {
    Ok,
    Partial,
    Unresolved,
    NoSymbols,
}

/// What happened when we tried to symbolize one module.
struct ModuleStat {
    name: Vec<u8>,
    build_id_hex: Vec<u8>,
    symbols_loaded: bool,
    symbol_count: u64,
    n_addrs: usize,
    n_resolved: usize,
    err: Vec<u8>,
}

impl ModuleStat {
    fn new(name: Vec<u8>, build_id_hex: Vec<u8>) -> Self {
        Self {
            name,
            build_id_hex,
            symbols_loaded: false,
            symbol_count: 0,
            n_addrs: 0,
            n_resolved: 0,
            err: Vec::new(),
        }
    }

    fn status(&self) -> Status {
        if !self.symbols_loaded {
            return Status::NoSymbols;
        }
        if self.n_resolved == 0 {
            return Status::Unresolved;
        }
        if self.n_resolved < self.n_addrs {
            return Status::Partial;
        }
        Status::Ok
    }
}

fn s(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(bytes)
}

fn report(stats: &[ModuleStat], n_addrs: usize, n_funcs: usize) {
    if stats.is_empty() {
        eprintln!("sismo record: no unsymbolized frames to resolve");
        return;
    }
    eprintln!(
        "sismo record: symbolized {n_funcs}/{n_addrs} addresses across {} modules",
        stats.len()
    );
    let mut needs_help = false;
    for st in stats {
        let tag = match st.status() {
            Status::Ok => "ok        ",
            Status::Partial => "partial   ",
            Status::Unresolved => "unresolved",
            Status::NoSymbols => "no symbols",
        };
        if matches!(st.status(), Status::NoSymbols | Status::Unresolved) {
            needs_help = true;
        }
        eprintln!("  [{tag}] {:>5}/{:<5} {}", st.n_resolved, st.n_addrs, s(&st.name));
    }
    if needs_help {
        print_guidance(stats);
    }
}

fn print_guidance(stats: &[ModuleStat]) {
    let hint = install_hint();
    eprintln!("\nsismo record: some modules did not fully symbolize:");
    for st in stats {
        match st.status() {
            Status::Ok | Status::Partial => continue,
            Status::NoSymbols => {
                eprint!("\n  {}\n    no symbols could be loaded", s(&st.name));
                if !st.err.is_empty() {
                    eprint!(" — wholesym: {}", s(&st.err));
                }
                eprintln!();
                if !file_exists(&st.name) {
                    eprintln!("    the file is no longer at this path (deleted/unmounted since recording?)");
                } else {
                    eprintln!("    the binary on disk is stripped and has no separate debug info installed.");
                    eprintln!("    fix it one of these ways:");
                    eprintln!("      - install its debug package: {hint}");
                    eprintln!("      - or let sismo fetch it: export DEBUGINFOD_URLS=https://debuginfod.fedoraproject.org/");
                    eprintln!("        then re-run `sismo record` (sismo honors DEBUGINFOD_URLS and caches downloads).");
                }
            }
            Status::Unresolved => {
                eprintln!(
                    "\n  {}\n    {} symbols loaded, but 0/{} sampled addresses fell inside any function.",
                    s(&st.name), st.symbol_count, st.n_addrs
                );
                eprintln!("    this is NOT a missing-symbols problem. The sampled addresses don't match this build.");
                eprintln!("    likely the binary changed since recording, or a build-id mismatch:");
                eprintln!("      sampled build-id: {}", s(&st.build_id_hex));
                eprintln!("      on disk:          readelf -n {} | grep -i 'build id'", s(&st.name));
            }
        }
    }
    eprintln!();
}

fn file_exists(path: &[u8]) -> bool {
    match std::str::from_utf8(path) {
        Ok(p) if std::path::Path::new(p).is_absolute() => std::path::Path::new(p).exists(),
        _ => false,
    }
}

/// Best-effort debug-package install command for the running distro, from
/// /etc/os-release. Falls back to a generic note.
fn install_hint() -> &'static str {
    let text = match std::fs::read_to_string("/etc/os-release") {
        Ok(t) => t,
        Err(_) => return GENERIC_HINT,
    };
    let id = match os_release_id(&text) {
        Some(i) => i,
        None => return GENERIC_HINT,
    };
    if ["fedora", "rhel", "centos", "rocky", "almalinux"].contains(&id) {
        "sudo dnf debuginfo-install <package>"
    } else if ["debian", "ubuntu", "pop", "linuxmint"].contains(&id) {
        "sudo apt install <package>-dbgsym  (enable the debug/-dbgsym repo first)"
    } else if ["arch", "manjaro"].contains(&id) {
        "install the matching -debug package (or use a debuginfod server)"
    } else {
        GENERIC_HINT
    }
}

const GENERIC_HINT: &str = "install your distro's debug-symbols package for this library";

fn os_release_id(text: &str) -> Option<&str> {
    for line in text.split('\n') {
        if let Some(v) = line.strip_prefix("ID=") {
            let v = v.strip_prefix('"').and_then(|x| x.strip_suffix('"')).unwrap_or(v);
            return Some(v);
        }
    }
    None
}

// ---- Pure helpers ----------------------------------------------------------

/// Strip wholesym's trailing " +<offset>" so only the function name is emitted
/// (trace_processor recomputes the per-frame offset itself).
fn strip_offset(name: &[u8]) -> &[u8] {
    let mut i = name.len();
    while i > 0 && name[i - 1].is_ascii_digit() {
        i -= 1;
    }
    if i < name.len() && i >= 2 && name[i - 1] == b'+' && name[i - 2] == b' ' {
        return &name[..i - 2];
    }
    name
}

/// Decode a hex string into `buf`, returning the filled prefix. Odd-length or
/// non-hex input yields an empty slice (build_id then omitted, not corrupted).
fn hex_to_bytes<'a>(hex: &[u8], buf: &'a mut [u8]) -> &'a [u8] {
    if hex.is_empty() || !hex.len().is_multiple_of(2) || hex.len() / 2 > buf.len() {
        return &[];
    }
    let mut i = 0;
    while i < hex.len() {
        let hi = match (hex[i] as char).to_digit(16) {
            Some(d) => d as u8,
            None => return &[],
        };
        let lo = match (hex[i + 1] as char).to_digit(16) {
            Some(d) => d as u8,
            None => return &[],
        };
        buf[i / 2] = (hi << 4) | lo;
        i += 2;
    }
    &buf[..hex.len() / 2]
}

// ===========================================================================
// Source-and-disassembly sidecar.
//
// THIS IS A HACK, in the same vein as sismo_privileged_marker. It bundles the
// source-file text (and, via AsmRecord, a disassembly listing) for the sampled
// functions by appending TYPE_INSTANT TrackEvent packets carrying the payload
// in debug_annotations. trace_processor surfaces those as `args` rows, which
// the Sismo UI's annotation loader reads to render the Source/Assembly view.
//
// Do not extend this into a general metadata system. When the proper
// JSON-in-zip sidecar lands, this and sismo_privileged_marker get deleted
// together. The UI matches the track name `sismo_temporary_source_asm_sidecar`
// and the event names `sismo_src` / `sismo_asm`.
// ===========================================================================

const TP_FIELD_TIMESTAMP: u32 = 8;
const TP_FIELD_TRUSTED_PACKET_SEQUENCE_ID: u32 = 10;
const TP_FIELD_TRACK_EVENT: u32 = 11;
const TP_FIELD_TIMESTAMP_CLOCK_ID: u32 = 58;
const TP_FIELD_TRACK_DESCRIPTOR: u32 = 60;
const BUILTIN_CLOCK_BOOTTIME: u32 = 6;
const TE_FIELD_TYPE: u32 = 9;
const TE_FIELD_TRACK_UUID: u32 = 11;
const TE_FIELD_NAME: u32 = 23;
const TE_FIELD_DEBUG_ANNOTATIONS: u32 = 4;
const TE_TYPE_INSTANT: u32 = 3;
const TD_FIELD_UUID: u32 = 1;
const TD_FIELD_NAME: u32 = 2;
const DA_FIELD_INT_VALUE: u32 = 4;
const DA_FIELD_STRING_VALUE: u32 = 6;
const DA_FIELD_NAME: u32 = 10;

const TRACK_NAME: &[u8] = b"sismo_temporary_source_asm_sidecar";
const TRACK_UUID: u64 = 0xC0DE_CAFE_5350_2020;
const SEQUENCE_ID: u32 = 0xC0DECAFF;
const SRC_EVENT_NAME: &[u8] = b"sismo_src";
const ASM_EVENT_NAME: &[u8] = b"sismo_asm";

// Bounds so a recording never balloons.
const MAX_SRC_BYTES: u64 = 1 << 20;
const MAX_TOTAL_SRC_BYTES: usize = 16 << 20;
const MAX_CHUNK_BYTES: usize = 192 * 1024;

/// One function's disassembly, ready to serialize. `json` is the already-built
/// `[{a,b,t,l}, …]` array; the sidecar only chunks + frames it.
struct AsmRecord {
    func: Vec<u8>,
    #[allow(dead_code)]
    module: Vec<u8>,
    #[allow(dead_code)]
    build_id_hex: Vec<u8>,
    json: Vec<u8>,
}

fn append_source_asm_sidecar(trace_path: &str, src_paths: &[Vec<u8>], asm_records: &[AsmRecord]) {
    if src_paths.is_empty() && asm_records.is_empty() {
        return;
    }
    if let Err(e) = append_sidecar(trace_path, src_paths, asm_records) {
        eprintln!("sismo record: source/asm bundling skipped ({e})");
    }
}

fn now_ns() -> u64 {
    #[repr(C)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }
    extern "C" {
        fn clock_gettime(clk_id: i32, tp: *mut Timespec) -> i32;
    }
    const CLOCK_MONOTONIC: i32 = 6; // Darwin; on Linux MONOTONIC=1 (both fine — relative clock)
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn append_sidecar(
    trace_path: &str,
    src_paths: &[Vec<u8>],
    asm_records: &[AsmRecord],
) -> std::io::Result<()> {
    if src_paths.is_empty() && asm_records.is_empty() {
        return Ok(());
    }
    let timestamp_ns = now_ns();
    let mut out = ProtoWriter::new();
    write_track_descriptor(&mut out, timestamp_ns);

    let mut total_src: usize = 0;
    for path in src_paths {
        if total_src >= MAX_TOTAL_SRC_BYTES {
            break;
        }
        let text = match read_whole_file(path, MAX_SRC_BYTES) {
            Some(t) => t,
            None => continue,
        };
        total_src += text.len();
        write_chunked(&mut out, timestamp_ns, SRC_EVENT_NAME, b"path", path, &text);
    }

    for rec in asm_records {
        write_chunked(&mut out, timestamp_ns, ASM_EVENT_NAME, b"func", &rec.func, &rec.json);
    }

    if out.bytes().is_empty() {
        return Ok(());
    }
    append_bytes(trace_path, out.bytes())
}

fn write_track_descriptor(out: &mut ProtoWriter, timestamp_ns: u64) {
    let mut td = ProtoWriter::new();
    td.write_uint64(TD_FIELD_UUID, TRACK_UUID);
    td.write_string(TD_FIELD_NAME, TRACK_NAME);

    let mut tp = ProtoWriter::new();
    tp.write_uint64(TP_FIELD_TIMESTAMP, timestamp_ns);
    tp.write_uint32(TP_FIELD_TIMESTAMP_CLOCK_ID, BUILTIN_CLOCK_BOOTTIME);
    tp.write_uint32(TP_FIELD_TRUSTED_PACKET_SEQUENCE_ID, SEQUENCE_ID);
    tp.write_message(TP_FIELD_TRACK_DESCRIPTOR, td.bytes());
    out.write_message(TP_FIELD_TRACE_PACKET, tp.bytes());
}

/// Emit one record as one (small payload) or several (chunked) TYPE_INSTANT
/// TrackEvents. Chunked records carry debug.chunk + nchunks.
fn write_chunked(
    out: &mut ProtoWriter,
    timestamp_ns: u64,
    event_name: &[u8],
    key_name: &[u8],
    key_val: &[u8],
    payload: &[u8],
) {
    if payload.len() <= MAX_CHUNK_BYTES {
        write_event(out, timestamp_ns, event_name, key_name, key_val, payload, None, 0);
        return;
    }
    let nchunks = payload.len().div_ceil(MAX_CHUNK_BYTES) as u32;
    let mut i: u32 = 0;
    let mut off = 0usize;
    while off < payload.len() {
        let end = (off + MAX_CHUNK_BYTES).min(payload.len());
        write_event(out, timestamp_ns, event_name, key_name, key_val, &payload[off..end], Some(i), nchunks);
        off = end;
        i += 1;
    }
}

#[allow(clippy::too_many_arguments)]
fn write_event(
    out: &mut ProtoWriter,
    timestamp_ns: u64,
    event_name: &[u8],
    key_name: &[u8],
    key_val: &[u8],
    text: &[u8],
    chunk: Option<u32>,
    nchunks: u32,
) {
    let mut te = ProtoWriter::new();
    te.write_uint32(TE_FIELD_TYPE, TE_TYPE_INSTANT);
    te.write_uint64(TE_FIELD_TRACK_UUID, TRACK_UUID);
    te.write_string(TE_FIELD_NAME, event_name);
    write_string_annotation(&mut te, key_name, key_val);
    write_string_annotation(&mut te, b"text", text);
    if let Some(c) = chunk {
        write_int_annotation(&mut te, b"chunk", c);
        write_int_annotation(&mut te, b"nchunks", nchunks);
    }

    let mut tp = ProtoWriter::new();
    tp.write_uint64(TP_FIELD_TIMESTAMP, timestamp_ns);
    tp.write_uint32(TP_FIELD_TIMESTAMP_CLOCK_ID, BUILTIN_CLOCK_BOOTTIME);
    tp.write_uint32(TP_FIELD_TRUSTED_PACKET_SEQUENCE_ID, SEQUENCE_ID);
    tp.write_message(TP_FIELD_TRACK_EVENT, te.bytes());
    out.write_message(TP_FIELD_TRACE_PACKET, tp.bytes());
}

fn write_string_annotation(te: &mut ProtoWriter, name: &[u8], value: &[u8]) {
    let mut ann = ProtoWriter::new();
    ann.write_string(DA_FIELD_NAME, name);
    ann.write_string(DA_FIELD_STRING_VALUE, value);
    te.write_message(TE_FIELD_DEBUG_ANNOTATIONS, ann.bytes());
}

fn write_int_annotation(te: &mut ProtoWriter, name: &[u8], value: u32) {
    let mut ann = ProtoWriter::new();
    ann.write_string(DA_FIELD_NAME, name);
    ann.write_uint64(DA_FIELD_INT_VALUE, value as u64);
    te.write_message(TE_FIELD_DEBUG_ANNOTATIONS, ann.bytes());
}

/// Read an absolute path into a buffer, up to `max` bytes. Returns None on any
/// open/read failure or when the file is empty / larger than `max`.
fn read_whole_file(path: &[u8], max: u64) -> Option<Vec<u8>> {
    let p = std::str::from_utf8(path).ok()?;
    if !std::path::Path::new(p).is_absolute() {
        return None;
    }
    let meta = std::fs::metadata(p).ok()?;
    let size = meta.len();
    if size == 0 || size > max {
        return None;
    }
    let data = std::fs::read(p).ok()?;
    if data.len() as u64 != size {
        return None;
    }
    Some(data)
}

// ---- Tests (pure helpers + sidecar byte structure) -------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_offset_removes_trailing_offset() {
        assert_eq!(strip_offset(b"matmul +12"), b"matmul");
        assert_eq!(strip_offset(b"operator+ +0"), b"operator+");
        assert_eq!(strip_offset(b"nooffset"), b"nooffset");
    }

    #[test]
    fn os_release_id_extracts_and_unquotes() {
        assert_eq!(os_release_id("NAME=\"Fedora\"\nID=fedora\nVERSION=44\n"), Some("fedora"));
        assert_eq!(os_release_id("ID=\"ubuntu\"\n"), Some("ubuntu"));
        assert_eq!(os_release_id("NAME=nope\n"), None);
    }

    #[test]
    fn install_hint_maps_known_families() {
        assert!(["fedora", "rhel"].contains(&"fedora"));
        assert!(!["fedora", "rhel"].contains(&"gentoo"));
    }

    #[test]
    fn module_stat_status_classification() {
        let mk = |loaded, n_addrs, n_resolved| {
            let mut st = ModuleStat::new(b"x".to_vec(), Vec::new());
            st.symbols_loaded = loaded;
            st.n_addrs = n_addrs;
            st.n_resolved = n_resolved;
            st
        };
        assert!(mk(true, 10, 10).status() == Status::Ok);
        assert!(mk(true, 10, 3).status() == Status::Partial);
        assert!(mk(true, 10, 0).status() == Status::Unresolved);
        assert!(mk(false, 10, 0).status() == Status::NoSymbols);
    }

    #[test]
    fn hex_to_bytes_roundtrips_a_build_id() {
        let mut buf = [0u8; 4];
        assert_eq!(hex_to_bytes(b"1f6ed5cd", &mut buf), &[0x1f, 0x6e, 0xd5, 0xcd]);
        let mut buf2 = [0u8; 4];
        assert_eq!(hex_to_bytes(b"abc", &mut buf2).len(), 0); // odd length
    }

    #[test]
    fn write_chunked_single_record_carries_key_and_text() {
        let mut out = ProtoWriter::new();
        write_chunked(&mut out, 0, SRC_EVENT_NAME, b"path", b"/a/b.c", b"hello world");
        let bytes = out.bytes();
        assert!(find(bytes, SRC_EVENT_NAME));
        assert!(find(bytes, b"/a/b.c"));
        assert!(find(bytes, b"hello world"));
    }

    #[test]
    fn write_chunked_splits_oversized_payloads() {
        let mut out = ProtoWriter::new();
        let big = vec![b'x'; MAX_CHUNK_BYTES * 2 + 10];
        write_chunked(&mut out, 0, ASM_EVENT_NAME, b"func", b"f", &big);
        // Three chunks → the "nchunks" annotation name appears once per chunk.
        let count = count_occurrences(out.bytes(), b"nchunks");
        assert_eq!(count, 3);
    }

    fn find(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
        haystack.windows(needle.len()).filter(|w| *w == needle).count()
    }

    #[test]
    fn append_insn_json_shapes_the_object() {
        let insn = DisasmInsn { rel_pc: 4096, bytes_hex: b"90".to_vec(), text: b"nop".to_vec() };
        let mut js = Vec::new();
        append_insn_json(&mut js, &insn, 7);
        assert_eq!(js, br#"{"a":"4096","b":"90","t":"nop","l":7}"#);
        let mut js2 = Vec::new();
        append_insn_json(&mut js2, &insn, 0); // no line
        assert_eq!(js2, br#"{"a":"4096","b":"90","t":"nop"}"#);
    }
}
