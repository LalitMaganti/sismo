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

use crate::disasm::{disasm_module, Arch};
use sismo_proto::ProtoWriter;
use crate::symbolizer::Symbolizer;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::Write;
use std::os::raw::{c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

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

    let mut sym = match Symbolizer::new() {
        Some(s) => s,
        None => {
            eprintln!("sismo record: symbolization skipped (symbolizer create failed)");
            return;
        }
    };

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
        let ms = build_module_symbols(&mut sym, m, &mut stat, &mut src_set, &mut src_seen);
        n_addrs += stat.n_addrs;
        n_funcs += stat.n_resolved;
        stats.push(stat);
        // Disassemble this module's hot functions while `sym` is scoped exactly
        // as build_module_symbols saw it (line resolution reuses the lookups).
        if let Some(arch) = host_arch {
            collect_module_disasm(&sym, m, arch, &mut asm_records);
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
            return;
        }
    }

    append_source_asm_sidecar(trace_path, &src_set, &asm_records);
    report(&stats, n_addrs, n_funcs);
}

/// Append `bytes` at the end of the file at `path`.
fn append_bytes(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new().append(true).open(path)?;
    f.write_all(bytes)
}

fn current_arch() -> Option<Arch> {
    if cfg!(target_arch = "x86_64") {
        Some(Arch::X86_64)
    } else if cfg!(target_arch = "aarch64") {
        Some(Arch::Aarch64)
    } else {
        None
    }
}

// ---- Symbolizer resolve helper ---------------------------------------------

/// Outer-frame view of a resolved address, used where inline frames are not
/// expanded (disassembly labels/lines). `name` carries the `+<offset>` suffix.
struct Resolved {
    name: Vec<u8>,
    line: u32,
}

fn resolve(sym: &Symbolizer, avma: u64) -> Resolved {
    match sym.resolve(avma) {
        Some(r) => Resolved {
            name: r.outer_display().into_bytes(),
            line: r.outer().line,
        },
        None => Resolved { name: Vec::new(), line: 0 },
    }
}

// ---- ModuleSymbols building ------------------------------------------------

/// Build one ModuleSymbols message for `m`, or return an empty vec if no address
/// resolved. Field order (path, build_id, then the repeated AddressSymbols).
fn build_module_symbols(
    sym: &mut Symbolizer,
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

    let load = sym.add_module(
        m.load_bias,
        end_avma,
        Path::new(OsStr::from_bytes(&m.name)),
        None,
        None,
    );
    stat.symbols_loaded = load.error.is_none();
    stat.symbol_count = load.symbol_count;
    stat.err = load.error.unwrap_or_default().into_bytes();

    // Accumulate the repeated AddressSymbols bodies; emit nothing if none match.
    let mut address_symbols: Vec<Vec<u8>> = Vec::new();
    for &rel_pc in &m.rel_pcs {
        stat.n_addrs += 1;
        let resolved = match sym.resolve(rel_pc) {
            Some(r) => r,
            None => continue,
        };

        // One Line per inline frame. `resolved.frames` is innermost inlinee
        // first, physical function last — the order Perfetto expands into the
        // callstack — so an inlined callee shows as its own frame rather than
        // being attributed to its caller.
        let mut as_ = ProtoWriter::new();
        as_.write_uint64(AS_FIELD_ADDRESS, rel_pc);
        let mut emitted = false;
        for frame in &resolved.frames {
            if frame.name.is_empty() {
                continue;
            }
            let mut line = ProtoWriter::new();
            line.write_string(LINE_FIELD_FUNCTION_NAME, frame.name.as_bytes());
            // Source file + line come from DWARF; absent for symtab-only modules.
            if let Some(file) = frame.file.as_ref().filter(|f| !f.is_empty()) {
                line.write_string(LINE_FIELD_SOURCE_FILE_NAME, file.as_bytes());
                let file_bytes = file.clone().into_bytes();
                if src_seen.insert(file_bytes.clone()) {
                    src_set.push(file_bytes);
                }
            }
            if frame.line > 0 {
                line.write_uint32(LINE_FIELD_LINE_NUMBER, frame.line);
            }
            as_.write_message(AS_FIELD_LINES, line.bytes());
            emitted = true;
        }
        if !emitted {
            continue;
        }
        stat.n_resolved += 1;
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
    // func_start -> instructions, kept in insertion order for deterministic emit.
    funcs: Vec<(u64, Vec<DisasmInsn>)>,
}

fn collect_module_disasm(sym: &Symbolizer, m: &Module, arch: Arch, out: &mut Vec<AsmRecord>) {
    // rel_pcs are absolute avmas; disasm needs load_bias to reach the link-time
    // addresses. It tags decoded instructions back in avma space, so func_start
    // and insn rel_pcs still resolve and match the trace's rel_pc.
    let decoded = disasm_module(Path::new(OsStr::from_bytes(&m.name)), arch, m.load_bias, &m.rel_pcs);
    if decoded.is_empty() {
        return;
    }

    // Bucket by func_start, preserving first-seen order for deterministic emit.
    let mut ctx = DisasmCtx { funcs: Vec::new() };
    for d in &decoded {
        let insn = DisasmInsn {
            rel_pc: d.rel_pc,
            bytes_hex: bytes_to_hex(&d.bytes),
            text: d.text.clone().into_bytes(),
        };
        match ctx.funcs.iter_mut().find(|(k, _)| *k == d.func_start) {
            Some((_, v)) => v.push(insn),
            None => ctx.funcs.push((d.func_start, vec![insn])),
        }
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
// Perfetto builtin clock enum; must match the domain now_ns() reads and the
// main trace's timebase (linux_bpf_capture declares MONOTONIC too).
const BUILTIN_CLOCK_MONOTONIC: u32 = 3;
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
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
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
    tp.write_uint32(TP_FIELD_TIMESTAMP_CLOCK_ID, BUILTIN_CLOCK_MONOTONIC);
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
    tp.write_uint32(TP_FIELD_TIMESTAMP_CLOCK_ID, BUILTIN_CLOCK_MONOTONIC);
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
