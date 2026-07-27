// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Userspace side of the in-kernel DWARF unwinder.
//!
//! Converts each target module's `.eh_frame` into lightswitch's compact unwind
//! rows (via the upstream `lightswitch-unwind-info` crate, unmodified) and
//! loads them into the BPF maps `sismo_unwind.bpf.h` declares:
//!
//! - `unwind_rows`: one flat mmapable array of 8-byte rows (all modules
//!   concatenated; sismo is single-process scoped so no per-executable
//!   map-of-maps like lightswitch's fleet-wide layout),
//! - `unwind_pages`: (executable_id, 64KiB-page) -> row index range,
//! - `exec_mappings`: LPM trie (pid, pc-prefix) -> mapping, same key/value
//!   encoding as lightswitch so the BPF-side lookup logic is shared.
//!
//! Loading is idempotent per module image base and runs on the capture worker
//! (from ensure_maps/reparse), mirroring lightswitch's lazy on-demand loads:
//! until a module's tables land, the in-kernel walk fails on its frames and
//! the sample keeps the frame-pointer stack.

use std::collections::HashSet;
use std::os::raw::{c_int, c_void};

use crate::cpu::linux_bpf_capture::{
    bpf_map__fd, bpf_object__find_map_by_name, bpf_map_update_elem, libbpf_num_possible_cpus,
    BpfObject,
};
use crate::symbolize::proc_maps::{Mapping, ProcMaps};
use lightswitch_unwind_info::compact_unwind_info;
use lightswitch_unwind_info::pages::to_pages;
use lightswitch_unwind_info::types::CompactUnwindRow;

// Mirrors of the sismo_unwind.bpf.h structs (which are byte-identical to
// lightswitch's stack_unwind_row_t / page_key_t / page_value_t / mapping_t /
// exec_mappings_key).

pub const SISMO_UNWIND_MAX_ROWS: usize = 2 * 1024 * 1024;

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct StackUnwindRow {
    pc_low: u16,
    cfa_type: u8,
    rbp_type: u8,
    cfa_offset: u16,
    rbp_offset: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PageKey {
    executable_id: u64,
    file_offset: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PageValue {
    low_index: u32,
    high_index: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BpfMapping {
    executable_id: u64,
    load_address: u64,
    begin: u64,
    end: u64,
    r#type: u32,
}

const MAPPING_TYPE_FILE: u32 = 0;
const MAPPING_TYPE_VDSO: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct ExecMappingsKey {
    prefix_len: u32,
    pid: i32,
    data: u64,
}

impl ExecMappingsKey {
    // Matches lightswitch's exec_mappings_key::new: pid + address stored
    // big-endian so the trie's prefix bits line up with address bits.
    fn new(pid: u32, address: u64, prefix_len: u32) -> ExecMappingsKey {
        ExecMappingsKey {
            prefix_len,
            pid: (pid as i32).to_be(),
            data: address.to_be(),
        }
    }
}

/// Aggregated `struct sismo_unwind_stats` (summed across CPUs).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct UnwindStats {
    pub total: u64,
    pub success: u64,
    pub partial: u64,
    pub err_mapping: u64,
    pub err_anon: u64,
    pub err_page: u64,
    pub err_search: u64,
    pub err_cfa: u64,
    pub err_read: u64,
    pub truncated: u64,
}

extern "C" {
    // <bpf/bpf.h> syscall wrapper (fd-based, like the update_elem already used).
    fn bpf_map_lookup_elem(fd: c_int, key: *const c_void, value: *mut c_void) -> c_int;
}

/// One address block of a longest-prefix-match decomposition.
/// Ported from lightswitch's `summarize_address_range` (src/util/lpm.rs, MIT):
/// split [low, high] into power-of-two aligned blocks so an LPM trie lookup of
/// any address in the range finds exactly one entry.
fn summarize_address_range(low: u64, high: u64) -> Vec<(u64, u32)> {
    let mut res = Vec::new();
    let mut curr = low;
    while curr <= high {
        let number_of_bits = std::cmp::min(
            curr.trailing_zeros(),
            (64 - (high - curr + 1).leading_zeros()) - 1,
        );
        res.push((curr, 64 - number_of_bits));
        curr += 1 << number_of_bits;
        if curr - 1 == u64::MAX {
            break;
        }
    }
    res
}

/// Precise unwind rows for a Go binary from its `.gopclntab` pcsp tables:
/// CFA = rsp + framesize + 8 (the call's pushed return address) at every pc,
/// rbp untouched. `None` when the file isn't a recognizable Go binary.
fn go_unwind_rows(path: &str) -> Option<Vec<CompactUnwindRow>> {
    use lightswitch_unwind_info::types::{CfaType, RbpType};
    let go = crate::symbolize::gopclntab::GoPclntab::from_path(path)?;
    let segs = go.pcsp_rows();
    if segs.is_empty() {
        return None;
    }
    let mut rows = Vec::with_capacity(segs.len());
    for (pc, fs) in segs {
        let row = match fs {
            // Table end / uncovered pc: stop the walk cleanly.
            None => CompactUnwindRow {
                pc,
                cfa_type: CfaType::EndFdeMarker,
                rbp_type: RbpType::Unchanged,
                cfa_offset: 0,
                rbp_offset: 0,
            },
            Some(fs) if fs < 0 || (fs as i64 + 8) > u16::MAX as i64 => CompactUnwindRow {
                pc,
                cfa_type: CfaType::OffsetDidNotFit,
                rbp_type: RbpType::Unchanged,
                cfa_offset: 0,
                rbp_offset: 0,
            },
            Some(fs) => CompactUnwindRow {
                pc,
                cfa_type: CfaType::StackPointerOffset,
                rbp_type: RbpType::Unchanged,
                cfa_offset: (fs as u32 + 8) as u16,
                rbp_offset: 0,
            },
        };
        rows.push(row);
    }
    Some(rows)
}

/// The `[vdso]` mapping range from `/proc/<pid>/maps`, if present.
fn vdso_range(pid: u32) -> Option<(u64, u64)> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    for line in text.lines() {
        if !line.ends_with("[vdso]") {
            continue;
        }
        let range = line.split_whitespace().next()?;
        let (s, e) = range.split_once('-')?;
        return Some((
            u64::from_str_radix(s, 16).ok()?,
            u64::from_str_radix(e, 16).ok()?,
        ));
    }
    None
}

/// ELF e_type from the file header: ET_EXEC (2) loads at its link address, so
/// the unwind rows' pcs are already absolute and the BPF-side load_address
/// ("bias") is 0; ET_DYN links at 0, so the bias is the image base.
fn elf_load_bias(path: &str, base_avma: u64) -> Option<u64> {
    let mut hdr = [0u8; 18];
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    f.read_exact(&mut hdr).ok()?;
    if &hdr[..4] != b"\x7fELF" {
        return None;
    }
    match u16::from_le_bytes([hdr[16], hdr[17]]) {
        2 => Some(0),         // ET_EXEC
        3 => Some(base_avma), // ET_DYN
        _ => None,
    }
}

pub struct UnwindTables {
    pages_fd: c_int,
    mappings_fd: c_int,
    stats_fd: c_int,
    rows: *mut StackUnwindRow, // mmap of the unwind_rows BPF array
    rows_len: usize,           // mmap length in bytes
    next_row: usize,
    target_pid: u32,
    // Module image bases whose tables are already loaded (or failed: negative
    // results cached too — a module without usable .eh_frame never retries).
    loaded: HashSet<u64>,
    pub modules_loaded: u64,
    pub rows_loaded: u64,
}

// The raw mmap pointer confines this to the capture worker thread, which is
// the only place load_all runs (same discipline as the rest of Capture).
unsafe impl Send for UnwindTables {}

fn map_fd(obj: *mut BpfObject, name: &std::ffi::CStr) -> Option<c_int> {
    let m = unsafe { bpf_object__find_map_by_name(obj, name.as_ptr()) };
    if m.is_null() {
        return None;
    }
    let fd = unsafe { bpf_map__fd(m) };
    if fd < 0 {
        None
    } else {
        Some(fd)
    }
}

impl UnwindTables {
    /// Locate the unwinder's maps on the loaded BPF object and mmap the row
    /// array. None if any map is missing or the mmap fails.
    pub fn new(obj: *mut BpfObject, target_pid: u32) -> Option<UnwindTables> {
        let rows_fd = map_fd(obj, c"unwind_rows")?;
        let pages_fd = map_fd(obj, c"unwind_pages")?;
        let mappings_fd = map_fd(obj, c"exec_mappings")?;
        let stats_fd = map_fd(obj, c"unwind_stats")?;

        let page = 4096usize;
        let len = (SISMO_UNWIND_MAX_ROWS * std::mem::size_of::<StackUnwindRow>())
            .next_multiple_of(page);
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                rows_fd,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return None;
        }
        Some(UnwindTables {
            pages_fd,
            mappings_fd,
            stats_fd,
            rows: ptr as *mut StackUnwindRow,
            rows_len: len,
            next_row: 0,
            target_pid,
            loaded: HashSet::new(),
            modules_loaded: 0,
            rows_loaded: 0,
        })
    }

    /// Load tables for every module in `maps` not yet loaded. Idempotent;
    /// called from ensure_maps/reparse on the capture worker.
    pub fn load_all(&mut self, maps: &ProcMaps) {
        // Group the executable segments by module image base.
        let mut by_module: std::collections::HashMap<u64, Vec<&Mapping>> =
            std::collections::HashMap::new();
        for m in maps.mappings() {
            by_module.entry(m.base_avma).or_default().push(m);
        }
        for (base, segs) in by_module {
            if self.loaded.contains(&base) {
                continue;
            }
            self.loaded.insert(base);
            self.load_module(base, &segs);
        }
        self.load_vdso();
    }

    fn load_module(&mut self, base_avma: u64, segs: &[&Mapping]) {
        let path = segs[0].path.clone();
        // ProcMaps only carries file-backed mappings; the vdso is handled
        // separately in load_vdso (it has no file to parse).
        if path.starts_with('[') || path.is_empty() {
            return;
        }
        // Go binaries carry .eh_frame that does not describe the real frame
        // layout (lightswitch refuses it too, synthesizing blanket FP rows
        // instead). sismo can do better: its .gopclntab parser decodes the
        // pcsp frame-size tables, which give the EXACT frame size at every
        // pc — including frameless leaves, where blanket FP rows would skip
        // the caller. Rows are image-relative, so the load bias is base_avma
        // regardless of ET_EXEC/ET_DYN.
        let (rows, load_address) = if let Some(rows) = go_unwind_rows(&path) {
            (rows, base_avma)
        } else {
            let Some(bias) = elf_load_bias(&path, base_avma) else {
                return;
            };
            match compact_unwind_info(&path, None) {
                Ok(rows) => (rows, bias),
                Err(e) => {
                    tracing::debug!(path, err = %e, "unwind-info conversion failed");
                    return;
                }
            }
        };
        let ranges: Vec<(u64, u64)> = segs.iter().map(|s| (s.start, s.end)).collect();
        self.install_rows(&path, base_avma, load_address, &rows, &ranges, MAPPING_TYPE_FILE);
    }

    /// The vDSO has no backing file, but its image is the same kernel-provided
    /// blob in every process (only the base varies with ASLR) — so dump our
    /// OWN vdso via AT_SYSINFO_EHDR, convert it like any ELF, and register the
    /// tables at the TARGET's vdso base. Same approach as lightswitch's
    /// fetch_vdso_info, minus the /proc/<pid>/mem read (which would need
    /// ptrace rights sismo doesn't hold).
    fn load_vdso(&mut self) {
        let Some((start, end)) = vdso_range(self.target_pid) else {
            return;
        };
        if self.loaded.contains(&start) {
            return;
        }
        self.loaded.insert(start);

        let own_base = unsafe { libc::getauxval(libc::AT_SYSINFO_EHDR) } as u64;
        let Some((own_start, own_end)) = vdso_range(std::process::id()) else {
            return;
        };
        if own_base != own_start || own_end <= own_start {
            return;
        }
        // Same blob in every process; still, only read what OUR mapping spans.
        let span = ((end - start).min(own_end - own_start)) as usize;
        let bytes = unsafe { std::slice::from_raw_parts(own_base as *const u8, span) };
        let tmp = std::env::temp_dir().join(format!("sismo-vdso-{}", std::process::id()));
        if std::fs::write(&tmp, bytes).is_err() {
            return;
        }
        let rows = compact_unwind_info(&tmp.to_string_lossy(), None);
        let _ = std::fs::remove_file(&tmp);
        let rows = match rows {
            Ok(rows) => rows,
            Err(e) => {
                tracing::debug!(err = %e, "vdso unwind-info conversion failed");
                return;
            }
        };
        // ET_DYN: the load bias is the target's vdso base.
        self.install_rows("[vdso]", start, start, &rows, &[(start, end)], MAPPING_TYPE_VDSO);
    }

    fn install_rows(
        &mut self,
        path: &str,
        executable_id: u64,
        load_address: u64,
        rows: &[CompactUnwindRow],
        ranges: &[(u64, u64)],
        mapping_type: u32,
    ) {
        if rows.is_empty() || self.next_row + rows.len() > SISMO_UNWIND_MAX_ROWS {
            tracing::warn!(
                path,
                rows = rows.len(),
                used = self.next_row,
                "unwind rows empty or table full; module not loaded"
            );
            return;
        }

        // 1. Rows into the mmap'd flat array (readable by BPF the moment the
        //    page/mapping entries below land — ordering matters).
        let start = self.next_row;
        for (i, row) in rows.iter().enumerate() {
            let pc = row.pc;
            let wire = StackUnwindRow {
                pc_low: (pc & 0xffff) as u16,
                cfa_type: row.cfa_type as u8,
                rbp_type: row.rbp_type as u8,
                cfa_offset: row.cfa_offset,
                rbp_offset: row.rbp_offset,
            };
            unsafe { self.rows.add(start + i).write(wire) };
        }
        self.next_row += rows.len();

        // 2. Page index: 64KiB-page -> global row index range. `to_pages`
        //    indexes are relative to this module's slice; rebase them.
        for page in to_pages(rows) {
            let key = PageKey { executable_id, file_offset: page.address };
            let val = PageValue {
                low_index: start as u32 + page.low_index,
                high_index: start as u32 + page.high_index,
            };
            let rc = unsafe {
                bpf_map_update_elem(
                    self.pages_fd,
                    &key as *const PageKey as *const c_void,
                    &val as *const PageValue as *const c_void,
                    0,
                )
            };
            if rc != 0 {
                tracing::warn!(path, "unwind page insert failed; module partially loaded");
                return;
            }
        }

        // 3. LPM mapping entries last: they make the module visible to the
        //    BPF walker.
        for &(seg_start, seg_end) in ranges {
            let mapping = BpfMapping {
                executable_id,
                load_address,
                begin: seg_start,
                end: seg_end,
                r#type: mapping_type,
            };
            for (addr, prefix_len) in summarize_address_range(seg_start, seg_end - 1) {
                let key = ExecMappingsKey::new(self.target_pid, addr, 32 + prefix_len);
                let rc = unsafe {
                    bpf_map_update_elem(
                        self.mappings_fd,
                        &key as *const ExecMappingsKey as *const c_void,
                        &mapping as *const BpfMapping as *const c_void,
                        0,
                    )
                };
                if rc != 0 {
                    tracing::warn!(path, "unwind LPM insert failed");
                    return;
                }
            }
        }

        self.modules_loaded += 1;
        self.rows_loaded += rows.len() as u64;
        tracing::info!(path, rows = rows.len(), base = format_args!("{executable_id:#x}"),
            "unwind tables loaded");
    }

    /// Read + sum the per-CPU unwinder stats.
    pub fn read_stats(&self) -> UnwindStats {
        let ncpu = unsafe { libbpf_num_possible_cpus() }.max(1) as usize;
        let mut buf = vec![UnwindStats::default(); ncpu];
        let zero: u32 = 0;
        let rc = unsafe {
            bpf_map_lookup_elem(
                self.stats_fd,
                &zero as *const u32 as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
            )
        };
        let mut sum = UnwindStats::default();
        if rc != 0 {
            return sum;
        }
        for s in &buf {
            sum.total += s.total;
            sum.success += s.success;
            sum.partial += s.partial;
            sum.err_mapping += s.err_mapping;
            sum.err_anon += s.err_anon;
            sum.err_page += s.err_page;
            sum.err_search += s.err_search;
            sum.err_cfa += s.err_cfa;
            sum.err_read += s.err_read;
            sum.truncated += s.truncated;
        }
        sum
    }
}

impl Drop for UnwindTables {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.rows as *mut c_void, self.rows_len) };
    }
}

/// Runs the table loader on its own thread. Converting `.eh_frame` takes long
/// enough under load that doing it on the ring-drain worker stalls draining
/// and overflows the sample ring — samples get dropped at the source. The
/// worker just pings this thread when the module set may have changed; the
/// thread parses the target's maps itself and loads idempotently.
pub struct UnwindLoader {
    ping: std::sync::mpsc::Sender<()>,
    handle: std::thread::JoinHandle<UnwindTables>,
}

impl UnwindLoader {
    /// Spawn the loader; it loads the current module set immediately, then
    /// reloads on every ping until [`UnwindLoader::join`].
    pub fn spawn(mut tables: UnwindTables) -> UnwindLoader {
        let (ping, rx) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            let pid = tables.target_pid;
            if let Some(maps) = ProcMaps::parse(pid) {
                tables.load_all(&maps);
            }
            while rx.recv().is_ok() {
                // Coalesce queued pings into one reload.
                while rx.try_recv().is_ok() {}
                if let Some(maps) = ProcMaps::parse(pid) {
                    tables.load_all(&maps);
                }
            }
            tables
        });
        UnwindLoader { ping, handle }
    }

    /// Ask for a reload (non-blocking; pings coalesce).
    pub fn ping(&self) {
        let _ = self.ping.send(());
    }

    /// Stop the thread and hand back the tables (for the final stats read).
    pub fn join(self) -> Option<UnwindTables> {
        drop(self.ping);
        self.handle.join().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_matches_lightswitch_semantics() {
        // Every address in [low, high] must be covered by exactly one block.
        let (low, high) = (0x7f001234u64, 0x7f00abcdu64);
        let blocks = summarize_address_range(low, high);
        for addr in (low..=high).step_by(97) {
            let covering = blocks
                .iter()
                .filter(|(base, prefix)| {
                    let bits = 64 - prefix;
                    (addr >> bits) == (base >> bits)
                })
                .count();
            assert_eq!(covering, 1, "addr {addr:#x}");
        }
    }

    // Debug aid: DUMP_BIN=<path> DUMP_LO=<hex> DUMP_HI=<hex> prints converted
    // rows in [lo, hi). Not a real test; no-op without the env vars.
    #[test]
    fn dump_rows_for_env() {
        let (Ok(bin), Ok(lo), Ok(hi)) = (
            std::env::var("DUMP_BIN"),
            std::env::var("DUMP_LO"),
            std::env::var("DUMP_HI"),
        ) else {
            return;
        };
        let lo = u64::from_str_radix(&lo, 16).unwrap();
        let hi = u64::from_str_radix(&hi, 16).unwrap();
        let rows = compact_unwind_info(&bin, None).unwrap();
        for r in &rows {
            let (pc, ct, co, rt, ro) =
                (r.pc, r.cfa_type, r.cfa_offset, r.rbp_type, r.rbp_offset);
            if pc >= lo && pc < hi {
                eprintln!("pc={pc:#x} cfa_type={ct:?} cfa_off={co} rbp_type={rt:?} rbp_off={ro}");
            }
        }
    }

    #[test]
    fn converts_own_vdso() {
        let (s, e) = vdso_range(std::process::id()).expect("vdso in own maps");
        let base = unsafe { libc::getauxval(libc::AT_SYSINFO_EHDR) } as u64;
        assert_eq!(base, s, "auxv vdso base matches maps");
        let bytes = unsafe { std::slice::from_raw_parts(base as *const u8, (e - s) as usize) };
        let tmp = std::env::temp_dir().join(format!("sismo-vdso-test-{}", std::process::id()));
        std::fs::write(&tmp, bytes).unwrap();
        let rows = compact_unwind_info(&tmp.to_string_lossy(), None);
        let _ = std::fs::remove_file(&tmp);
        let rows = rows.expect("vdso image should convert");
        assert!(!rows.is_empty());
    }

    #[test]
    fn converts_own_binary() {
        // The test binary itself must have .eh_frame convertible end-to-end.
        let path = std::env::current_exe().unwrap();
        let rows = compact_unwind_info(path.to_str().unwrap(), None).unwrap();
        assert!(rows.len() > 100, "expected real unwind info, got {}", rows.len());
        assert!(rows.is_sorted_by(|a, b| {
            let (pa, pb) = (a.pc, b.pc);
            pa <= pb
        }));
        let pages = to_pages(&rows);
        assert!(!pages.is_empty());
    }
}
