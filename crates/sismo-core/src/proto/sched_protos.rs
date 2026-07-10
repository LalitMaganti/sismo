// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! sched-producer proto encoders:
//!   - GenericKernelProcessTree (TracePacket field 122): process/thread names.
//!   - The ProtoVM `VmProgram` bytecode that mirrors those process-tree packets
//!     into traced's per-buffer DST (so long-lived thread names survive ring
//!     overwrites in flight-recorder mode).
//!
//! The VmProgram is built once from a fixed structure (no runtime inputs);
//! `sismo_macos_sched_vm_program` writes it into a caller buffer. The process
//! tree is built per-drain from flattened FFI arrays. Both are covered by
//! byte-exact tests.

use crate::proto::ProtoWriter;
use std::slice;

// ---- GenericKernelProcessTree (field 122 body) -----------------------------

/// A process entry (repr(C), from the sched worker's per-drain staging).
#[repr(C)]
pub struct ProcessC {
    pub pid: i64,
    pub ppid: i64,
    pub cmdline: *const u8,
    pub cmdline_len: usize,
}

/// A thread entry.
#[repr(C)]
pub struct ThreadC {
    pub tid: i64,
    pub pid: i64,
    pub comm: *const u8,
    pub comm_len: usize,
    pub is_main_thread: bool,
    pub is_idle: bool,
}

unsafe fn opt_slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(ptr, len) }
    }
}

fn encode_process(p: &ProcessC) -> Vec<u8> {
    let mut w = ProtoWriter::new();
    w.write_int64(1, p.pid); // Process.pid
    if p.ppid != 0 {
        w.write_int64(2, p.ppid);
    }
    let cmdline = unsafe { opt_slice(p.cmdline, p.cmdline_len) };
    if !cmdline.is_empty() {
        w.write_string(3, cmdline);
    }
    w.bytes().to_vec()
}

fn encode_thread(t: &ThreadC) -> Vec<u8> {
    let mut w = ProtoWriter::new();
    w.write_int64(1, t.tid); // Thread.tid
    w.write_int64(2, t.pid);
    let comm = unsafe { opt_slice(t.comm, t.comm_len) };
    if !comm.is_empty() {
        w.write_string(3, comm);
    }
    if t.is_main_thread {
        w.write_uint32(4, 1);
    }
    if t.is_idle {
        w.write_uint32(5, 1);
    }
    w.bytes().to_vec()
}

/// Encode a GenericKernelProcessTree payload: repeated Process (field 1) then
/// repeated Thread (field 2). Writes into out[..cap]; returns the length, or 0
/// if too small.
///
/// # Safety
/// `processes`/`threads` valid for their counts (and each embedded
/// cmdline/comm pointer valid for its len or null); `out` writable for `cap`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_encode_kernel_process_tree(
    processes: *const ProcessC,
    n_processes: usize,
    threads: *const ThreadC,
    n_threads: usize,
    out: *mut u8,
    cap: usize,
) -> usize {
    let procs: &[ProcessC] =
        if processes.is_null() { &[] } else { unsafe { slice::from_raw_parts(processes, n_processes) } };
    let thrs: &[ThreadC] =
        if threads.is_null() { &[] } else { unsafe { slice::from_raw_parts(threads, n_threads) } };

    let mut w = ProtoWriter::new();
    for p in procs {
        w.write_message(1, &encode_process(p));
    }
    for t in thrs {
        w.write_message(2, &encode_thread(t));
    }
    let b = w.bytes();
    if b.len() > cap {
        return 0;
    }
    unsafe { std::ptr::copy_nonoverlapping(b.as_ptr(), out, b.len()) };
    b.len()
}

// ---- ProtoVM VmProgram (fixed macos_sched program) -------------------------

// Cursor enum values.
const CURSOR_UNSPECIFIED: u32 = 0;
const CURSOR_DST: u32 = 2;

// AbortLevel: 0 = unset (leave field absent), 1 = SKIP_CURRENT.
const ABORT_UNSET: u32 = 0;
const ABORT_SKIP_CURRENT: u32 = 1;

#[derive(Default)]
struct PathComponent {
    field_id: Option<u32>,
    array_index: Option<u32>,
    map_key_field_id: Option<u32>,
    is_repeated: bool,
    register_to_match: Option<u32>,
    store_foreach_index_into_register: Option<u32>,
}

struct Select {
    cursor: u32,
    relative_path: Vec<PathComponent>,
    create_if_not_exist: bool,
}

enum Op {
    Select(Select),
    RegLoad { cursor: u32, dst_register: u32 },
    Merge { skip_submessages: bool },
    // Set/Del complete the VmInstruction oneof for fidelity with the schema;
    // the macos_sched program doesn't use them (exercised only in tests).
    #[allow(dead_code)]
    Set,
    #[allow(dead_code)]
    Del,
}

struct Instruction {
    op: Op,
    abort_level: u32,
    nested: Vec<Instruction>,
}

impl Instruction {
    fn new(op: Op) -> Self {
        Instruction { op, abort_level: ABORT_UNSET, nested: Vec::new() }
    }
    fn with_abort(mut self, level: u32) -> Self {
        self.abort_level = level;
        self
    }
    fn with_nested(mut self, nested: Vec<Instruction>) -> Self {
        self.nested = nested;
        self
    }
}

fn encode_path_component(pc: &PathComponent) -> Vec<u8> {
    let mut w = ProtoWriter::new();
    if let Some(v) = pc.field_id {
        w.write_uint32(1, v);
    }
    if let Some(v) = pc.array_index {
        w.write_uint32(2, v);
    }
    if let Some(v) = pc.map_key_field_id {
        w.write_uint32(3, v);
    }
    if pc.is_repeated {
        w.write_uint32(5, 1);
    }
    if let Some(v) = pc.register_to_match {
        w.write_uint32(6, v);
    }
    if let Some(v) = pc.store_foreach_index_into_register {
        w.write_uint32(7, v);
    }
    w.bytes().to_vec()
}

fn encode_select(s: &Select) -> Vec<u8> {
    let mut w = ProtoWriter::new();
    if s.cursor != CURSOR_UNSPECIFIED {
        w.write_uint32(1, s.cursor);
    }
    for pc in &s.relative_path {
        w.write_message(2, &encode_path_component(pc));
    }
    if s.create_if_not_exist {
        w.write_uint32(3, 1);
    }
    w.bytes().to_vec()
}

fn encode_instruction(ins: &Instruction) -> Vec<u8> {
    let mut w = ProtoWriter::new();
    match &ins.op {
        Op::Select(s) => w.write_message(1, &encode_select(s)),
        Op::RegLoad { cursor, dst_register } => {
            let mut r = ProtoWriter::new();
            if *cursor != CURSOR_UNSPECIFIED {
                r.write_uint32(1, *cursor);
            }
            r.write_uint32(2, *dst_register);
            w.write_message(2, r.bytes());
        }
        Op::Merge { skip_submessages } => {
            let mut m = ProtoWriter::new();
            if *skip_submessages {
                m.write_uint32(1, 1);
            }
            w.write_message(3, m.bytes());
        }
        Op::Set => w.write_message(4, &[]),
        Op::Del => w.write_message(5, &[]),
    }
    if ins.abort_level != ABORT_UNSET {
        w.write_uint32(6, ins.abort_level);
    }
    for n in &ins.nested {
        w.write_message(7, &encode_instruction(n));
    }
    w.bytes().to_vec()
}

fn encode_vm_program(version: u32, instructions: &[Instruction]) -> Vec<u8> {
    let mut w = ProtoWriter::new();
    if version != 0 {
        w.write_uint32(1, version);
    }
    for ins in instructions {
        w.write_message(2, &encode_instruction(ins));
    }
    w.bytes().to_vec()
}

/// Build the fixed macos_sched ProtoVM program bytes (mirrors
/// GenericKernelProcessTree packets into traced's DST, keyed under field 122).
fn build_macos_sched_vm_program() -> Vec<u8> {
    const TP_TREE: u32 = 122; // TracePacket.generic_kernel_process_tree
    const F_PROCESSES: u32 = 1;
    const F_THREADS: u32 = 2;
    const F_PROCESS_PID: u32 = 1;
    const F_THREAD_TID: u32 = 1;
    const REG: u32 = 0;

    // A "foreach <coll>: read <key> -> R0; select-or-create DST[<key>=R0]; merge"
    // block, shared shape for processes and threads.
    let make_block = |coll_field: u32, key_field: u32| -> Instruction {
        Instruction::new(Op::Select(Select {
            cursor: CURSOR_UNSPECIFIED,
            relative_path: vec![PathComponent {
                field_id: Some(coll_field),
                is_repeated: true,
                ..Default::default()
            }],
            create_if_not_exist: false,
        }))
        .with_abort(ABORT_SKIP_CURRENT)
        .with_nested(vec![
            // Read <key> into R0.
            Instruction::new(Op::Select(Select {
                cursor: CURSOR_UNSPECIFIED,
                relative_path: vec![PathComponent { field_id: Some(key_field), ..Default::default() }],
                create_if_not_exist: false,
            }))
            .with_nested(vec![Instruction::new(Op::RegLoad {
                cursor: CURSOR_UNSPECIFIED,
                dst_register: REG,
            })]),
            // Select-or-create DST.tree.<coll>[<key>=R0], merge SRC into it.
            Instruction::new(Op::Select(Select {
                cursor: CURSOR_DST,
                create_if_not_exist: true,
                relative_path: vec![
                    PathComponent { field_id: Some(TP_TREE), ..Default::default() },
                    PathComponent { field_id: Some(coll_field), ..Default::default() },
                    PathComponent {
                        map_key_field_id: Some(key_field),
                        register_to_match: Some(REG),
                        ..Default::default()
                    },
                ],
            }))
            .with_nested(vec![Instruction::new(Op::Merge { skip_submessages: false })]),
        ])
    };

    let top = Instruction::new(Op::Select(Select {
        cursor: CURSOR_UNSPECIFIED,
        relative_path: vec![PathComponent { field_id: Some(TP_TREE), ..Default::default() }],
        create_if_not_exist: false,
    }))
    .with_nested(vec![
        make_block(F_PROCESSES, F_PROCESS_PID),
        make_block(F_THREADS, F_THREAD_TID),
    ]);

    encode_vm_program(0, &[top])
}

/// Write the fixed macos_sched ProtoVM program into `out[..cap]`. Returns the
/// length, or 0 if too small.
///
/// # Safety
/// `out` must be writable for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sismo_macos_sched_vm_program(out: *mut u8, cap: usize) -> usize {
    let b = build_macos_sched_vm_program();
    if b.len() > cap {
        return 0;
    }
    unsafe { std::ptr::copy_nonoverlapping(b.as_ptr(), out, b.len()) };
    b.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_process_tree_single_thread_bytes_are_exact() {
        let comm = b"hi";
        let threads = [ThreadC {
            tid: 7,
            pid: 3,
            comm: comm.as_ptr(),
            comm_len: comm.len(),
            is_main_thread: false,
            is_idle: false,
        }];
        let mut out = [0u8; 64];
        let n = unsafe {
            sismo_encode_kernel_process_tree(
                std::ptr::null(),
                0,
                threads.as_ptr(),
                threads.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        // Thread submessage at field 2: outer 12 08, body 08 07 10 03 1a 02 'h' 'i'.
        assert_eq!(
            &out[..n],
            &[0x12, 0x08, 0x08, 0x07, 0x10, 0x03, 0x1a, 0x02, b'h', b'i']
        );
    }

    #[test]
    fn vm_program_matches_reference_serialization() {
        // Reference bytes from a protos::gen::VmProgram of the same structure,
        // SerializeAsString()'d + hex-dumped — the byte-exact contract.
        let expected_hex = concat!(
            "126e0a041202087a3a320a0612040801280130013a0c0a04120208013a041",
            "20210003a180a1208021202087a1202080112041801300018013a021a003",
            "a320a0612040802280130013a0c0a04120208013a04120210003a180a120",
            "8021202087a1202080212041801300018013a021a00",
        );
        let mut out = [0u8; 4096];
        let n = unsafe { sismo_macos_sched_vm_program(out.as_mut_ptr(), out.len()) };
        let got: String = out[..n].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, expected_hex);
    }

    #[test]
    fn vm_program_del_instruction_bytes() {
        let bytes = encode_vm_program(0, &[Instruction::new(Op::Del)]);
        // instr(2) len 2, del(5) len 0: 12 02 2a 00.
        assert_eq!(bytes, &[0x12, 0x02, 0x2a, 0x00]);
    }
}
