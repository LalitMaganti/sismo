// SPDX-License-Identifier: GPL-2.0-only
// Derived from the lightswitch profiler's BPF unwinder
// (https://github.com/javierhonduco/lightswitch, src/bpf/profiler.{h,bpf.c}
// @ 62fc32b4ce5a36d2693973a65b65649007743e3f):
//   Copyright 2022 The Parca Authors
//   Copyright 2024 The Lightswitch Authors
// The row, page, and mapping formats are byte-identical to lightswitch's, so
// the userspace conversion crate (lightswitch-unwind-info) is shared
// unmodified. Rows live in one flat mmapable array rather than a
// per-executable map-of-maps because sismo is single-process scoped. This
// header holds the formats, maps, search, and per-frame step; the tail-call
// driver programs live in sched.bpf.c. The driver MUST be a tail-call chain:
// the walker needs its own verifier budget, and a bpf_loop inside on_tick
// exceeds the one-million-instruction limit.
//
// x86-64 only.

#ifndef SISMO_SRC_C_SISMO_BPF_SISMO_UNWIND_BPF_H_
#define SISMO_SRC_C_SISMO_BPF_SISMO_UNWIND_BPF_H_

// ---- shared contract with lightswitch (keep byte-identical) ----------------

#define UNWIND_INFO_PAGE_BIT_LEN 16
#define UNWIND_INFO_PAGE_SIZE    (1 << UNWIND_INFO_PAGE_BIT_LEN)
#define PREVIOUS_PAGE(address)   ((address) - UNWIND_INFO_PAGE_SIZE)
#define HIGH_PC_MASK  0x0000FFFFFFFF0000LLU
#define LOW_PC_MASK   0x000000000000FFFFLLU
#define HIGH_PC(addr) ((addr) & HIGH_PC_MASK)
#define LOW_PC(addr)  ((addr) & LOW_PC_MASK)

#define MAX_BINARY_SEARCH_DEPTH 17

#define CFA_TYPE_RBP                   1
#define CFA_TYPE_RSP                   2
#define CFA_TYPE_UNSUP_EXP             3
#define CFA_TYPE_PLT1                  4
#define CFA_TYPE_PLT2                  5
#define CFA_TYPE_DEREF_AND_ADD         6
#define CFA_TYPE_END_OF_FDE_MARKER     7
#define CFA_TYPE_UNSUP_REGISTER_OFFSET 8
#define CFA_TYPE_OFFSET_DID_NOT_FIT    9

#define RBP_TYPE_UNCHANGED                0
#define RBP_TYPE_OFFSET                   1
#define RBP_TYPE_REGISTER                 2
#define RBP_TYPE_EXPRESSION               3
#define RBP_TYPE_UNDEFINED_RETURN_ADDRESS 4
#define RBP_TYPE_OFFSET_DID_NOT_FIT       5

#define MAPPING_TYPE_FILE 0
#define MAPPING_TYPE_ANON 1
#define MAPPING_TYPE_VDSO 2

typedef struct __attribute__((packed)) {
  unsigned short pc_low;
  unsigned char cfa_type;
  unsigned char rbp_type;
  unsigned short cfa_offset;
  short rbp_offset;
} stack_unwind_row_t;
_Static_assert(sizeof(stack_unwind_row_t) == 8, "unwind row is 8 bytes");

typedef struct {
  __u64 executable_id;
  __u64 file_offset;  // HIGH_PC bits of the object-relative pc
} page_key_t;

// Deviation from lightswitch: low/high index into the single flat row array
// (sismo is one-process scoped), not into a per-executable inner map.
typedef struct {
  __u32 low_index;
  __u32 high_index;  // exclusive
} page_value_t;

typedef struct {
  __u64 executable_id;
  __u64 load_address;
  __u64 begin;
  __u64 end;
  __u32 type;  // MAPPING_TYPE_*
} mapping_t;

// LPM trie key: match on (pid, pc-prefix), big-endian so prefix bits align.
struct exec_mappings_key {
  __u32 prefix_len;
  __s32 pid;
  __u64 data;
};
#define EXEC_MAPPINGS_PREFIX_BITS \
  ((sizeof(struct exec_mappings_key) - sizeof(__u32)) * 8)

// ---- sismo-side sizing ------------------------------------------------------

// Flat row store: 2M rows (16 MiB, mmapable so userspace bulk-writes them).
#define SISMO_UNWIND_MAX_ROWS (2 * 1024 * 1024)
// (executable, 64KiB-page) -> row-index range. A 1 GiB text segment is 16K
// pages, so this covers many large modules.
#define SISMO_UNWIND_MAX_PAGES 65536
// LPM entries for one process's executable segments (each segment costs a few
// prefix-split entries).
#define SISMO_UNWIND_MAX_MAPPINGS 4096

struct sismo_unwind_stats {
  __u64 total;        // in-kernel unwind attempts
  __u64 success;      // reached bottom-of-stack marker
  __u64 partial;      // stopped early but recovered >= 1 frame
  __u64 err_mapping;  // pc outside any registered mapping
  __u64 err_anon;     // pc in anon-exec (JIT) mapping
  __u64 err_page;     // no unwind-info page for pc
  __u64 err_search;   // binary search failed
  __u64 err_cfa;      // unsupported CFA / rbp recovery
  __u64 err_read;     // stack memory read failed
  __u64 truncated;    // frame budget exhausted
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, SISMO_UNWIND_MAX_ROWS);
  __uint(map_flags, BPF_F_MMAPABLE);
  __type(key, __u32);
  __type(value, stack_unwind_row_t);
} unwind_rows SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, SISMO_UNWIND_MAX_PAGES);
  __type(key, page_key_t);
  __type(value, page_value_t);
} unwind_pages SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, SISMO_UNWIND_MAX_MAPPINGS);
  __type(key, struct exec_mappings_key);
  __type(value, mapping_t);
} exec_mappings SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct sismo_unwind_stats);
} unwind_stats SEC(".maps");

// Recovered user PCs, leaf-first (off the 512-byte BPF stack).
struct sismo_unwind_out {
  __u64 pcs[SISMO_MAX_STACK];
};
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct sismo_unwind_out);
} unwind_out SEC(".maps");

static __always_inline struct sismo_unwind_stats *unwind_stats_get(void) {
  __u32 zero = 0;
  return bpf_map_lookup_elem(&unwind_stats, &zero);
}

static __always_inline mapping_t *unwind_find_mapping(__u32 pid, __u64 pc) {
  struct exec_mappings_key key = {};
  key.prefix_len = EXEC_MAPPINGS_PREFIX_BITS;
  key.pid = __builtin_bswap32(pid);
  key.data = __builtin_bswap64(pc);
  return bpf_map_lookup_elem(&exec_mappings, &key);
}

#define BINARY_SEARCH_NOT_FOUND 0xffffffff

// Binary-search unwind_rows[left, right) for the last row whose pc_low <=
// pc_low. Ported from lightswitch's find_offset_for_pc, on flat-array indexes.
// Unrolled like upstream: the search runs inside the dedicated tail-call
// walker program, which has the full verifier budget to itself (lightswitch's
// comment notes 6.8+ verifiers reject the rolled form in this position).
static __always_inline __u32 unwind_search(__u16 pc_low, __u32 left, __u32 right) {
  __u32 found = BINARY_SEARCH_NOT_FOUND;
#pragma unroll
  for (int i = 0; i < MAX_BINARY_SEARCH_DEPTH; i++) {
    if (left >= right)
      return found;
    __u32 mid = (left + right) / 2;
    stack_unwind_row_t *row = bpf_map_lookup_elem(&unwind_rows, &mid);
    if (!row)
      return BINARY_SEARCH_NOT_FOUND;
    if (row->pc_low <= pc_low) {
      found = mid;
      left = mid + 1;
    } else {
      right = mid;
    }
  }
  return BINARY_SEARCH_NOT_FOUND;
}

// One in-flight unwind: the register state marching up the stack.
struct sismo_unwind_run {
  __u64 ip;
  __u64 sp;
  __u64 bp;
  __u32 pid;
  __u32 n;       // frames written to unwind_out
  __u32 status;  // 0 = running, 1 = reached bottom, 2 = stopped on error
  __u32 err;     // UWERR_* failure kind (valid when status == UNWIND_FAILED)
};
#define UNWIND_RUNNING 0
#define UNWIND_DONE    1
#define UNWIND_FAILED  2
#define UNWIND_NOTRUN  3  // walk never started (kernel-context tick)

// Frames stepped per walker program invocation and the self-tail-call budget,
// mirroring lightswitch's MAX_STACK_DEPTH_PER_PROGRAM / MAX_TAIL_CALLS
// (scaled to sismo's 64-frame records; the kernel caps chains at 33).
#define SISMO_UNWIND_FRAMES_PER_PROG 7
#define SISMO_UNWIND_MAX_TAIL_CALLS  12

// Failure kinds, accounted into unwind_stats by the emitter after the walk
// finishes — one stats-map lookup per sample instead of one per error path
// inside the step, which multiplied the verifier's explored states.
#define UWERR_NONE      0
#define UWERR_MAPPING   1
#define UWERR_ANON      2
#define UWERR_PAGE      3
#define UWERR_SEARCH    4
#define UWERR_CFA       5
#define UWERR_READ      6
#define UWERR_TRUNCATED 7

// One frame step, ported from lightswitch's dwarf_unwind walker body
// (x86-64 paths only). Called from the consumer's driver — sismo's tail-call
// walker program in sched.bpf.c (lightswitch drives the same logic from its
// own tail-call chain). Returns nonzero when the walk is finished (done or
// failed); `run` carries the outcome.
// Leaf-frame fallback when the sampled pc has no unwind info (a module whose
// tables couldn't be built, e.g. -fno-asynchronous-unwind-tables): guess the
// return address at [sp] — where a frameless leaf's ra sits — push the leaf,
// and let the walk continue from the caller. framehop applies the same
// first-frame heuristic. Only ever tried for the leaf (n == 0): deeper
// frames have no such guarantee.
// Record the in-flight pc. Every non-leaf ip was derived from a real return
// address read off the stack, so it belongs in the chain even when its own
// unwind rule turns out to be unknown — framehop keeps such frames too.
static __always_inline void sismo_unwind_push_ip(struct sismo_unwind_run *run,
                                                 struct sismo_unwind_out *out) {
  if (run->n < SISMO_MAX_STACK) {
    out->pcs[run->n & (SISMO_MAX_STACK - 1)] = run->ip;
    run->n++;
  }
}

static __always_inline int sismo_unwind_leaf_guess(struct sismo_unwind_run *run,
                                                   struct sismo_unwind_out *out,
                                                   __u32 err) {
  __u64 ra = 0;
  if (run->n == 0 &&
      bpf_probe_read_user(&ra, 8, (void *)run->sp) == 0 && ra != 0) {
    out->pcs[0] = run->ip;
    run->n = 1;
    run->ip = ra - 1;
    run->sp += 8;
    return 0;  // keep walking from the guessed caller
  }
  if (run->n > 0)
    sismo_unwind_push_ip(run, out);  // a real frame with an unknown rule
  run->err = err;
  run->status = UNWIND_FAILED;
  return 1;
}

static __always_inline int sismo_unwind_step(struct sismo_unwind_run *run,
                                             struct sismo_unwind_out *out) {
  mapping_t *mapping = unwind_find_mapping(run->pid, run->ip);
  if (!mapping) {
    return sismo_unwind_leaf_guess(run, out, UWERR_MAPPING);
  }
  if (run->ip < mapping->begin || run->ip >= mapping->end) {
    run->err = UWERR_MAPPING;
    run->status = UNWIND_FAILED;
    return 1;
  }
  if (mapping->type == MAPPING_TYPE_ANON) {
    run->err = UWERR_ANON;
    run->status = UNWIND_FAILED;
    return 1;
  }

  __u64 object_relative_pc = run->ip - mapping->load_address;
  __u64 object_relative_pc_high = HIGH_PC(object_relative_pc);
  __u16 object_relative_pc_low = (__u16)LOW_PC(object_relative_pc);

  page_key_t page_key = {
      .executable_id = mapping->executable_id,
      .file_offset = object_relative_pc_high,
  };
  page_value_t *page = bpf_map_lookup_elem(&unwind_pages, &page_key);
  if (!page) {
    return sismo_unwind_leaf_guess(run, out, UWERR_PAGE);
  }

  __u32 table_idx =
      unwind_search(object_relative_pc_low, page->low_index, page->high_index);
  if (table_idx == BINARY_SEARCH_NOT_FOUND) {
    // The pc may precede this page's first row: the covering row is then the
    // last row of the range just below (lightswitch's previous-page fallback).
    __u32 prev = page->low_index;
    __u32 in_previous = 0;
    if (prev > 0) {
      prev -= 1;
      stack_unwind_row_t *previous_row = bpf_map_lookup_elem(&unwind_rows, &prev);
      if (previous_row &&
          object_relative_pc >
              PREVIOUS_PAGE(object_relative_pc_high) + previous_row->pc_low) {
        table_idx = prev;
        in_previous = 1;
      }
    }
    if (!in_previous) {
      run->err = UWERR_SEARCH;
      run->status = UNWIND_FAILED;
      return 1;
    }
  }

  stack_unwind_row_t *row = bpf_map_lookup_elem(&unwind_rows, &table_idx);
  if (!row) {
    run->status = UNWIND_FAILED;
    return 1;
  }

  __u8 cfa_type = row->cfa_type;
  __u8 rbp_type = row->rbp_type;
  // Unsigned, deliberately. The converter emits CFA offsets up to u16::MAX;
  // a 40 KiB stack frame is enough to exceed s16. Reading the field as s16,
  // as lightswitch's walker does, turns such offsets negative and computes a
  // CFA below the stack pointer.
  __u16 cfa_offset = row->cfa_offset;
  __s16 rbp_offset = row->rbp_offset;

  if (cfa_type == CFA_TYPE_END_OF_FDE_MARKER) {
    // An end-of-FDE marker means the pc has no coverage — a gap, or a module
    // whose only rows came from the crt objects. At the leaf, try the [sp]
    // guess; deeper, keep this (real) frame and stop cleanly.
    if (run->n == 0)
      return sismo_unwind_leaf_guess(run, out, UWERR_SEARCH);
    sismo_unwind_push_ip(run, out);
    run->status = UNWIND_DONE;
    return 1;
  }
  if (rbp_type == RBP_TYPE_UNDEFINED_RETURN_ADDRESS) {
    run->status = UNWIND_DONE;
    return 1;
  }
  if (cfa_type == CFA_TYPE_OFFSET_DID_NOT_FIT ||
      rbp_type == RBP_TYPE_OFFSET_DID_NOT_FIT) {
    if (run->n == 0)
      return sismo_unwind_leaf_guess(run, out, UWERR_CFA);
    run->err = UWERR_CFA;
    run->status = UNWIND_FAILED;
    return 1;
  }

  // This frame's pc is good: record it.
  if (run->n < SISMO_MAX_STACK) {
    out->pcs[run->n & (SISMO_MAX_STACK - 1)] = run->ip;
    run->n++;
  } else {
    run->err = UWERR_TRUNCATED;
    run->status = UNWIND_FAILED;
    return 1;
  }

  if (rbp_type == RBP_TYPE_REGISTER || rbp_type == RBP_TYPE_EXPRESSION) {
    run->err = UWERR_CFA;
    run->status = UNWIND_FAILED;
    return 1;
  }

  __u64 previous_rsp = 0;
  if (cfa_type == CFA_TYPE_RBP) {
    previous_rsp = run->bp + cfa_offset;
  } else if (cfa_type == CFA_TYPE_RSP) {
    previous_rsp = run->sp + cfa_offset;
  } else if (cfa_type == CFA_TYPE_DEREF_AND_ADD) {
    __u8 offset = cfa_offset >> 8;
    __u8 addition = (__u8)cfa_offset;
    if (bpf_probe_read_user(&previous_rsp, 8, (void *)(run->sp + offset)) < 0) {
      run->err = UWERR_READ;
      run->status = UNWIND_FAILED;
      return 1;
    }
    previous_rsp += addition;
  } else if (cfa_type == CFA_TYPE_PLT1 || cfa_type == CFA_TYPE_PLT2) {
    __u64 threshold = cfa_type == CFA_TYPE_PLT1 ? 11 : 10;
    previous_rsp = run->sp + 8 + ((((run->ip & 15) >= threshold)) << 3);
  } else {
    run->err = UWERR_CFA;
    run->status = UNWIND_FAILED;
    return 1;
  }
  if (previous_rsp == 0) {
    run->err = UWERR_READ;
    run->status = UNWIND_FAILED;
    return 1;
  }

  __u64 previous_rbp = run->bp;
  if (rbp_type != RBP_TYPE_UNCHANGED) {
    __u64 previous_rbp_addr = previous_rsp + rbp_offset;
    if (bpf_probe_read_user(&previous_rbp, 8, (void *)previous_rbp_addr) < 0) {
      run->err = UWERR_READ;
      run->status = UNWIND_FAILED;
      return 1;
    }
  }

  // x86-64: the return address sits 8 bytes below the previous frame's CFA.
  __u64 previous_rip = 0;
  if (bpf_probe_read_user(&previous_rip, 8, (void *)(previous_rsp - 8)) < 0) {
    run->err = UWERR_READ;
    run->status = UNWIND_FAILED;
    return 1;
  }
  // A zero return address marks the deepest frame (the x86-64 ABI's
  // outermost-frame convention, and Go's goroutine-bottom sentinel): a clean
  // bottom-of-stack, not an error. (Diverges from lightswitch, which counts
  // it as error_previous_rip_zero.)
  if (previous_rip == 0) {
    run->status = UNWIND_DONE;
    return 1;
  }

  // Point inside the caller's call instruction, not at the return site.
  run->ip = previous_rip - 1;
  run->sp = previous_rsp;
  run->bp = previous_rbp;
  return 0;
}

#endif  // SISMO_SRC_C_SISMO_BPF_SISMO_UNWIND_BPF_H_
