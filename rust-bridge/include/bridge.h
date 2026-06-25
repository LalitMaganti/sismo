// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

// rust-bridge/include/bridge.h
//
// C ABI surface for the rust-bridge staticlib. Hand-maintained — cbindgen
// is overkill at this size. The Zig orchestrator re-declares these
// signatures inline (see src/unwinder.zig); this header is the canonical
// reference and the integration point if/when a non-Zig consumer (C++
// tests, FFI from another runtime, etc.) shows up.
//
// Symbol naming convention: `sismo_<subsystem>_<verb>` for free functions,
// `sismo_<subsystem>_t` for opaque handle typedefs.

#ifndef SISMO_BRIDGE_H
#define SISMO_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ===== CLI dispatch =======================================================
//
// Top-level `sismo` subcommand routing. The caller (Zig `main`) extracts the
// subcommand token argv[1] and passes it here; the bridge owns the help text,
// the unknown-subcommand error, and the routing decision.
//
// `cmd_utf8` is argv[1] or NULL when no subcommand was given. Matching is by
// raw bytes, so a non-UTF-8 token is just an unknown subcommand.
//
// Returns one of SISMO_CLI_*. On SISMO_CLI_HANDLED the bridge already printed
// help (or the unknown-subcommand error) to stderr and *exit_code holds the
// process exit status (0 for help, 2 for unknown). On any other value the
// caller runs that subcommand and *exit_code is untouched.
#define SISMO_CLI_HANDLED 0
#define SISMO_CLI_RECORD 1
#define SISMO_CLI_PREPARE 2
#define SISMO_CLI_SNAPSHOT 3
#define SISMO_CLI_DATASOURCE 4

int32_t sismo_cli_dispatch(const uint8_t *cmd_utf8,
                           size_t cmd_len,
                           int32_t *exit_code);

// ===== Unwinder ===========================================================
//
// One handle per profiled process. Lifecycle:
//   1. sismo_unwinder_create_arm64()  — allocate.
//   2. sismo_unwinder_add_module(...) — once per loaded mach-o image.
//   3. sismo_unwinder_walk(...)       — once per stack snapshot.
//   4. sismo_unwinder_destroy(...)    — release.
//
// `read_stack_cb` is invoked from inside `walk` to fetch 8 bytes at a
// time from the target's address space (`mach_vm_read_overwrite` on
// macOS). It must be reentrant w.r.t. the cb itself but the bridge does
// not invoke it concurrently for a single `walk` call.

typedef struct sismo_unwinder sismo_unwinder_t;

typedef int (*sismo_unwinder_read_stack_cb)(uint64_t addr,
                                            uint64_t *out_value,
                                            void *user_data);

sismo_unwinder_t *sismo_unwinder_create_arm64(void);

void sismo_unwinder_destroy(sismo_unwinder_t *u);

// Register a loaded mach-o image. `mach_o_data` should be the in-memory
// image starting at the LC_SEGMENT_64 __TEXT base (= `base_avma`).
//
// Returns:
//    0  success
//   -1  bytes don't parse as a 64-bit mach-o
//   -2  parsed, but no usable unwind sections (__unwind_info / __eh_frame)
int sismo_unwinder_add_module(sismo_unwinder_t *u,
                              uint64_t base_avma,
                              const uint8_t *mach_o_data,
                              size_t mach_o_len);

// Walk the stack. Slot 0 of `out_pcs` is always the snapshot `pc`;
// subsequent slots are return-address AVMAs. Returns the number of slots
// written (>= 1 on success; 0 on bad arguments). Stops early on the first
// iter error or when `max_pcs` slots are filled.
size_t sismo_unwinder_walk(sismo_unwinder_t *u,
                           uint64_t pc,
                           uint64_t fp,
                           uint64_t lr,
                           uint64_t sp,
                           sismo_unwinder_read_stack_cb read_stack_cb,
                           void *user_data,
                           uint64_t *out_pcs,
                           size_t max_pcs);

// Snapshot-mode walk: unwind from a captured stack-bytes buffer instead
// of live process memory. Used by the heap profiler consumer thread,
// which receives (registers + 8 KB stack snapshot) from the in-process
// client and unwinds after the fact. Same pattern as samply's
// linux_shared converter for perf_event DWARF callstacks.
//
// `snapshot_sp` is the SP value at capture time; `snapshot_bytes`
// contains [snapshot_sp .. snapshot_sp+snapshot_len) verbatim. Reads
// outside the buffer terminate the walk gracefully (truncated marker).
size_t sismo_unwinder_walk_snapshot(sismo_unwinder_t *u,
                                    uint64_t pc,
                                    uint64_t fp,
                                    uint64_t lr,
                                    uint64_t sp,
                                    const uint8_t *snapshot_bytes,
                                    size_t snapshot_len,
                                    uint64_t snapshot_sp,
                                    uint64_t *out_pcs,
                                    size_t max_pcs);

// ===== Symbolizer =========================================================
//
// One handle per symbolication session (typically one per recording).
// Lifecycle:
//   1. sismo_symbolizer_create()       — allocate (incl. tokio runtime).
//   2. sismo_symbolizer_add_module(...)— once per loaded image with a
//                                        resolvable on-disk path.
//   3. sismo_symbolizer_resolve(...)   — per AVMA, post-recording.
//   4. sismo_symbolizer_destroy(...)   — release.
//
// Module add takes a non-NUL-terminated UTF-8 path + length so callers
// don't have to allocate a NUL-terminated copy.

typedef struct sismo_symbolizer sismo_symbolizer_t;

sismo_symbolizer_t *sismo_symbolizer_create(void);

void sismo_symbolizer_destroy(sismo_symbolizer_t *s);

// Returns 0 on success (even if the binary couldn't be opened — the
// AVMA range is taken regardless, so resolves in that range return 0
// rather than falling through to an adjacent module).
// Returns -1 on bad arguments or invalid UTF-8 path.
//
// For fat archives (universal binaries) on disk, the bridge needs help
// picking the right slice. `uuid_bytes` (optional, 16 bytes) is the
// preferred mechanism — read LC_UUID from the in-memory image and pass
// here. `arch_utf8` / `arch_len` is a fallback when UUID isn't
// available; pass the architecture name of the in-memory slice
// ("arm64", "arm64e", "x86_64", "x86_64h"). UUID lookup wins because
// the on-disk fat archive's arch field doesn't reliably distinguish
// arm64e from arm64.
int sismo_symbolizer_add_module(sismo_symbolizer_t *s,
                                uint64_t base_avma,
                                uint64_t end_avma,
                                const uint8_t *path_utf8,
                                size_t path_len,
                                const uint8_t *uuid_bytes,
                                const uint8_t *arch_utf8,
                                size_t arch_len);

// Writes "<demangled_name> +<offset>" UTF-8 (no NUL) into out_utf8[..cap]
// and returns bytes written (truncated to cap on overflow). Returns 0 if
// `avma` doesn't fall in any registered module or no symbol matches.
size_t sismo_symbolizer_resolve(sismo_symbolizer_t *s,
                                uint64_t avma,
                                uint8_t *out_utf8,
                                size_t cap);

// ===== /proc/<pid>/maps reader (Linux) ====================================
//
// Parses /proc/<pid>/maps into the executable, file-backed mappings a
// sampled user PC can land in, resolving each file's GNU build-id and base
// avma. One handle per parse; the recorder re-parses to pick up dlopen()s.
//
//   1. sismo_proc_maps_parse(pid)        — read + parse (null on failure).
//   2. sismo_proc_maps_find(addr, &out)  — mapping containing addr.
//   3. sismo_proc_maps_destroy(handle)   — release.

typedef struct sismo_proc_maps sismo_proc_maps_t;

// `path`/`build_id` borrow the handle and stay valid until destroy.
typedef struct {
  uint64_t start;
  uint64_t end;
  uint64_t offset;
  uint64_t base_avma;  // avma of the file's lowest mapping (image base)
  const uint8_t *path;
  size_t path_len;
  const uint8_t *build_id;  // GNU build-id, or a 16-byte synthetic id
  size_t build_id_len;
} sismo_mapping_t;

sismo_proc_maps_t *sismo_proc_maps_parse(uint32_t pid);

void sismo_proc_maps_destroy(sismo_proc_maps_t *m);

// Fills *out with the executable file-backed mapping containing `addr`.
// Returns 1 if found (out written), 0 otherwise (out untouched).
int sismo_proc_maps_find(const sismo_proc_maps_t *m,
                         uint64_t addr,
                         sismo_mapping_t *out);

#ifdef __cplusplus
}
#endif

#endif  // SISMO_BRIDGE_H
