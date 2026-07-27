# Symbolization: one pass, two capture backends

sismo symbolizes native frames the same way on every platform: the capture
backend emits *coordinates* (a module identity + an address), and one shared
post-record pass — `perf_symbolize::symbolize_trace`, also runnable offline as
`sismo symbolize <trace>` — resolves them to demangled names, inline chains,
and source lines, appending `ModuleSymbols` packets to the trace in place.
This doc is the shared contract and how each backend produces it. Keep the
backends in sync with this doc.

## The contract

Every native frame in the trace must be resolvable from the trace alone plus
the module's bytes. That means each mapping carries:

| field | meaning |
| --- | --- |
| `path` | best known original path, or `[buildid:<full hex>]` when unknown |
| `build_id` | the module's *identity* (see table below) — never empty for a sampled file-backed module |
| `address_kind` | `VIRTUAL_ADDRESS` or `FILE_OFFSET`; never inferred from another field |
| `load_bias` | for virtual coordinates, the value subtracted before lookup |
| `start`/`end` | the avma range for virtual mappings; zero for whole-file build-id mappings |

The pass groups unsymbolized frames by `(path, build_id, load_bias, address_kind)` (via a
trace_processor query — `sismo_trace_query.cc` mirrors trace_processor's own
`kQueryUnsymbolized` so the emitted `AddressSymbols.address` always matches
`spf.rel_pc`), loads each module's bytes, and resolves either `rel_pc -
load_bias` or a file offset translated through the executable's `PT_LOAD`
headers. `ModuleSymbols.AddressSymbols.address` always remains the original
`spf.rel_pc` in both modes.

## Address conventions

| | Linux build-id mapping | Virtual mapping (macOS, kernel, residual/id-less Linux) |
| --- | --- | --- |
| `address_kind` | `FILE_OFFSET` | `VIRTUAL_ADDRESS` |
| frame `rel_pc` | ELF file offset from `BPF_F_USER_BUILD_ID` | absolute/synthetic PC |
| lookup | `p_vaddr + (rel_pc - p_offset)` through executable `PT_LOAD` | `rel_pc - load_bias` |

Linux normal file-backed frames are whole-file mappings keyed by their 20-byte
build ID and survive target exit. Per-frame `BPF_STACK_BUILD_ID_IP` fallbacks
remain raw for anonymous/JIT/id-less/contended cases; live file-backed raw PCs
are normalized to file offsets before interning.

## Module identity

| | Linux | macOS |
| --- | --- | --- |
| real id | GNU build-id note (20-byte sha1) | `LC_UUID` (16 bytes) |
| captured | per-frame by `bpf_get_stack(BPF_F_USER_STACK | BPF_F_USER_BUILD_ID)` | read from the target's mapped image (`read_macho_meta`) — in-band by construction |
| id-less module | synthetic `SISMOSYN` + random (per `(dev,inode)`, minted by the ModuleRegistry) | same registry, same synthetic id |

The 16-byte id doubles as wholesym's `MultiArchDisambiguator` on macOS, picking
the right slice of a fat binary and the matching dSYM. Synthetic ids are never
passed as UUIDs — a per-run invention is not the binary's identity.

## Module bytes (where symbols come from)

Tried in order by the pass / wholesym:

1. **The matching recorded path** on disk, preserving adjacent dSYM,
   `.gnu_debuglink`, and split-DWARF discovery. On macOS a `/usr/…` or `/System/…` path that
   no longer exists as a file falls through to the **dyld shared cache**:
   `sismo-macho`'s own cache reader extracts the member's nlist (matched by
   LC_UUID), so system-dylib frames resolve with no on-disk file. (wholesym's
   built-in cache support mis-probes the macOS 26 subcache file names —
   `.02.dylddata` etc. — which is why sismo carries its own reader.)
2. **Held fds** (`--keep-module-files`): Linux's retention pipeline does no
   startup inventory or eager retention (the separate in-kernel unwind-table
   loader may inventory mappings for CFI). After a module first appears in a
   CPU sample, userspace resolves that target's mappings on demand, prefers
   `/proc/<pid>/map_files/<start>-<end>`, verifies real build IDs and the
   kernel-reported device/inode, dedupes by inode, and retains at most 1024
   fds. If `map_files` access is denied, the display path
   is accepted only while its device/inode still matches; otherwise no fd is
   retained rather than risking bytes from a replacement. This work is never
   performed by a BPF probe. A retained inode survives deletion/rebuild.
   Offline `sismo symbolize` has no held fds, but the durable build-id and file
   offset remain in the trace when bytes are unavailable.
3. **Debug info by identity**: conventional `.build-id` locations and
   debuginfod (Linux, opt-in via
   `DEBUGINFOD_URLS`), dSYM bundles by adjacency/Spotlight (macOS), debug
   maps (`N_OSO` → the `.o` files) for un-dsymutil'ed macOS builds.
4. **Format fallbacks** (Linux/ELF): `.gopclntab` for stripped Go,
   `.dynsym`-via-`PT_DYNAMIC` for section-header-stripped ELF.

## Diagnostics

The stack-shape (DIA-0/1) and missing-build-id diagnostics are judged from the
trace, not the file format: the build-id warning fires when the *trace's* id
is synthetic/absent (so a mach-o with an `LC_UUID`, or a shared-cache dylib
with no file, never misfires) and names the per-OS remedy. The ELF-only
probes (`.eh_frame` coverage, FP prologues) return `None` on mach-o and stay
silent rather than misread it.

## Test guards

- Linux end-to-end: the `matrix` difftest suite (BPF + root, opt-in).
- macOS offline half: the `macho` difftest suite (unprivileged, default-on) —
  builds fixtures in each mach-o shape (dSYM, debug-map, symtab-only,
  stripped±dSYM, fat, `-no_uuid`, deleted, dyld-shared-cache dylib),
  synthesizes the kperf emitter's exact trace shape, runs `sismo symbolize`,
  and goldens what resolved.
- macOS record path (kperf, root): `sudo tools/e2e-all-sources`.

## Known gaps (macOS)

- Kernel frames render as raw addresses under `[kernel]` (no KASLR slide /
  kernel symbolication yet — `kperf_sample.rs`).
- Interpreter/JIT recovery (CPython, V8 perf-map, Go pcsp) is Linux-only
  today; the macOS captures emit native frames only.
