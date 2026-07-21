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
| `path` | where the module's bytes lived at record time |
| `build_id` | the module's *identity* (see table below) — never empty for a sampled file-backed module |
| `load_bias` | the value to subtract from a frame's `rel_pc` to reach the symbolizer's module-relative address space |
| `start`/`end` | the avma range frames of this module fall in |

The pass groups unsymbolized frames by `(path, build_id, load_bias)` (via a
trace_processor query — `sismo_trace_query.cc` mirrors trace_processor's own
`kQueryUnsymbolized` so the emitted `AddressSymbols.address` always matches
`spf.rel_pc`), loads each module's bytes, and resolves `rel_pc - load_bias`
through wholesym.

## Address conventions

| | Linux (eBPF) | macOS (kperf) |
| --- | --- | --- |
| frame `rel_pc` | link-time vaddr | absolute PC |
| mapping `load_bias` | load bias (avma of vaddr 0) | image base (avma of the mach-o header) |
| `rel_pc - load_bias` | ELF file-relative vaddr | offset from `__TEXT` base |

Both right-hand columns are exactly wholesym's `Relative` lookup space for the
respective format, so the pass does the same arithmetic everywhere.

## Module identity

| | Linux | macOS |
| --- | --- | --- |
| real id | GNU build-id note (20-byte sha1) | `LC_UUID` (16 bytes) |
| captured | host-side file read + in-band BPF page copy (CAP-2) | read from the target's mapped image (`read_macho_meta`) — in-band by construction |
| id-less module | synthetic `SISMOSYN` + random (per `(dev,inode)`, minted by the ModuleRegistry) | same registry, same synthetic id |

The 16-byte id doubles as wholesym's `MultiArchDisambiguator` on macOS, picking
the right slice of a fat binary and the matching dSYM. Synthetic ids are never
passed as UUIDs — a per-run invention is not the binary's identity.

## Module bytes (where symbols come from)

Tried in order by the pass / wholesym:

1. **The recorded path** on disk. On macOS a `/usr/…` or `/System/…` path that
   no longer exists as a file falls through to the **dyld shared cache**:
   `sismo-macho`'s own cache reader extracts the member's nlist (matched by
   LC_UUID), so system-dylib frames resolve with no on-disk file. (wholesym's
   built-in cache support mis-probes the macOS 26 subcache file names —
   `.02.dylddata` etc. — which is why sismo carries its own reader.)
2. **Held fds** (`--keep-module-files`, CAP-3(b)): the recorder pins an fd per
   sampled module (policy: `auto` pins unstable paths only), so a binary
   rebuilt or deleted mid-run still resolves via `/proc/self/fd/<n>` (Linux) /
   `/dev/fd/<n>` (macOS). The ModuleRegistry is shared by both kperf perf
   consumers on macOS and owned by the BPF collector on Linux. Offline
   `sismo symbolize` has no held fds — a since-deleted binary is its
   documented limitation.
3. **Debug info by identity**: debuginfod (Linux, opt-in via
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
