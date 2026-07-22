# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""matrix-mac suite — mach-o-only build shapes (macOS, unprivileged).

The macOS-only half of the compatibility matrix, focused on what matters on
darwin/arm64: symbolization and deobfuscation. Frame-pointer unwinding is
mandated by the arm64 ABI and the kernel walks stacks for us, so the axes
here are the mach-o-specific ways real binaries are built: dSYM relinking,
debug maps through static archives, LTO's temp-object loss, chained fixups,
arm64e, universal binaries, and the Apple-only languages (Swift, ObjC).
Build shapes that exist on every OS live in the cross-platform `matrix`
suite, which draws its macOS variants from cross_variants() here.

Like the macho suite, every case is offline: build a fixture, read marker
addresses with nm (plus inline-range PCs from the dSYM DWARF), synthesize
the kperf emitter's trace shape, run `sismo symbolize`, and golden what
resolved. Fixtures are never executed, which is what lets arm64e and
foreign-arch (x86_64) binaries be covered on any host.

Goldens pin the exact resolved names, so demangling regressions (or the
absence of demangling — Swift today) are visible as text. Matrix rules
apply: a golden records *current* behavior, degraded or not; when a gap
closes, the diff fails and prompts --rebaseline.
"""

from __future__ import annotations

import dataclasses
import functools
import os
import platform
import re
import shutil
import subprocess
import tempfile

from python.tools.diff_suites.common import (
    ROOT_DIR, SISMO, TP_SHELL, Skip, SuiteContext, run_golden_cases)
from python.tools.diff_suites.symbolize_mac import (
    SLIDE, host_arch, macho_uuid, run_symbolize, synth_trace)

NAME = "matrix-mac"
DESCRIPTION = "mach-o-only build shapes (macOS, unprivileged)"
# Default-on: unprivileged and offline; cases self-skip off-macOS or when a
# toolchain (swiftc, go, ...) is missing.
ENABLED_BY_DEFAULT = True

TARGETS: str = os.path.join(ROOT_DIR, "tests", "matrix", "targets", "macho")

# The macho DIAG_CATALOG plus the stale-file rejection the replaced case
# exists to exercise.
DIAG_CATALOG = [
    ("no symbols could be loaded", "load-failed"),
    ("no longer at this path", "missing-file"),
    ("has no build-id", "no-build-id"),
    ("did not fully symbolize", "partial"),
    ("changed since recording (build-id mismatch)", "stale-file"),
]

C_MARKERS = [("main", "main"), ("mid", "sismo_fix_mid"),
             ("leaf", "sismo_fix_leaf")]


@dataclasses.dataclass
class Variant:
    """One mach-o build shape. Build commands run with cwd=<work> and may use
    {T} (targets dir), {W} (work dir), {BIN} ({W}/fix). The first element of
    each command is a logical tool name resolved via _tool()."""

    name: str
    desc: str
    build: list[list[str]]
    markers: list[tuple[str, str]]       # (label, needle), root-first
    arch: str | None = None              # nm/dwarfdump arch; default host
    dsym: bool = False                   # run dsymutil after the build
    inline_origin: str | None = None     # append an "inline" frame at a PC
                                         # inside this fn's inlined body
    strip_after_nm: bool = False         # strip the binary once addresses are
                                         # read (UUID survives a plain strip)
    replace_build: list[list[str]] | None = None  # rebuild after the trace is
                                         # synthesized (UUID mismatch case)


def _require_macos() -> None:
    if platform.system() != "Darwin":
        raise Skip("macOS only")


@functools.lru_cache(maxsize=None)
def _tool(name: str) -> str | None:
    """Resolve a logical tool name. rustc/zig go through the repo wrappers
    (hermetic toolchains); everything else is PATH, then mise."""
    if name in ("rustc", "zig"):
        return os.path.join(ROOT_DIR, "tools", name)
    found = shutil.which(name)
    if found:
        return found
    try:
        p = subprocess.run(["mise", "which", name], capture_output=True,
                           text=True, cwd=ROOT_DIR)
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout.strip()
    except OSError:
        pass
    return None


def _subst(arg: str, work: str) -> str:
    return (arg.replace("{T}", TARGETS).replace("{BIN}", os.path.join(work, "fix"))
            .replace("{W}", work))


def run_build(cmds, work: str) -> None:
    for cmd in cmds:
        tool = _tool(cmd[0])
        if tool is None:
            raise Skip(f"{cmd[0]} not installed")
        subprocess.run([tool] + [_subst(a, work) for a in cmd[1:]],
                       cwd=work, check=True, capture_output=True)


# ---- address extraction ------------------------------------------------------


def nm_code_symbols(path: str, arch: str) -> list[tuple[str, int]]:
    out = subprocess.run(["nm", "-arch", arch, path], capture_output=True,
                         text=True, check=True).stdout
    syms = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[1] not in ("t", "T"):
            continue
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue
        # ObjC method names contain spaces: the name is everything after the
        # type column.
        syms.append((" ".join(parts[2:]), addr))
    return syms


def find_marker(syms, needle: str) -> int:
    """Exact match first (nm name, modulo one leading underscore), else a
    unique substring match — mangled Swift/Rust/C++ names embed the needle."""
    exact = [a for n, a in syms if n == needle or n.lstrip("_") == needle
             or n == "_" + needle]
    if exact:
        return exact[0]
    subs = sorted({a for n, a in syms if needle in n})
    if len(subs) == 1:
        return subs[0]
    if not subs:
        raise Skip(f"marker {needle} not in symtab")
    raise Skip(f"marker {needle} ambiguous ({len(subs)} matches)")


def text_segment(path: str, arch: str) -> tuple[int, int]:
    """(vmaddr, vmsize) of __TEXT — go/zig/rust don't all link at the same
    base, so read it rather than assume 0x100000000."""
    out = subprocess.run(["otool", "-arch", arch, "-l", path],
                         capture_output=True, text=True, check=True).stdout
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if "segname __TEXT" in line:
            vmaddr = vmsize = None
            for j in range(i, min(i + 6, len(lines))):
                if "vmaddr" in lines[j]:
                    vmaddr = int(lines[j].split()[1], 16)
                if "vmsize" in lines[j]:
                    vmsize = int(lines[j].split()[1], 16)
            if vmaddr is not None and vmsize is not None:
                return vmaddr, vmsize
    raise Skip("no __TEXT segment")


def inline_pc(binp: str, origin: str) -> int:
    """A PC inside `origin`'s inlined body, from the dSYM's relocated DWARF
    (DW_TAG_inlined_subroutine low/high_pc are final linked addresses)."""
    dwarf = os.path.join(binp + ".dSYM", "Contents", "Resources", "DWARF",
                         os.path.basename(binp))
    out = subprocess.run(["dwarfdump", "--debug-info", dwarf],
                         capture_output=True, text=True, check=True).stdout
    block: list[str] = []
    in_block = False
    for line in out.splitlines() + [""]:
        if "DW_TAG_inlined_subroutine" in line:
            in_block, block = True, []
            continue
        if not in_block:
            continue
        if not line.strip() or "DW_TAG" in line:
            attrs = "\n".join(block)
            if f'"{origin}"' in attrs:
                low = re.search(r"DW_AT_low_pc\s+\(0x([0-9a-f]+)\)", attrs)
                high = re.search(r"DW_AT_high_pc\s+\(0x([0-9a-f]+)\)", attrs)
                if low:
                    # Mid-range, 4-aligned: the body is often inlined at the
                    # caller's entry, so low_pc can equal the caller's own
                    # marker PC — aim inside instead.
                    lo = int(low.group(1), 16)
                    hi = int(high.group(1), 16) if high else lo
                    return lo + (max(hi - lo, 0) // 2 & ~3)
            in_block = "DW_TAG_inlined_subroutine" in line
            block = []
            continue
        block.append(line)
    raise Skip(f"no inlined_subroutine for {origin}")


# ---- fact extraction ---------------------------------------------------------


def query_rows(trace: str) -> list[tuple[int, str, int]]:
    """(rel_pc, name, line) rows, inline expansions grouped by rel_pc in
    symbol-table order. Fixture symbol names must stay comma-free — this
    parses trace_processor's CSV output."""
    sql = ("select spf.rel_pc, coalesce(sym.name, '') as name, "
           "coalesce(sym.line_number, 0) as line "
           "from __intrinsic_stack_profile_frame spf "
           "left join __intrinsic_stack_profile_symbol sym "
           "on sym.symbol_set_id = spf.symbol_set_id "
           "order by spf.rel_pc, sym.id")
    qf = trace + ".sql"
    with open(qf, "w") as f:
        f.write(sql)
    out = subprocess.run([TP_SHELL, "-q", qf, trace],
                         capture_output=True, text=True).stdout
    rows = []
    for line in out.splitlines():
        if not line or line.startswith('"rel_pc"'):
            continue
        parts = line.split(",")
        if len(parts) >= 3:
            name = ",".join(parts[1:-1]).strip('"')
            rows.append((int(parts[0]), name, int(parts[-1])))
    return rows


def normalize_name(name: str) -> str:
    # Rust legacy mangling ends in a per-build ::h<16 hex> hash (17h...E in
    # the raw mangled form).
    return re.sub(r"(::|17)h[0-9a-f]{16}", r"\1h<HASH>", name)


def facts(trace: str, work: str, stderr: str, frames) -> str:
    """frames: [(label, abs_pc)] root-first, as synthesized."""
    out = []
    for line in stderr.splitlines():
        s = line.strip()
        if s.startswith("[") and "]" in s:
            status, rest = s.split("]", 1)
            parts = rest.split()
            counts, path = parts[0], " ".join(parts[1:])
            out.append(f"module: {status.strip('[ ')} {counts} "
                       f"{path.replace(work, '$WORK')}")
    rows = query_rows(trace)
    by_rel: dict[int, list[tuple[str, int]]] = {}
    for rel, name, ln in rows:
        by_rel.setdefault(rel, []).append((name, ln))
    if len(by_rel) != len(frames):
        raise RuntimeError(f"{len(frames)} frames synthesized but "
                           f"{len(by_rel)} distinct rel_pcs in trace")
    # The mapping's slide is constant, so sorted abs PCs pair with sorted
    # rel_pcs positionally.
    rel_for_abs = dict(zip(sorted(a for _, a in frames), sorted(by_rel)))
    for label, abs_pc in frames:
        got = by_rel[rel_for_abs[abs_pc]]
        names = [normalize_name(n) for n, _ in got if n]
        shown = " <- ".join(names) if names else "(none)"
        has_line = any(ln > 0 for _, ln in got)
        out.append(f"frame {label}: {shown} [{'line' if has_line else 'noline'}]")
    diags = sorted({key for needle, key in DIAG_CATALOG if needle in stderr})
    out.append(f"diags: {', '.join(diags) if diags else '(none)'}")
    return "\n".join(out) + "\n"


# ---- case driver -------------------------------------------------------------


def variant_case(v: Variant):
    def produce() -> str:
        _require_macos()
        work = tempfile.mkdtemp(prefix="sismo-macmatrix-")
        try:
            run_build(v.build, work)
            binp = os.path.join(work, "fix")
            if v.dsym:
                subprocess.run(["dsymutil", binp], check=True,
                               capture_output=True)
            arch = v.arch or host_arch()
            uuid = macho_uuid(binp, arch)
            if uuid is None:
                raise Skip("no UUID in fixture")
            syms = nm_code_symbols(binp, arch)
            frames = [(label, find_marker(syms, needle) + SLIDE + 4)
                      for label, needle in v.markers]
            if v.inline_origin:
                frames.append(("inline", inline_pc(binp, v.inline_origin) + SLIDE))
            if v.strip_after_nm:
                subprocess.run(["strip", binp], check=True, capture_output=True)
            vmaddr, vmsize = text_segment(binp, arch)
            base = vmaddr + SLIDE
            mod = dict(iid=1, path=binp.encode(), build_id=uuid,
                       base=base, end=base + vmsize)
            trace = os.path.join(work, "t.pftrace")
            synth_trace(trace, [mod], [(i + 1, 1, pc)
                                       for i, (_, pc) in enumerate(frames)])
            if v.replace_build:
                run_build(v.replace_build, work)
            stderr = run_symbolize(trace)
            return facts(trace, work, stderr, frames)
        finally:
            shutil.rmtree(work, ignore_errors=True)
    return produce


# ---- the matrix --------------------------------------------------------------

# ld64 internalizes under LTO and drops the markers from the symtab entirely
# (nm shows only _main); exporting them keeps the addresses readable so the
# LTO cases stay testable. Realistic, too — plugins export their entry points.
LTO_KEEP = ["-Wl,-exported_symbol,_sismo_fix_leaf",
            "-Wl,-exported_symbol,_sismo_fix_mid"]


def _c2(v, name, desc, src="fix.c", cflags=(), ldflags=(), cc="clang",
        markers=C_MARKERS, **kw):
    """The canonical two-step build: compile via a kept .o so the debug map
    (N_OSO) stays resolvable, then link."""
    v.append(Variant(name, desc, [
        [cc, *cflags, "-c", "{T}/" + src, "-o", "{W}/fix.o"],
        [cc, *ldflags, "{W}/fix.o", "-o", "{BIN}"],
    ], markers=list(markers), **kw))


def cross_variants() -> dict[str, Variant]:
    """The macOS side of the cross-platform `matrix` suite: build shapes whose
    scenario exists on every supported OS. Names must match
    matrix_linux.cross_variants(); the matrix suite asserts they do."""
    v: list[Variant] = []

    def c2(*args, **kw):
        _c2(v, *args, **kw)

    # --- C/C++: clang shapes that exist on both ELF and mach-o -------------
    c2("c-clang-dwarf4", "DWARF 4 through the debug map",
       cflags=["-gdwarf-4", "-O1"])
    c2("c-clang-thinlto", "ThinLTO: markers survive via exported symbols; "
       "the debug map points at a deleted temp object",
       cflags=["-g", "-O2", "-flto=thin"],
       ldflags=["-flto=thin", *LTO_KEEP])
    v.append(Variant(
        "c-clang-inline", "force-inlined leaf: a PC in the inlined body must "
        "expand to the leaf <- mid chain",
        [["clang", "-g", "-O2", "-c", "{T}/fix_inline.c", "-o", "{W}/fix.o"],
         ["clang", "{W}/fix.o", "-o", "{BIN}"]],
        markers=[("main", "main"), ("mid", "sismo_fix_mid")],
        dsym=True, inline_origin="sismo_fix_leaf"))
    c2("cpp-clang", "Itanium demangling: namespace + template markers",
       src="fix.cpp", cc="clang++", cflags=["-g", "-O1"],
       markers=[("main", "main"), ("mid", "fix_mid"), ("leaf", "fix_leaf")])

    # --- Rust ---------------------------------------------------------------
    rust_markers = [("main", "main"), ("mid", "sismo_fix_mid"),
                    ("leaf", "sismo_fix_leaf")]
    v.append(Variant(
        "rust-debug", "rustc debug: packed split-debuginfo auto-dSYM",
        [["rustc", "-g", "{T}/fix.rs", "-o", "{BIN}"]],
        markers=list(rust_markers)))
    v.append(Variant(
        "rust-release", "rustc -O: auto-dSYM, legacy-mangled names",
        [["rustc", "-g", "-O", "{T}/fix.rs", "-o", "{BIN}"]],
        markers=list(rust_markers)))
    v.append(Variant(
        "rust-release-stripped", "stripped binary, adjacent dSYM: names come "
        "back through the dSYM (unlike ELF -Cstrip=symbols)",
        [["rustc", "-g", "-O", "{T}/fix.rs", "-o", "{BIN}"]],
        markers=list(rust_markers), strip_after_nm=True))

    # --- Go / Zig -----------------------------------------------------------
    v.append(Variant(
        "go-default", "gc-compiled mach-o: main.sismoFixLeaf naming, "
        "gopclntab lines",
        [["go", "build", "-o", "{BIN}", "{T}/fix.go"]],
        markers=[("main", "main.main"), ("mid", "main.sismoFixMid"),
                 ("leaf", "main.sismoFixLeaf")]))
    zig_markers = [("mid", "fix.sismoFixMid"), ("leaf", "fix.sismoFixLeaf")]
    v.append(Variant(
        "zig-debug", "zig build-exe Debug: DWARF embedded in the binary",
        [["zig", "build-exe", "-O", "Debug", "-femit-bin={BIN}",
          "{T}/fix.zig"]],
        markers=list(zig_markers)))
    v.append(Variant(
        "zig-releasefast", "zig ReleaseFast: optimized, DWARF still embedded",
        [["zig", "build-exe", "-O", "ReleaseFast", "-femit-bin={BIN}",
          "{T}/fix.zig"]],
        markers=list(zig_markers)))

    # --- environments -------------------------------------------------------
    c2("env-replaced-binary", "binary rebuilt (new UUID) between recording "
       "and symbolize, no held fd: refuse stale symbols",
       cflags=["-g", "-O1"])
    v[-1].replace_build = [
        ["clang", "-g", "-O1", "-DSISMO_FIX_REV=2", "-c", "{T}/fix.c",
         "-o", "{W}/fix.o"],
        ["clang", "{W}/fix.o", "-o", "{BIN}"]]

    return {x.name: x for x in v}


def build_variants() -> list[Variant]:
    v: list[Variant] = []

    def c2(*args, **kw):
        _c2(v, *args, **kw)

    # --- mach-o DWARF / linker axes -----------------------------------------
    c2("c-dwarf5", "DWARF 5 through the debug map",
       cflags=["-gdwarf-5", "-O1"])
    c2("c-dwarf5-dsym", "DWARF 5 relinked by dsymutil",
       cflags=["-gdwarf-5", "-O1"], dsym=True)
    c2("c-lto", "full LTO without -object_path_lto: the debug map points at "
       "a deleted temp object", cflags=["-g", "-O1", "-flto"],
       ldflags=["-flto", *LTO_KEEP])
    c2("c-lto-object-path", "full LTO with the merged object kept on disk",
       cflags=["-g", "-O1", "-flto"],
       ldflags=["-flto", "-Wl,-object_path_lto,{W}/lto.o", *LTO_KEEP])
    v.append(Variant(
        "c-archive", "markers linked from libfix.a: the archive(member) "
        "N_OSO spelling",
        [["clang", "-g", "-O1", "-c", "{T}/fix_lib.c", "-o", "{W}/fix_lib.o"],
         ["ar", "rcs", "{W}/libfix.a", "{W}/fix_lib.o"],
         ["clang", "-g", "-O1", "-c", "{T}/fix_main.c", "-o", "{W}/fix_main.o"],
         ["clang", "{W}/fix_main.o", "{W}/libfix.a", "-o", "{BIN}"]],
        markers=C_MARKERS))
    c2("c-no-fixup-chains", "legacy (pre-chained-fixups) link layout",
       cflags=["-g", "-O1"], ldflags=["-Wl,-no_fixup_chains"])
    c2("c-arm64e", "arm64e slice: PAC ABI, distinct UUID line",
       cflags=["-g", "-O1", "-arch", "arm64e"],
       ldflags=["-arch", "arm64e"], arch="arm64e")
    c2("c-cross-arch", "x86_64-only binary symbolized on any host — offline "
       "traces are arch-blind",
       cflags=["-g", "-O1", "-arch", "x86_64"],
       ldflags=["-arch", "x86_64"], arch="x86_64")
    v.append(Variant(
        "fat-dsym", "universal binary + fat dSYM: host slice picked by UUID, "
        "with line info (the macho fat case has none)",
        [["clang", "-g", "-O1", "-arch", "arm64", "-c", "{T}/fix.c",
          "-o", "{W}/fix_a.o"],
         ["clang", "-g", "-O1", "-arch", "x86_64", "-c", "{T}/fix.c",
          "-o", "{W}/fix_x.o"],
         ["clang", "-arch", "arm64", "{W}/fix_a.o", "-o", "{W}/fix_a"],
         ["clang", "-arch", "x86_64", "{W}/fix_x.o", "-o", "{W}/fix_x"],
         ["lipo", "-create", "{W}/fix_a", "{W}/fix_x", "-output", "{BIN}"]],
        markers=C_MARKERS, dsym=True))

    # --- Apple-only languages / build modes ---------------------------------
    c2("objc", "ObjC class methods: +[SismoFix leafWithDepth:] spelling",
       src="fix.m", cflags=["-g", "-O1"], ldflags=["-framework", "Foundation"],
       markers=[("main", "main"), ("mid", "midWithDepth"),
                ("leaf", "leafWithDepth")])
    v.append(Variant(
        "swift", "Swift markers: goldens the $s... mangling until a Swift "
        "demangler exists",
        [["swiftc", "-module-name", "fix", "-g", "-O", "-emit-object",
          "-o", "{W}/fix.o", "{T}/fix.swift"],
         ["swiftc", "-module-name", "fix", "-o", "{BIN}", "{W}/fix.o"]],
        markers=[("main", "main"), ("mid", "sismoFixMid"),
                 ("leaf", "sismoFixLeaf")]))
    v.append(Variant(
        "rust-unpacked", "split-debuginfo=unpacked: debug map into the kept "
        ".rcgu.o",
        [["rustc", "-g", "-O", "-C", "split-debuginfo=unpacked",
          "{T}/fix.rs", "-o", "{BIN}"]],
        markers=[("main", "main"), ("mid", "sismo_fix_mid"),
                 ("leaf", "sismo_fix_leaf")]))

    return v


def run(ctx: SuiteContext) -> int:
    needs = [SISMO, TP_SHELL]
    cases = [(v.name, variant_case(v), needs) for v in build_variants()]
    _, failed, _ = run_golden_cases(ctx, NAME, cases)
    return failed
