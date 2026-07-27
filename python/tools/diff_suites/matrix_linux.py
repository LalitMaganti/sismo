# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""matrix-linux suite — the Linux-only half of the compatibility matrix.

ELF/BPF shapes (debuglink, MiniDebugInfo, sectionless, static/musl,
no-build-id), gcc's flag axes, and the /proc- and capability-dependent env
cases — everything whose scenario only exists on Linux. Build shapes that
exist on every OS (including the interpreted/JIT runtimes) live in the
cross-platform `matrix` suite, which draws its Linux variants — and the
machinery for the macOS live mode — from this module's cross_variants()
and variant_facts(); mach-o-only shapes live in matrix-mac.

Each variant builds a canonical workload (tests/matrix/targets/), records it
with sismo, and goldens two things:

  1. Output quality — did samples land, is the target mapping present, did
     the hot leaf symbolize, is the leaf→mid→outer call chain intact?
  2. Diagnostic quality — when output is degraded (stripped binary, missing
     frame pointers, deleted file, no privileges, interpreted language),
     did sismo tell the user what happened (see DIAG_CATALOG)?

Each variant's golden is its stable observed facts. A "known gap" is simply a
golden that records degraded output today; when a roadmap feature lands and the
output improves, the golden diff fails and prompts a --rebaseline. That diff is
the "gap closed → update expectation" flow — no separate xfail bookkeeping.

This suite is ENABLED_BY_DEFAULT = False: heavy, needs a caps-granted sismo
(see `sismo doctor --fix`) and the Perfetto build, run it with
`tools/difftest --suite matrix-linux`. Scope is
local only for now; the kernel-version axis, the multi-version toolchain
matrix, and the CI gate are deferred — see the testing design doc.
"""

from __future__ import annotations

import dataclasses
import functools
import os
import platform
import re
import shutil
import subprocess
import time

from python.tools.diff_suites.common import (
    ROOT_DIR, SISMO, TP_SHELL, Skip, SuiteContext, crashmark,
    ensure_record_env, run_golden_cases)

NAME = "matrix-linux"
DESCRIPTION = "Linux-only workloads × compilers × flags × env (heavy, needs BPF caps)"
ENABLED_BY_DEFAULT = False
NEEDS_BINARY = True

TARGETS: str = os.path.join(ROOT_DIR, "tests", "matrix", "targets")
OUT_DIR: str = os.path.join(ROOT_DIR, "out", "matrix")
BIN_DIR: str = os.path.join(OUT_DIR, "bin")
TRACE_DIR: str = os.path.join(OUT_DIR, "traces")
GOCACHE: str = os.path.join(OUT_DIR, "gocache")

ZIG: list[str] = [os.path.join(ROOT_DIR, "tools", "zig")]
RUSTC: list[str] = [os.path.join(ROOT_DIR, "tools", "rustc")]

MIN_SAMPLES: int = 50
# The 8-byte prefix sismo stamps on a fabricated build-id (proc_maps::SYNTH_MAGIC
# = b"SISMOSYN"), as lowercase hex, so a synthetic id is recognized by its prefix.
SYNTH_MAGIC_HEX: str = "5349534d4f53594e"


# ----- variant model ------------------------------------------------------


@dataclasses.dataclass
class Expect:
    """What this variant's recording should look like.

    Encodes *current* behavior, not aspiration: when a variant is known to
    produce degraded output, say so here and attach a `gremlin` note if
    sismo emits no useful diagnostic about it. A fixed gremlin then shows
    up as XPASS, prompting an expectation update.
    """

    record_exit: int = 0
    samples: bool = True          # >= MIN_SAMPLES perf samples
    offcpu: bool = True           # both on-CPU and off-CPU sessions present
    mapping: bool = True          # target module mapping in the trace
    leaf: str = "full"            # full | none — hot leaf fn symbolized
    chain: str = "full"           # full      — mid+outer both ancestors of leaf
                                  # partial   — only one (leaf-FP omitted →
                                  #             the leaf's caller is skipped)
                                  # truncated — neither (no FP at all)
                                  # na        — not meaningful for this variant
    module_status: str | None = "ok"   # expected status in sismo's per-module
                                       # symbolization report; None = don't
                                       # check; "absent" = not in report
    diags: list[str] = dataclasses.field(default_factory=list)
                                  # regexes that must appear on stderr
    gremlin: str | None = None    # known missing/unhelpful diagnostic


@dataclasses.dataclass
class Variant:
    name: str
    group: str
    desc: str
    cmd: list[str]                       # target argv; "{DUR}" replaced
    expect: Expect
    build: list[list[str]] = dataclasses.field(default_factory=list)
    leaf: str = "sismo_wl_leaf"          # symbol LIKE patterns
    mid: str = "sismo_wl_mid"
    outer: str = "sismo_wl_outer"
    map_substr: str = ""                 # mapping-name substring; default:
                                         # basename of cmd[0]
    runner: str = "caps"                 # caps (sismo) | plain (uncapped copy)
    chain_need: int = 2                  # distinct chain symbols for "full"
    mid_run: tuple[float, str] | None = None   # (delay_s, "delete"|"replace")
    # Build command run at the mid_run point for action "replace" — rebuilds the
    # binary at cmd[0] so the on-disk file's build-id no longer matches the trace.
    mid_run_build: list[list[str]] = dataclasses.field(default_factory=list)
    keep_module_files: str = "auto"      # --keep-module-files=<all|auto|none>
    build_may_skip: str | None = None    # regex on build stderr → skip
    skip_reason: str | None = None

    def mapping_pattern(self) -> str:
        return self.map_substr or os.path.basename(self.cmd[0])


def _bin(name: str) -> str:
    return os.path.join(BIN_DIR, name)


FP = "-fno-omit-frame-pointer"

# gcc never frames leaf functions that don't touch the stack — even
# with -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer (verified,
# gcc 16). The FP walk then reads the leaf's caller's frame, so the
# hot leaf's immediate caller is missing from every stack: chain is
# "partial" for all gcc builds. clang/zig cc do frame leaves.
GCC_LEAF_FP = ("gcc omits leaf-fn frame pointers even with "
               "-fno-omit-frame-pointer → the hot leaf's caller is "
               "silently missing from every stack (misattribution); "
               "no diagnostic")

# rustc omits frame pointers by default in BOTH debug and release
# (verified: leaf prologue is `sub $N,%rsp` with no `push %rbp`), so
# sismo's FP walk truncates to the leaf PC. Users must pass
# -Cforce-frame-pointers=yes; nothing tells them.
RUST_FP = ("rustc omits frame pointers by default (debug AND release) → "
           "stacks truncate to the leaf PC; no diagnostic. Fix is "
           "-Cforce-frame-pointers=yes or RUSTFLAGS.")


def _c_variant(v, name, cc, flags, expect, desc, post=(), **kw):
    # post commands may reference the built binary as "{BIN}"; commands
    # without the placeholder get it appended (strip-style).
    b = _bin(name)
    build = [[*cc, *flags, "-o", b, os.path.join(TARGETS, "workload.c")]]
    for p in post:
        cmd = [a.replace("{BIN}", b) for a in p]
        if not any("{BIN}" in a for a in p):
            cmd.append(b)
        build.append(cmd)
    v.append(Variant(name, name.split("-")[0], desc, [b, "{DUR}"], expect, build, **kw))


@functools.lru_cache(maxsize=None)
def _mise_tool(name: str) -> str:
    """Absolute path to a tool, resolving mise-managed toolchains (java) that
    are not on the harness PATH. Falls back to the bare name so the variant's
    availability check can Skip it cleanly when nothing provides it."""
    found = shutil.which(name)
    if found:
        return found
    try:
        p = subprocess.run(["mise", "which", name], capture_output=True, text=True)
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout.strip()
    except OSError:
        pass
    return name


def cross_variants() -> dict[str, Variant]:
    """The Linux side of the cross-platform `matrix` suite: build shapes whose
    scenario exists on every supported OS. Names must match
    matrix_mac.cross_variants(); the matrix suite asserts they do."""
    wl_c = os.path.join(TARGETS, "workload.c")
    wl_rs = os.path.join(TARGETS, "workload.rs")
    wl_go = os.path.join(TARGETS, "workload.go")
    wl_zig = os.path.join(TARGETS, "workload.zig")
    wl_inline = os.path.join(TARGETS, "workload_inline.c")
    fp = FP
    v: list[Variant] = []
    c_variant = functools.partial(_c_variant, v)

    # --- C/C++: clang shapes that exist on both ELF and mach-o -------------
    c_variant("c-clang-dwarf4", ["clang"], ["-O2", fp, "-g", "-gdwarf-4"],
              Expect(), "clang -gdwarf-4: the older DWARF version still resolves")
    c_variant("c-clang-thinlto", ["clang"], ["-O2", fp, "-flto=thin"],
              Expect(), "clang -flto=thin: ThinLTO cross-module optimization")
    b = _bin("c-clang-inline")
    v.append(Variant(
        "c-clang-inline", "c",
        "inlined hot leaf (-g): inline-frame fidelity",
        [b, "{DUR}"],
        Expect(leaf="none", chain="na",
               gremlin="inlined callee names are dropped — the symbolizer "
                       "keeps only the outermost DWARF frame, so an inlined "
                       "hot function is invisible in the profile"),
        [["clang", "-O2", fp, "-g", "-o", b, wl_inline]],
        leaf="sismo_wl_inline_leaf", mid="sismo_wl_mid", outer="sismo_wl_outer"))
    b = _bin("cpp-clang")
    v.append(Variant(
        "cpp-clang", "cpp", "same source as C++ with clang++: Itanium demangling",
        [b, "{DUR}"], Expect(),
        [["clang++", "-x", "c++", "-O2", fp, "-o", b, wl_c]]))

    # --- Rust ---------------------------------------------------------------
    b = _bin("rust-debug")
    v.append(Variant("rust-debug", "rust", "rustc debug: FP omitted by default",
                     [b, "{DUR}"], Expect(chain="truncated", gremlin=RUST_FP),
                     [RUSTC + ["-o", b, wl_rs]]))
    b = _bin("rust-release")
    v.append(Variant("rust-release", "rust", "rustc -O: FP omitted by default",
                     [b, "{DUR}"], Expect(chain="truncated", gremlin=RUST_FP),
                     [RUSTC + ["-O", "-o", b, wl_rs]]))
    b = _bin("rust-release-stripped")
    v.append(Variant(
        "rust-release-stripped", "rust", "rustc -O -Cstrip=symbols",
        [b, "{DUR}"],
        Expect(leaf="none", chain="na", module_status="ok",
               gremlin="rustc -Cstrip=symbols drops local fn names, but "
                       "every address still resolves to *some* nearest "
                       "symbol so sismo reports a green [ok] — the hot "
                       "function names are silently wrong/missing"),
        [RUSTC + ["-O", "-Cforce-frame-pointers=yes", "-Cstrip=symbols",
                  "-o", b, wl_rs]]))

    # --- Go -----------------------------------------------------------------
    b = _bin("go-default")
    v.append(Variant(
        "go-default", "go", "go build: leaf-fn FP omitted (mid skipped)",
        [b, "{DUR}"],
        Expect(chain="partial",
               gremlin="Go omits the hot leaf's frame pointer → its caller "
                       "is skipped in every stack, same misattribution as "
                       "gcc; no diagnostic"),
        [["go", "build", "-o", b, wl_go]]))

    # --- Zig ----------------------------------------------------------------
    b = _bin("zig-debug")
    v.append(Variant("zig-debug", "zig", "zig build-exe Debug",
                     [b, "{DUR}"], Expect(),
                     [ZIG + ["build-exe", "-O", "Debug", f"-femit-bin={b}", wl_zig]]))
    b = _bin("zig-releasefast")
    v.append(Variant(
        "zig-releasefast", "zig",
        "zig ReleaseFast: good stacks; one runtime stub stays unresolved",
        [b, "{DUR}"],
        Expect(module_status="partial"),
        [ZIG + ["build-exe", "-O", "ReleaseFast", f"-femit-bin={b}", wl_zig]]))

    # --- interpreted / JIT ---------------------------------------------------
    py = shutil.which("python3") or "python3"
    v.append(Variant(
        "py-cpython", "py", "CPython: interpreter frames are a known gap",
        [py, os.path.join(TARGETS, "workload.py"), "{DUR}"],
        Expect(leaf="none", chain="na", module_status=None,
               gremlin="Python samples show only native interpreter frames; "
                       "no diagnostic explains why user code is invisible"),
        map_substr="python"))
    node = shutil.which("node") or "node"
    v.append(Variant(
        "js-node", "js", "Node: JIT frames are a known gap",
        [node, os.path.join(TARGETS, "workload.js"), "{DUR}"],
        Expect(leaf="none", chain="na", module_status=None,
               gremlin="Node samples show only V8 native frames; no "
                       "diagnostic explains missing JS frames (no perf-map/"
                       "jitdump support)"),
        map_substr="node"))
    v.append(Variant(
        "js-node-perfmap", "js",
        "Node --perf-basic-prof: V8 JIT methods named from the perf-map (JIT-1)",
        # --no-turbo-inlining keeps sismo_wl_leaf a distinct method; V8 otherwise
        # inlines it into its caller, collapsing the leaf frame the chain check
        # anchors on. The point here is that sismo names the JIT frames, not V8's
        # inlining policy. --logfile=/dev/null suppresses the per-isolate v8.log
        # --perf-basic-prof would otherwise drop in the cwd (the repo root).
        [node, "--perf-basic-prof", "--no-turbo-inlining", "--logfile=/dev/null",
         os.path.join(TARGETS, "workload.js"), "{DUR}"],
        Expect(leaf="full", chain="full", module_status=None),
        map_substr="node"))
    javac = _mise_tool("javac")
    java = _mise_tool("java")
    jar = _mise_tool("jar")
    classdir = _bin("jvm-java.d")
    v.append(Variant(
        "jvm-java", "jit", "JVM/HotSpot: Java methods are unnamed native frames",
        [java, "-jar", _bin("jvm-java"), "{DUR}"],
        Expect(leaf="none", chain="na", module_status=None,
               gremlin="HotSpot samples show only native libjvm/JIT frames; "
                       "naming the sismo_wl_* methods needs a perf-map "
                       "(-XX:+PreserveFramePointer + producer), JIT-1"),
        [[javac, "-d", classdir, os.path.join(TARGETS, "workload.java")],
         [jar, "--create", "--file", _bin("jvm-java"),
          "--main-class", "Workload", "-C", classdir, "."]],
        map_substr="libjvm",
        # macOS ships /usr/bin/javac as a stub that errors when no JDK is
        # installed, so `which javac` succeeding does not mean java exists.
        build_may_skip=r"Unable to locate a Java Runtime"))

    # --- environments -------------------------------------------------------
    b = _bin("env-replaced-binary")
    v.append(Variant(
        "env-replaced-binary", "env",
        "binary rebuilt mid-run, not held: symbolizer refuses the changed file",
        [b, "{DUR}"],
        Expect(leaf="none", chain="na", module_status=None,
               diags=[r"changed since recording"]),
        [["gcc", "-O2", fp, "-o", b, wl_c]],
        # Record with the file NOT held, then rebuild it (at -O0, a different
        # build-id) at the same path at 0.5s. At symbolize the path holds the new
        # file, whose id no longer matches the trace, so the safety net refuses it
        # rather than emit the wrong build's symbols: `leaf: absent`, `build_id:
        # mismatch`, and a changed-file diagnostic. Held (`auto`) would instead
        # symbolize correctly from the retained original inode.
        keep_module_files="none",
        mid_run=(0.5, "replace"),
        # Build to a sibling and rename() over the target: linking straight to
        # the path hits ETXTBSY while the workload still runs it, silently
        # leaving the file unreplaced (and the timing-dependent outcome flaky).
        mid_run_build=[["gcc", "-O0", fp, "-o", b + ".new", wl_c],
                       ["mv", b + ".new", b]]))

    return {x.name: x for x in v}


def build_variants() -> list[Variant]:
    wl_c = os.path.join(TARGETS, "workload.c")
    wl_dlopen = os.path.join(TARGETS, "workload_dlopen.c")
    wl_plugin = os.path.join(TARGETS, "workload_plugin.c")
    wl_rs = os.path.join(TARGETS, "workload.rs")
    wl_go = os.path.join(TARGETS, "workload.go")
    wl_zig = os.path.join(TARGETS, "workload.zig")
    wl_py = os.path.join(TARGETS, "workload.py")
    wl_js = os.path.join(TARGETS, "workload.js")
    wl_java = os.path.join(TARGETS, "workload.java")
    wl_inline = os.path.join(TARGETS, "workload_inline.c")
    mk_mdi = os.path.join(TARGETS, "make_minidebug.sh")

    fp = FP
    v: list[Variant] = []
    c_variant = functools.partial(_c_variant, v)

    # --- C: compiler / flag axes -----------------------------------------
    c_variant("c-gcc-O0", ["gcc"], ["-O0"], Expect(),
              "gcc -O0: FP everywhere, symtab present")

    # --- flags that strip or reshape the data sismo needs -----------------
    # No unwind tables: the workload's own functions get no .eh_frame FDEs
    # (crt/libc still ship theirs), so the in-kernel lightswitch walker has no
    # rows and -O2's omitted frame pointers leave the helper chain truncated.
    c_variant("c-gcc-O2-noeh", ["gcc"],
              ["-O2", "-fno-asynchronous-unwind-tables", "-fno-unwind-tables"],
              Expect(chain="partial",
                     gremlin="no .eh_frame FDEs for the workload's functions and "
                             "no frame pointers → the chain is partial and sismo "
                             "emits no diagnostic naming the missing unwind tables"),
              "gcc -O2, no unwind tables: neither DWARF CFI nor frame pointers")
    # No .eh_frame_hdr (and no PT_GNU_EH_FRAME): the `.eh_frame` section is still
    # present, so the unwind-table loader indexes it directly and FP-less stacks unwind to
    # full chains — a regression guard for the no-hdr path. The point of the
    # variant is Finding B: the phdr-only probe used to under-report this binary
    # as having no CFI; it now also checks the `.eh_frame` section.
    c_variant("c-gcc-O2-noehframehdr", ["gcc"],
              ["-O2", "-Wl,--no-eh-frame-hdr"],
              Expect(),
              "gcc -O2, --no-eh-frame-hdr: .eh_frame kept but no lookup header")
    # Cross-TU optimization: LTO can rename/merge and inline across units.
    c_variant("c-gcc-O2-lto", ["gcc"], ["-O2", fp, "-flto"],
              Expect(),
              "gcc -O2 -flto: link-time optimization reshapes symbols/inlining")
    # Compressed debug info (SHF_COMPRESSED .debug_*): the symbolizer must
    # decompress to read line/inline info.
    c_variant("c-gcc-O2-gz", ["gcc"], ["-O2", fp, "-g", "-gz"],
              Expect(),
              "gcc -O2 -g -gz: zlib-compressed DWARF sections")
    # DWARF 5 forms (.debug_rnglists/.debug_addr, new abbrev forms).
    c_variant("c-gcc-O2-dwarf5", ["gcc"], ["-O2", fp, "-g", "-gdwarf-5"],
              Expect(),
              "gcc -O2 -g -gdwarf-5: DWARF version 5 encoding")
    c_variant("c-gcc-O2", ["gcc"], ["-O2"],
              Expect(chain="truncated",
                     gremlin="plain -O2 omits frame pointers → stacks are "
                             "just the leaf PC; sismo emits no diagnostic "
                             "at all"),
              "gcc -O2 (upstream default): FP omitted")
    c_variant("c-gcc-O2-fp", ["gcc"], ["-O2", fp],
              Expect(chain="partial", gremlin=GCC_LEAF_FP),
              "gcc -O2 with frame pointers — what users think is golden")
    c_variant("c-clang-O2-fp", ["clang"], ["-O2", fp], Expect(),
              "clang -O2 with frame pointers — the actual golden path")
    c_variant("c-zigcc-O2-fp", ZIG + ["cc"], ["-O2", fp], Expect(),
              "zig cc (clang under the hood), glibc")
    c_variant("c-gcc-O2-fp-g", ["gcc"], ["-O2", fp, "-g"],
              Expect(chain="partial", gremlin=GCC_LEAF_FP),
              "with full DWARF: file/line should be available")
    c_variant("c-clang-splitdwarf", ["clang"],
              ["-O2", fp, "-g", "-gsplit-dwarf"], Expect(),
              "split DWARF (.dwo): names from symtab must still work")
    # Lock-in regression guards: build shapes sismo already handles, pinned so a
    # future symbolizer/unwinder change that breaks one fails the golden.
    # (clang dwarf4/thinlto/inline moved to the cross-platform matrix suite.)
    c_variant("c-gcc-splitdwarf", ["gcc"], ["-O2", fp, "-g", "-gsplit-dwarf"],
              Expect(), "gcc split DWARF (.dwo): names from symtab must still work")
    c_variant("c-clang-gz-zstd", ["clang"], ["-O2", fp, "-g", "-gz=zstd"],
              Expect(), "clang -gz=zstd: zstd-compressed DWARF (object ruzstd path)")
    c_variant("c-gcc-O2-fp-stripped", ["gcc"], ["-O2", fp],
              Expect(leaf="none", chain="na", module_status="partial",
                     gremlin="stripped binary reports [partial] with no "
                             "explanation and no remedy hint — the "
                             "stripped/debuginfo hints only fire on "
                             "'no symbols'"),
              "stripped binary: no symtab, keeps build-id",
              post=[["strip"]])
    c_variant("c-clang-debuglink", ["clang"], ["-O2", fp, "-g"],
              Expect(module_status=None),
              "stripped + .gnu_debuglink to a separate debug file",
              post=[["objcopy", "--only-keep-debug", "{BIN}", "{BIN}.dbg"],
                    ["strip"],
                    ["objcopy", "--add-gnu-debuglink={BIN}.dbg", "{BIN}"]])
    c_variant("c-gcc-O2-fp-nobuildid", ["gcc"],
              ["-O2", fp, "-Wl,--build-id=none"],
              Expect(chain="partial",
                     gremlin="no build-id → synthetic per-run id; nothing "
                             "warns that cross-run/symbol-server matching "
                             "cannot work (plus: " + GCC_LEAF_FP + ")"),
              "no GNU build-id note")
    c_variant("c-gcc-O2-fp-nopie", ["gcc"], ["-O2", fp, "-no-pie"],
              Expect(chain="partial", gremlin=GCC_LEAF_FP),
              "non-PIE: fixed load address")
    c_variant("c-gcc-O2-fp-static", ["gcc"], ["-O2", fp, "-static"],
              Expect(chain="partial", gremlin=GCC_LEAF_FP),
              "fully static glibc binary",
              build_may_skip=r"cannot find -lc|glibc-static")
    c_variant("c-zigcc-musl-static", ZIG + ["cc"],
              ["-target", "x86_64-linux-musl", "-O2", fp], Expect(),
              "static musl binary via zig cc")

    # --- weird binary layouts / out-of-line symbols ----------------------
    # Real distro shapes that defeat name-based section/table lookup.
    c_variant("c-sectionless", ["clang"], ["-O2", fp, "-rdynamic"],
              Expect(leaf="none", chain="na",
                     gremlin="section header table removed (objcopy "
                             "--strip-section-headers); names must be read "
                             "from PT_DYNAMIC/.dynsym, not section headers"),
              "no section header table; symbols only via .dynsym",
              post=[["objcopy", "--strip-section-headers", "{BIN}", "{BIN}"]])
    # FLAG-sectionless-eh (Finding A): a section-header-stripped binary that is
    # ALSO frame-pointer-less. c-sectionless kept frame pointers, so its FP walk
    # hid the bug; here there is no FP walk to fall back on, so unwinding must
    # come from `.eh_frame` reached via PT_GNU_EH_FRAME/PT_LOAD. -rdynamic keeps
    # the names in .dynsym (SYM-2) so the recovered chain is symbolized.
    c_variant("c-clang-sectionless-nofp", ["clang"], ["-O2", "-rdynamic"],
              Expect(),
              "FP-less + no section headers: unwind from .eh_frame via phdrs",
              post=[["objcopy", "--strip-section-headers", "{BIN}", "{BIN}"]])
    c_variant("c-gnu-debugdata", ["clang"], ["-O2", fp],
              Expect(leaf="none", chain="na",
                     gremlin="function names live only in an xz-compressed "
                             ".gnu_debugdata (MiniDebugInfo, the Fedora/Arch "
                             "stripped-lib format); the real .symtab is gone"),
              "MiniDebugInfo: symbols in a compressed .gnu_debugdata section",
              post=[["bash", mk_mdi, "{BIN}"]])
    b = _bin("go-sectionless-pclntab")
    v.append(Variant(
        "go-sectionless-pclntab", "go",
        "stripped Go with .gopclntab renamed away (distro external-PIE "
        "shape, systing #158)",
        [b, "{DUR}"],
        Expect(leaf="none", chain="na", module_status="partial",
               gremlin="no .gopclntab by name — the table is merged into a "
                       "data section, so a resolver must scan data sections "
                       "to find it (sismo has no gopclntab resolver yet)"),
        [["go", "build", "-ldflags=-s -w", "-o", b, wl_go],
         ["objcopy", "--rename-section", ".gopclntab=.data.rel.ro.pcln", b]]))

    # --- C++ --------------------------------------------------------------
    b = _bin("cpp-gxx-O2-fp")
    v.append(Variant(
        "cpp-gxx-O2-fp", "cpp", "same source as C++: mangled names must demangle",
        [b, "{DUR}"], Expect(chain="partial", gremlin=GCC_LEAF_FP),
        [["g++", "-x", "c++", "-O2", fp, "-o", b, wl_c]]))

    # --- dlopen: module appears mid-recording -----------------------------
    # Built with clang so the gcc leaf-FP issue doesn't confound the
    # late-mapping axis. Chain check: plugin_outer above plugin_leaf.
    b = _bin("c-dlopen")
    plug = _bin("workload_plugin.so")
    v.append(Variant(
        "c-dlopen", "c", "hot code in a dlopen()ed plugin (late mapping)",
        [b, "{DUR}", plug],
        Expect(),
        [["clang", "-O2", fp, "-o", b, wl_dlopen],
         ["clang", "-O2", fp, "-shared", "-fPIC", "-o", plug, wl_plugin]],
        leaf="sismo_plugin_leaf", mid="sismo_plugin_outer",
        outer="sismo_plugin_outer", map_substr="workload_plugin.so",
        chain_need=1))

    # --- Rust (cross-platform rust cases live in the matrix suite) --------
    b = _bin("rust-release-fp")
    v.append(Variant("rust-release-fp", "rust",
                     "rustc -O -Cforce-frame-pointers=yes — the golden path",
                     [b, "{DUR}"], Expect(),
                     [RUSTC + ["-O", "-Cforce-frame-pointers=yes", "-o", b, wl_rs]]))

    # --- Go ---------------------------------------------------------------
    # Go keeps frame pointers on non-leaf funcs but omits them on the hot
    # leaf (same effect as gcc): `mid` is skipped, leaf sits under outer.
    b = _bin("go-stripped")
    v.append(Variant(
        "go-stripped", "go", "go build -ldflags=-s -w (very common in CI)",
        [b, "{DUR}"],
        Expect(leaf="none", chain="na", module_status="partial",
               gremlin="stripped Go resolves only 8/36 addresses yet reports "
                       "[partial] (not 'no symbols'), so no stripped/debuginfo "
                       "hint fires — and the distro debuginfo-install hint "
                       "would be wrong advice for a user's own Go binary. Go "
                       "still ships pclntab, which sismo doesn't read."),
        [["go", "build", "-ldflags=-s -w", "-o", b, wl_go]]))

    # (interpreted/JIT runtimes moved to the cross-platform matrix suite —
    # their scenario exists on every OS, live-recorded on each.)

    # --- environments -----------------------------------------------------
    b = _bin("env-unprivileged")
    v.append(Variant(
        "env-unprivileged", "env",
        "plain `sismo record` without caps: the error must say what to do",
        [b, "{DUR}"],
        Expect(samples=False, offcpu=False, mapping=False, leaf="none",
               chain="na", module_status=None,
               diags=[r"bpf capture init failed", r"doctor --fix"]),
        [["gcc", "-O2", fp, "-o", b, wl_c]],
        runner="plain"))
    b = _bin("env-deleted-binary")
    v.append(Variant(
        "env-deleted-binary", "env",
        "binary deleted mid-recording: symbolizer must say the file is gone",
        [b, "{DUR}"],
        Expect(leaf="none", chain="na", module_status="no symbols",
               diags=[r"no longer|deleted|not found|missing"]),
        [["gcc", "-O2", fp, "-o", b, wl_c]],
        # Delete before a later userspace maps refresh. Per-frame
        # BPF_F_USER_BUILD_ID capture must still retain the real identity; bytes
        # may remain unavailable when the initial userspace fd pin lost the race.
        mid_run=(0.1, "delete")))
    b = _bin("env-deleted-binary-kept")
    v.append(Variant(
        "env-deleted-binary-kept", "env",
        "binary deleted after sismo held its fd: symbolizes via /proc/self/fd",
        [b, "{DUR}"],
        Expect(leaf="full", chain="full", module_status="ok"),
        [["gcc", "-O2", fp, "-o", b, wl_c]],
        # Delete at 0.6s — after the first sample (~0.2s) made sismo hold an fd
        # open to the executable (it lives under out/, an unstable path, so the
        # default --keep-module-files=auto holds it), but before the post-record
        # symbolize pass. The file is gone at symbolize time, so `leaf: symbolized`
        # here is due entirely to userspace fd retention reading the bytes back through the held
        # fd; with --keep-module-files=none it reverts to `leaf: absent`.
        mid_run=(0.6, "delete")))
    # (env-replaced-binary moved to the cross-platform matrix suite.)

    return v


# ----- execution ----------------------------------------------------------


class BuildError(Exception):
    pass


class BuildSkip(Exception):
    pass


@functools.lru_cache(maxsize=1)
def _sources_mtime() -> float:
    """Newest mtime among the workload sources and this config. A variant's
    binary older than this must be rebuilt; newer can be reused."""
    newest = os.path.getmtime(__file__)
    for name in os.listdir(TARGETS):
        p = os.path.join(TARGETS, name)
        if os.path.isfile(p):
            newest = max(newest, os.path.getmtime(p))
    return newest


def build_is_current(variant: Variant) -> bool:
    """True when the variant's binary already exists and is newer than every
    workload source and the matrix config. The workloads are independent of
    sismo, so iterating on sismo alone need not recompile them — this is what
    makes a re-run fast."""
    try:
        return os.path.getmtime(_bin(variant.name)) >= _sources_mtime()
    except OSError:
        return False


def run_build(variant: Variant) -> None:
    # Reuse an up-to-date binary from a previous run — the common case when
    # only sismo changed between matrix runs. A variant whose mid_run replaces
    # its own binary must always rebuild: the leftover replacement is newer
    # than the sources, so the mtime check would wrongly keep it.
    if not variant.mid_run_build and build_is_current(variant):
        return
    crashmark(f"build begin {variant.name}")
    os.makedirs(BIN_DIR, exist_ok=True)
    env = dict(os.environ, GOCACHE=GOCACHE)
    for cmd in variant.build:
        p = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=ROOT_DIR)
        if p.returncode != 0:
            err = p.stdout + p.stderr
            if variant.build_may_skip and re.search(variant.build_may_skip, err):
                raise BuildSkip(f"build prerequisite missing ({cmd[0]})")
            raise BuildError(f"build failed: {' '.join(cmd)}\n{err[-2000:]}")
    crashmark(f"build end {variant.name}")


@dataclasses.dataclass
class RecordResult:
    exit: int
    stdout: str
    stderr: str
    trace: str
    wall_s: float


def _uncapped_sismo() -> str:
    """A copy of the sismo binary without its file caps, for the unprivileged
    env case (copyfile does not carry the security.capability xattr)."""
    dst = os.path.join(BIN_DIR, "sismo-nocaps")
    os.makedirs(BIN_DIR, exist_ok=True)
    if (not os.path.exists(dst)
            or os.path.getmtime(dst) < os.path.getmtime(SISMO)):
        shutil.copyfile(SISMO, dst)
        os.chmod(dst, 0o755)
    return dst


def run_record(variant: Variant, duration_ms: int, no_symbolize: bool = False,
               mac_live: bool = False) -> RecordResult:
    trace = os.path.join(TRACE_DIR, variant.name + ".pftrace")
    os.makedirs(TRACE_DIR, exist_ok=True)
    if os.path.exists(trace):
        os.unlink(trace)
    if mac_live:
        # kdebug/kperf are root-only, and macOS record runs its data sources
        # in-process when euid == 0 — so the whole record runs under sudo.
        # The caller must have verified `sudo -n` works (or euid == 0); the
        # macOS record has no --keep-module-files flag.
        prefix = [] if os.geteuid() == 0 else ["sudo", "-n"]
        # --no-heap: this suite goldens the CPU/sched pillar; leaving heap
        # capture on couples these facts to heap-attach latency (the preload
        # gates the target's main() on the recorder attaching).
        cmd = prefix + [SISMO, "record", "--no-heap", "--output", trace]
    else:
        runner = SISMO if variant.runner == "caps" else _uncapped_sismo()
        cmd = [runner, "record", "--keep-module-files", variant.keep_module_files,
               "--output", trace]
    if no_symbolize:
        cmd.append("--no-symbolize")
    cmd += [a.replace("{DUR}", str(duration_ms)) for a in variant.cmd]
    t0 = time.monotonic()
    crashmark(f"record begin {variant.name}")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, cwd=ROOT_DIR)
    if variant.mid_run:
        delay, action = variant.mid_run
        time.sleep(delay)
        if action == "delete" and os.path.exists(variant.cmd[0]):
            os.unlink(variant.cmd[0])
        elif action == "replace":
            # Rebuild the binary at the same path so its build-id changes under
            # the running process — the running inode is untouched, the path now
            # holds a different file.
            for step in variant.mid_run_build:
                subprocess.run(step, capture_output=True, cwd=ROOT_DIR)
    try:
        out, err = proc.communicate(timeout=120)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        rc = -9
    crashmark(f"record end {variant.name} exit={rc}")
    # Keep the record's stderr on disk: when a golden diff shows a stray
    # diagnostic, this is the only way to see which module emitted it.
    with open(os.path.join(TRACE_DIR, variant.name + ".stderr.txt"), "w") as f:
        f.write(err)
    return RecordResult(rc, out, err, trace, time.monotonic() - t0)


def query_trace(variant: Variant, trace: str) -> dict[str, int]:
    """One trace_processor invocation returning labeled scalar facts."""
    # trace_processor -q permits a single result-returning statement, so
    # every fact is one UNION ALL arm of one SELECT.
    like = lambda s: f"'%{s}%'"  # noqa: E731
    m = like(variant.mapping_pattern())
    # A frame counts as "named X" if either its symbolized name (from
    # stack_profile_symbol, the native/DWARF path) or its own frame.name (set
    # directly via function_name_id — how synthetic frames like the PY-1
    # recovered Python qualnames are named) matches. LEFT JOIN the symbol so
    # frames with no symbol_set_id (every synthetic frame) still match on
    # frame.name.
    leaf = like(variant.leaf)
    mid = like(variant.mid)
    outer = like(variant.outer)
    sql = f"""
WITH RECURSIVE anc(id, parent_id, frame_id) AS (
  SELECT c.id, c.parent_id, c.frame_id FROM stack_profile_callsite c
  JOIN stack_profile_frame f ON c.frame_id = f.id
  LEFT JOIN stack_profile_symbol s USING(symbol_set_id)
  WHERE s.name LIKE {leaf} OR f.name LIKE {leaf}
  UNION ALL
  SELECT p.id, p.parent_id, p.frame_id
  FROM stack_profile_callsite p JOIN anc a ON p.id = a.parent_id
)
SELECT 'samples' AS k, count(*) AS v FROM perf_sample
UNION ALL SELECT 'sessions', count(DISTINCT perf_session_id) FROM perf_sample
UNION ALL SELECT 'mapping', count(*) FROM stack_profile_mapping WHERE name LIKE {m}
UNION ALL SELECT 'leaf_syms', count(*)
  FROM stack_profile_frame f LEFT JOIN stack_profile_symbol s USING(symbol_set_id)
  WHERE s.name LIKE {leaf} OR f.name LIKE {leaf}
UNION ALL SELECT 'target_frames', count(*)
  FROM stack_profile_frame f JOIN stack_profile_mapping mp ON f.mapping = mp.id
  WHERE mp.name LIKE {m}
UNION ALL SELECT 'max_depth', coalesce(max(depth), 0) FROM stack_profile_callsite
UNION ALL SELECT 'chain',
  (SELECT count(DISTINCT CASE WHEN s.name LIKE {mid} OR f.name LIKE {mid} THEN 1
                              WHEN s.name LIKE {outer} OR f.name LIKE {outer} THEN 2 END)
   FROM anc JOIN stack_profile_frame f ON anc.frame_id = f.id
   LEFT JOIN stack_profile_symbol s USING(symbol_set_id)
   WHERE s.name LIKE {mid} OR f.name LIKE {mid}
      OR s.name LIKE {outer} OR f.name LIKE {outer});
"""
    p = subprocess.run([TP_SHELL, "-q", "/dev/stdin", trace],
                       input=sql, capture_output=True, text=True)
    facts: dict[str, int] = {}
    for line in p.stdout.splitlines():
        mo = re.match(r'^"([a-z_]+)",(-?\d+|\[NULL\])$', line)
        if mo:
            facts[mo.group(1)] = 0 if mo.group(2) == "[NULL]" else int(mo.group(2))
    return facts


def query_residual(trace: str) -> list[str]:
    """The distinct residual-frame labels present in the trace, sorted.

    DIA-6 records an unresolvable PC as a synthetic mapping whose name is the
    residual class — `[jit:<runtime>]` for anonymous executable (JIT) pages,
    `[anon]` / `[unmapped]` otherwise. A native, fully-symbolized capture emits
    none. js-node's hot leaf JITs into anonymous exec pages, so it surfaces
    `[jit:node]` here.
    """
    # trace_processor renders the synthetic mapping's path with a leading '/'
    # (it is stored as a normal mapping name), so match the label anywhere and
    # extract the bracketed class. LIKE treats '[' literally.
    #
    # A stray garbage FP-walk PC lands in [anon]/[unmapped] as one-off noise
    # that flaps run to run; the meaningful signal (js-node's JITed hot loop)
    # covers dozens of distinct PCs. Require a class to carry >= 5 distinct
    # frames so the golden reports only residuals that actually recur.
    sql = (
        "SELECT m.name FROM stack_profile_frame f "
        "JOIN stack_profile_mapping m ON f.mapping = m.id "
        "WHERE m.name LIKE '%[jit:%' OR m.name LIKE '%[anon]' "
        "OR m.name LIKE '%[anon-exec]' OR m.name LIKE '%[unmapped]' "
        "GROUP BY m.name HAVING count(*) >= 5;"
    )
    p = subprocess.run([TP_SHELL, "-q", "/dev/stdin", trace],
                       input=sql, capture_output=True, text=True)
    labels = set()
    for line in p.stdout.splitlines():
        mo = re.search(r'(\[[a-z0-9:_-]+\])', line)
        if mo:
            labels.add(mo.group(1))
    out = sorted(labels)
    # A JIT runtime frees code regions continuously, so a longer or throttled
    # run samples PCs in regions unmapped by trace end — expected churn there,
    # load-dependent, not a diagnostic. Native targets keep [unmapped]'s
    # meaning (a real attribution gap).
    if any(lbl.startswith("[jit:") for lbl in out):
        out = [lbl for lbl in out if lbl != "[unmapped]"]
    return out


MODULE_RE = re.compile(
    r"^\s*\[(ok|partial|unresolved|no symbols|no names)\s*\]\s+(\d+)/(\d+)\s+(.+)$")


def parse_module_report(stderr: str) -> list[tuple[str, int, int, str]]:
    out = []
    for line in stderr.splitlines():
        mo = MODULE_RE.match(line)
        if mo:
            out.append((mo.group(1), int(mo.group(2)), int(mo.group(3)), mo.group(4)))
    return out


# ----- golden facts -------------------------------------------------------

DEFAULT_DURATION_MS: int = 1500


# Diagnostic markers scanned in sismo's own stderr. Covers messages that exist
# today (bpf-init-failed, stripped/debuginfo hints, build-id/deleted-file) and
# ones the roadmap will add (frame-pointer, interpreted-runtime). When a new
# diagnostic lands it starts appearing in the goldens, and the diff prompts a
# --rewrite. That is the whole "gap closed → update expectation" flow.
DIAG_CATALOG: list[tuple[str, str]] = [
    ("bpf-init-failed", r"bpf capture init failed"),
    ("stripped", r"stripped|no debug info|debuginfo"),
    ("build-id", r"build[- ]id|readelf -n"),
    ("deleted-file", r"no longer at this path|deleted|binary changed since"),
    ("changed-file", r"changed since recording|build-id mismatch"),
    ("frame-pointer", r"frame pointer|omit-frame|force-frame-pointers"),
    ("unwind-tables", r"unwind tables|asynchronous-unwind|\.eh_frame FDE"),
    ("interpreted-runtime", r"interpreter frame|interpreted runtime|"
                            r"JIT frame|perf-?map|jitdump"),
    # macOS: task_for_pid denied — hardened-runtime targets (signed node/JDK
    # builds) refuse the task port unless sismo carries the debugger
    # entitlement (`sismo doctor --fix`), even for root.
    ("task-port", r"task_for_pid\(\d+\) failed|debugger entitlement"),
]


def variant_facts(variant: Variant, duration_ms: int = DEFAULT_DURATION_MS,
                  mac_live: bool = False) -> str:
    """Build + record + query one variant, returning normalized golden text.

    The text is the stable, observable facts — never raw sample counts or
    paths — so it is diffable against a checked-in golden. Sampling is
    nondeterministic, so the fine-grained facts (samples/leaf/chain) can flip
    on borderline variants; --rewrite absorbs that, and the aggregate ratchet
    (see the deferred design) is the eventual fix. Raises Skip when the
    toolchain or a build prerequisite is unavailable.

    `mac_live` is the cross-platform matrix suite's macOS live mode: the same
    build + record + query flow, with the record run under sudo (kperf/kdebug
    are root-only). The caller pre-checks sudo availability.
    """
    if mac_live:
        if platform.system() != "Darwin":
            raise Skip("macOS only")
    elif platform.system() != "Linux":
        raise Skip("Linux only")
    tool = variant.build[0][0] if variant.build else variant.cmd[0]
    if not (os.path.sep in tool and os.path.exists(tool)) and not shutil.which(tool):
        raise Skip(f"{tool} not available")
    try:
        run_build(variant)
    except BuildSkip as s:
        raise Skip(str(s))

    # Capture cmd[0]'s real build-id now — a deleted-binary variant removes the
    # file during the record, so this is the only chance to read it. Used as the
    # reference id only when the target module's own file is gone by symbolize time.
    prebuilt_bid = real_build_id(variant.cmd[0])

    rec = run_record(variant, duration_ms, mac_live=mac_live)
    facts = query_trace(variant, rec.trace) if os.path.exists(rec.trace) else {}

    samples = facts.get("samples", 0)
    samples_present = samples >= MIN_SAMPLES
    chain_n = facts.get("chain", 0)
    if not samples_present:
        chain = "none"
    elif chain_n >= variant.chain_need:
        chain = "full"
    elif chain_n >= 1:
        chain = "partial"
    else:
        chain = "truncated"

    modules = parse_module_report(rec.stderr)
    pat = variant.mapping_pattern()
    found = [st for (st, _d, _t, path) in modules if pat in path]
    module_status = found[0] if found else "absent"

    diagnostics = sorted(
        label for label, rx in DIAG_CATALOG if re.search(rx, rec.stderr))

    residual = query_residual(rec.trace) if os.path.exists(rec.trace) else []

    # build_id: what identity does the trace carry for the target module? `gnu`
    # means a real GNU note matching the module's own file (Linux captures it per
    # frame with BPF_F_USER_BUILD_ID); `synthetic` means sismo
    # fabricated an id, recognized precisely by its magic prefix; `absent` means
    # none at all; `mismatch` is a real-looking id that does not match the file —
    # expected for a replaced binary (env-replaced-binary), a capture bug on any
    # normal recording. The reference id is read from the
    # module's actual file (the trace path — e.g. the real libjvm.so, not the java
    # launcher in cmd[0]); only when that file is gone do we fall back to cmd[0].
    trace_exists = os.path.exists(rec.trace)
    trace_bid = query_build_id(variant, rec.trace) if trace_exists else ""
    target_path = query_target_path(variant, rec.trace) if trace_exists else ""
    if target_path and "(deleted)" not in target_path and os.path.exists(target_path):
        real_bid = real_build_id(target_path) or prebuilt_bid
    else:
        real_bid = prebuilt_bid
    if not trace_bid:
        build_id = "absent"
    elif trace_bid.startswith(SYNTH_MAGIC_HEX):
        build_id = "synthetic"
    elif real_bid and trace_bid == real_bid:
        # A real id matching the module's own file: a GNU note on ELF, the
        # LC_UUID on mach-o.
        build_id = "uuid" if mac_live else "gnu"
    else:
        build_id = "mismatch"

    lines = [
        f"record_exit: {rec.exit}",
        f"samples: {'present' if samples_present else 'absent'}",
        f"offcpu: {'present' if facts.get('sessions', 0) >= 2 else 'absent'}",
        f"mapping: {'present' if facts.get('mapping', 0) >= 1 else 'absent'}",
        f"leaf: {'symbolized' if facts.get('leaf_syms', 0) >= 1 else 'absent'}",
        f"chain: {chain}",
        f"module_status: {module_status}",
        f"build_id: {build_id}",
        f"diagnostics: {', '.join(diagnostics) if diagnostics else 'none'}",
        f"residual: {', '.join(residual) if residual else 'none'}",
    ]
    return "\n".join(lines) + "\n"


def real_build_id(path: str) -> str:
    """The file's build identity as lowercase hex — GNU build-id note on ELF,
    host-arch LC_UUID on mach-o — or '' if it has none. Captured before the
    record, since a deleted-binary variant removes the file mid-run."""
    if platform.system() == "Darwin":
        arch = "arm64" if platform.machine() == "arm64" else "x86_64"
        try:
            p = subprocess.run(["dwarfdump", "--uuid", path],
                               capture_output=True, text=True)
        except OSError:
            return ""
        for line in p.stdout.splitlines():
            if line.startswith("UUID:") and f"({arch})" in line:
                return line.split()[1].replace("-", "").lower()
        return ""
    try:
        p = subprocess.run(["readelf", "-n", path], capture_output=True, text=True)
    except OSError:
        return ""
    mo = re.search(r"Build ID:\s*([0-9a-f]+)", p.stdout)
    return mo.group(1).lower() if mo else ""


def query_build_id(variant: Variant, trace: str) -> str:
    """The build-id (lowercase hex) the trace carries for the target module, or
    '' if none. trace_processor stores build_id already as a hex string, so read
    it directly (hex()-ing it would double-encode)."""
    pat = f"'%{variant.mapping_pattern()}%'"
    sql = ("SELECT lower(build_id) FROM __intrinsic_stack_profile_mapping "
           f"WHERE name LIKE {pat} AND build_id IS NOT NULL AND build_id != '' LIMIT 1;")
    p = subprocess.run([TP_SHELL, "-q", "/dev/stdin", trace],
                       input=sql, capture_output=True, text=True)
    for line in p.stdout.splitlines():
        mo = re.match(r'^"([0-9a-f]+)"$', line)
        if mo:
            return mo.group(1)
    return ""


def query_target_path(variant: Variant, trace: str) -> str:
    """The on-disk path the trace records for the target module (e.g. the actual
    libjvm.so, not the java launcher). '' if none."""
    pat = f"'%{variant.mapping_pattern()}%'"
    sql = ("SELECT name FROM __intrinsic_stack_profile_mapping "
           f"WHERE name LIKE {pat} AND build_id IS NOT NULL AND build_id != '' LIMIT 1;")
    p = subprocess.run([TP_SHELL, "-q", "/dev/stdin", trace],
                       input=sql, capture_output=True, text=True)
    for line in p.stdout.splitlines():
        # Skip the CSV header row ("name"); mappings are absolute paths.
        mo = re.match(r'^"(/.+)"$', line)
        if mo:
            return mo.group(1)
    return ""


_headroom_reserved = False


def reserve_cpu_headroom() -> None:
    """Pin this run and its build/record children off four CPUs so the machine
    stays usable — parallel toolchain builds and the hot-loop workloads
    otherwise saturate every core. Children inherit the affinity. Note this
    only bounds userspace: kernel-side work (BPF programs, perf interrupts,
    ftrace) runs on every CPU regardless. Idempotent, so running several
    suites in one process doesn't stack reservations."""
    global _headroom_reserved
    if _headroom_reserved or not hasattr(os, "sched_setaffinity"):
        return
    try:
        avail = sorted(os.sched_getaffinity(0))
        reserve = min(4, len(avail) - 1)
        if reserve > 0:
            os.sched_setaffinity(0, set(avail[:-reserve]))
        _headroom_reserved = True
    except OSError:
        pass


def run(ctx: SuiteContext) -> int:
    reserve_cpu_headroom()
    if platform.system() == "Linux" and not ensure_record_env():
        print("skip matrix-linux (recording env not ready — "
              "run: sudo sismo doctor --fix)")
        return 0
    needs = [SISMO, TP_SHELL]
    cases = [
        (v.name, functools.partial(variant_facts, v), needs)
        for v in build_variants()
    ]
    _passed, failed, _skipped = run_golden_cases(ctx, NAME, cases)
    return failed
