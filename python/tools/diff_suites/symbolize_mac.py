# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""The mach-o offline-symbolization suite (macOS, unprivileged).

Verifies the deferred half of record/symbolize on macOS without touching
kperf/kdebug (which need root): each case builds a fixture binary in one
mach-o shape (dSYM, symtab-only, stripped, stripped+dSYM, fat, -no_uuid,
deleted, dyld-shared-cache system dylib), synthesizes the exact trace shape
the kperf emitter produces — mappings keyed by LC_UUID with load_bias =
image base, frames as absolute PCs — runs `sismo symbolize` over it, and
goldens what resolved: per-module status, which marker functions got names,
whether line info came through, and which diagnostics fired.

The golden records *current* behavior, matrix-style: when a roadmap item
improves one of these shapes, the diff fails and prompts --rebaseline.
"""

from __future__ import annotations

import ctypes
import os
import platform
import shutil
import struct
import subprocess
import tempfile

from python.tools.diff_suites.common import (
    SISMO, TP_SHELL, Skip, SuiteContext, run_golden_cases)

NAME = "macho"
DESCRIPTION = "mach-o offline symbolization (macOS, unprivileged)"
# Default-on: every case self-skips off-macOS or when sismo/tp aren't built.
ENABLED_BY_DEFAULT = True

FIXTURE_SRC = """\
#include <stdio.h>

__attribute__((noinline)) int sismo_fix_leaf(int x) {
    int acc = 0;
    for (int i = 0; i < x; i++) acc += i * i;
    return acc;
}

__attribute__((noinline)) int sismo_fix_mid(int x) {
    return sismo_fix_leaf(x) + 1;
}

int main(void) {
    printf("%d\\n", sismo_fix_mid(100));
    return 0;
}
"""

MARKERS = ["sismo_fix_leaf", "sismo_fix_mid", "main"]

# stderr lines mapped to stable diagnostic keys (the macho DIAG_CATALOG).
DIAG_CATALOG = [
    ("no symbols could be loaded", "load-failed"),
    ("no longer at this path", "missing-file"),
    ("has no build-id", "no-build-id"),
    ("did not fully symbolize", "partial"),
]

SEQ_ID = 0x42

# ---- protobuf wire helpers ---------------------------------------------------


def _varint(v: int) -> bytes:
    out = b""
    while True:
        b7 = v & 0x7F
        v >>= 7
        if v:
            out += bytes([b7 | 0x80])
        else:
            return out + bytes([b7])


def _key(field: int, wire: int) -> bytes:
    return _varint((field << 3) | wire)


def _fv(field: int, v: int) -> bytes:
    return _key(field, 0) + _varint(v)


def _fb(field: int, b: bytes) -> bytes:
    return _key(field, 2) + _varint(len(b)) + b


# ---- fixture builds ----------------------------------------------------------


def host_arch() -> str:
    return "arm64" if platform.machine() == "arm64" else "x86_64"


def build_fixture(work: str, *, debug: bool, fat: bool = False,
                  no_uuid: bool = False, dsym: bool = False,
                  strip: bool = False) -> str:
    """Build fixture.c into <work>/fixture in the requested shape; return its
    path. Symbol addresses must be read (nm) before a `strip`."""
    src = os.path.join(work, "fixture.c")
    with open(src, "w") as f:
        f.write(FIXTURE_SRC)
    binp = os.path.join(work, "fixture")
    arch = ["-arch", "arm64", "-arch", "x86_64"] if fat else []
    link = ["-Wl,-no_uuid"] if no_uuid else []
    if debug and not fat:
        # Compile via a kept .o so the debug map (N_OSO) — and any dSYM built
        # from it — carries real DWARF.
        obj = os.path.join(work, "fixture.o")
        subprocess.run(["clang", "-g", "-O1", "-c", src, "-o", obj], check=True)
        subprocess.run(["clang", obj, "-o", binp] + link, check=True)
    else:
        flags = ["-g"] if debug else []
        subprocess.run(["clang", "-O1"] + flags + arch + link + [src, "-o", binp],
                       check=True)
    if dsym:
        subprocess.run(["dsymutil", binp], check=True)
    if strip:
        subprocess.run(["strip", binp], check=True)
    return binp


def macho_uuid(path: str, arch: str) -> bytes | None:
    out = subprocess.run(["dwarfdump", "--uuid", path],
                         capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "UUID:" and f"({arch})" in line:
            return bytes.fromhex(parts[1].replace("-", ""))
    return None


def nm_addrs(path: str, arch: str, names) -> dict[str, int]:
    cmd = ["nm", "-arch", arch, path]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    addrs = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2].lstrip("_") in names:
            addrs[parts[2].lstrip("_")] = int(parts[0], 16)
    missing = [n for n in names if n not in addrs]
    if missing:
        raise Skip(f"nm missing {missing}")
    return addrs


def text_vmsize(path: str, arch: str) -> int:
    out = subprocess.run(["otool", "-arch", arch, "-l", path],
                         capture_output=True, text=True, check=True).stdout
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if "segname __TEXT" in line:
            for j in range(i, min(i + 6, len(lines))):
                if "vmsize" in lines[j]:
                    return int(lines[j].split()[1], 16)
    raise Skip("no __TEXT vmsize")


def dyld_cache_module(target: bytes, symbol: str):
    """A system dylib as loaded into this process: (path, base, end, uuid,
    symbol_pc). For cache-only dylibs there is no on-disk file at all."""
    libc = ctypes.CDLL(None)
    libc._dyld_image_count.restype = ctypes.c_uint32
    libc._dyld_get_image_name.restype = ctypes.c_char_p
    libc._dyld_get_image_name.argtypes = [ctypes.c_uint32]
    libc._dyld_get_image_header.restype = ctypes.c_void_p
    libc._dyld_get_image_header.argtypes = [ctypes.c_uint32]
    base = None
    for i in range(libc._dyld_image_count()):
        if libc._dyld_get_image_name(i) == target:
            base = libc._dyld_get_image_header(i)
            break
    if base is None:
        raise Skip(f"{target.decode()} not loaded")
    hdr = ctypes.string_at(base, 32)
    magic, _, _, _, ncmds, _ = struct.unpack("<IiiIII", hdr[:24])
    if magic != 0xFEEDFACF:
        raise Skip("unexpected mach header")
    off, uuid, vmsize = 32, None, None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack("<II", ctypes.string_at(base + off, 8))
        if cmd == 0x1B:  # LC_UUID
            uuid = ctypes.string_at(base + off + 8, 16)
        elif cmd == 0x19:  # LC_SEGMENT_64
            body = ctypes.string_at(base + off + 8, 64)
            if body[:16].rstrip(b"\0") == b"__TEXT":
                vmsize = struct.unpack("<Q", body[24:32])[0]
        off += cmdsize
    sym_pc = ctypes.cast(getattr(libc, symbol), ctypes.c_void_p).value
    if not (uuid and vmsize and sym_pc):
        raise Skip(f"{target.decode()} introspection failed")
    return target.decode(), base, base + vmsize, uuid, sym_pc


# ---- trace synthesis ---------------------------------------------------------


def synth_trace(out_path: str, modules, frames) -> None:
    """modules: [{iid, path(bytes), build_id(bytes), base, end}], frames:
    [(frame_iid, mapping_iid, abs_pc)] root-first. Emits the kperf emitter's
    shape: defaults packet, then one interning sample packet + repeats."""

    def packet(body):
        return _fb(1, body)

    # PerfSampleDefaults.timebase.name = "cpu-ns", sample_scope = THREAD(2).
    psd = _fb(1, _fb(10, b"cpu-ns")) + _fv(5, 2)
    defaults = packet(_fv(10, SEQ_ID) + _fv(13, 1) + _fb(59, _fb(12, psd)))

    def sample(ts, intern):
        idata = b""
        if intern:
            for m in modules:
                idata += _fb(17, _fv(1, m["iid"]) + _fb(2, m["path"]))
                if m["build_id"]:
                    idata += _fb(16, _fv(1, m["iid"]) + _fb(2, m["build_id"]))
                mp = _fv(1, m["iid"])
                if m["build_id"]:
                    mp += _fv(2, m["iid"])
                mp += (_fv(4, m["base"]) + _fv(5, m["end"]) +
                       _fv(6, m["base"]) + _fv(8, 0) + _fv(7, m["iid"]))
                idata += _fb(19, mp)
            for fiid, miid, pc in frames:
                idata += _fb(6, _fv(1, fiid) + _fv(3, miid) + _fv(4, pc))
            idata += _fb(7, _fv(1, 1) + b"".join(_fv(2, f) for f, _, _ in frames))
        ps = _fv(1, 0) + _fv(2, 4242) + _fv(3, 4242) + _fv(4, 1) + _fv(6, 250000)
        body = _fv(8, ts) + _fv(10, SEQ_ID) + _fv(13, 2)
        if idata:
            body += _fb(12, idata)
        return packet(body + _fb(66, ps))

    trace = defaults
    for i in range(20):  # clears the MIN_SAMPLES=16 diagnostic floor
        trace += sample(1_000_000 * (i + 1), intern=(i == 0))
    with open(out_path, "wb") as f:
        f.write(trace)


SLIDE = 0x4000
LINK_BASE = 0x100000000


def fixture_module_and_frames(binp: str, arch: str, build_id: bytes):
    addrs = nm_addrs(binp, arch, MARKERS)
    vmsize = text_vmsize(binp, arch)
    base = LINK_BASE + SLIDE
    mod = dict(iid=1, path=binp.encode(), build_id=build_id,
               base=base, end=base + vmsize)
    frames = [(i + 1, 1, addrs[n] + SLIDE + 4)
              for i, n in enumerate(["main", "sismo_fix_mid", "sismo_fix_leaf"])]
    return mod, frames


# ---- fact extraction ---------------------------------------------------------


def query_frames(trace: str) -> list[tuple[int, str, int]]:
    sql = ("select spf.rel_pc, coalesce(sym.name, ''), "
           "coalesce(sym.line_number, 0) "
           "from __intrinsic_stack_profile_frame spf "
           "left join __intrinsic_stack_profile_symbol sym "
           "on sym.symbol_set_id = spf.symbol_set_id")
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
            rows.append((int(parts[0]), parts[1].strip('"'), int(parts[2])))
    return rows


def facts(trace: str, work: str, stderr: str) -> str:
    lines_out = []
    # Per-module report lines from the symbolize pass, workdir-normalized.
    for line in stderr.splitlines():
        s = line.strip()
        if s.startswith("[") and "]" in s:
            status, rest = s.split("]", 1)
            parts = rest.split()
            counts, path = parts[0], " ".join(parts[1:])
            path = path.replace(work, "$WORK")
            lines_out.append(f"module: {status.strip('[ ')}{'':<0} {counts} {path}")
    rows = query_frames(trace)
    named = {r[1] for r in rows}
    marker_facts = " ".join(
        f"{m}={'yes' if m in named else 'no'}" for m in MARKERS)
    lines_out.append(f"names: {marker_facts}")
    has_lines = any(r[2] > 0 for r in rows)
    lines_out.append(f"lines: {'yes' if has_lines else 'no'}")
    diags = sorted({key for needle, key in DIAG_CATALOG if needle in stderr})
    lines_out.append(f"diags: {', '.join(diags) if diags else '(none)'}")
    return "\n".join(lines_out) + "\n"


def sys_facts(trace: str, stderr: str, symbol: str) -> str:
    rows = query_frames(trace)
    named = {r[1] for r in rows}
    out = [f"names: {symbol}={'yes' if symbol in named else 'no'}"]
    diags = sorted({key for needle, key in DIAG_CATALOG if needle in stderr})
    out.append(f"diags: {', '.join(diags) if diags else '(none)'}")
    return "\n".join(out) + "\n"


# ---- cases -------------------------------------------------------------------


def _require_macos() -> None:
    if platform.system() != "Darwin":
        raise Skip("macOS only")


def run_symbolize(trace: str) -> str:
    r = subprocess.run([SISMO, "symbolize", trace], capture_output=True, text=True)
    return r.stderr


def fixture_case(*, build_kw, synthetic_id=False, delete_after_synth=False):
    def produce() -> str:
        _require_macos()
        work = tempfile.mkdtemp(prefix="sismo-macho-")
        try:
            arch = host_arch()
            binp = build_fixture(work, **build_kw)
            uuid = macho_uuid(binp, arch)
            if synthetic_id:
                # The registry's stand-in for a UUID-less image: the magic
                # prefix + deterministic tail (the real one is random).
                build_id = b"SISMOSYN" + bytes(range(8))
                if uuid is not None:
                    raise Skip("-no_uuid still produced a UUID")
            else:
                if uuid is None:
                    raise Skip("no UUID in fixture")
                build_id = uuid
            # nm before any strip: build_fixture strips last, so re-read here
            # would fail — read addresses first, then strip.
            mod, frames = fixture_module_and_frames(binp, arch, build_id)
            trace = os.path.join(work, "t.pftrace")
            synth_trace(trace, [mod], frames)
            if delete_after_synth:
                os.unlink(binp)
            stderr = run_symbolize(trace)
            return facts(trace, work, stderr)
        finally:
            shutil.rmtree(work, ignore_errors=True)
    return produce


def dyld_cache_case(target: bytes, symbol: str):
    def produce() -> str:
        _require_macos()
        work = tempfile.mkdtemp(prefix="sismo-macho-")
        try:
            path, base, end, uuid, sym_pc = dyld_cache_module(target, symbol)
            mod = dict(iid=1, path=path.encode(), build_id=uuid, base=base, end=end)
            trace = os.path.join(work, "t.pftrace")
            synth_trace(trace, [mod], [(1, 1, sym_pc + 4)])
            stderr = run_symbolize(trace)
            return sys_facts(trace, stderr, symbol)
        finally:
            shutil.rmtree(work, ignore_errors=True)
    return produce


def stripped_case(*, dsym: bool):
    def produce() -> str:
        _require_macos()
        work = tempfile.mkdtemp(prefix="sismo-macho-")
        try:
            arch = host_arch()
            binp = build_fixture(work, debug=True, dsym=dsym)
            uuid = macho_uuid(binp, arch)
            if uuid is None:
                raise Skip("no UUID in fixture")
            mod, frames = fixture_module_and_frames(binp, arch, uuid)
            subprocess.run(["strip", binp], check=True)
            trace = os.path.join(work, "t.pftrace")
            synth_trace(trace, [mod], frames)
            stderr = run_symbolize(trace)
            return facts(trace, work, stderr)
        finally:
            shutil.rmtree(work, ignore_errors=True)
    return produce


def run(ctx: SuiteContext) -> int:
    needs = [SISMO, TP_SHELL]
    cases = [
        # dSYM adjacent to the binary: full names + line info.
        ("dsym", fixture_case(build_kw=dict(debug=True, dsym=True)), needs),
        # Debug-map binary, no dSYM: wholesym follows N_OSO to the kept .o.
        ("debugmap", fixture_case(build_kw=dict(debug=True)), needs),
        # No -g at all: symtab names only.
        ("symtab-only", fixture_case(build_kw=dict(debug=False)), needs),
        # Fully stripped, no dSYM: what little survives.
        ("stripped", stripped_case(dsym=False), needs),
        # Stripped binary + adjacent dSYM: names + lines come back.
        ("stripped-dsym", stripped_case(dsym=True), needs),
        # Universal binary: the host-arch slice resolves via its UUID.
        ("fat", fixture_case(build_kw=dict(debug=False, fat=True)), needs),
        # -no_uuid link: trace carries the registry's synthetic id; names
        # still resolve by path, and the no-build-id diagnostic names -no_uuid.
        ("no-uuid", fixture_case(build_kw=dict(debug=False, no_uuid=True),
                                 synthetic_id=True), needs),
        # Deleted before the offline pass with no held fd: the documented
        # offline limitation.
        ("deleted", fixture_case(build_kw=dict(debug=False),
                                 delete_after_synth=True), needs),
        # libsystem_kernel has an on-disk file — resolves by path.
        ("sys-on-disk", dyld_cache_case(
            b"/usr/lib/system/libsystem_kernel.dylib", "close"), needs),
        # libsystem_c is cache-only since Big Sur: no on-disk file, resolves
        # from the dyld shared cache member's nlist (sismo-macho's own
        # reader — wholesym mis-probes the macOS 26 subcache names).
        ("sys-cache-only", dyld_cache_case(
            b"/usr/lib/system/libsystem_c.dylib", "atoi"), needs),
    ]
    _, failed, _ = run_golden_cases(ctx, NAME, cases)
    return failed
