# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""matrix suite — the cross-platform compatibility matrix.

Build shapes whose scenario exists on every supported OS: clang DWARF and
ThinLTO, inline-frame fidelity, C++ demangling, Rust, Go, Zig, the
interpreted/JIT runtimes, and the replaced-binary safety net. Each case has
one variant per OS, defined by the platform module that owns the machinery
(matrix_linux / matrix_mac), and one golden per mode:

  <case>.linux.txt       Linux live record (BPF) — capture + symbolize quality
  <case>.macos.txt       macOS offline — build fixture, synthesize the kperf
                         trace shape, `sismo symbolize` (unprivileged)
  <case>.macos-live.txt  macOS live record — the same workload recorded
                         through kperf/kdebug, which are root-only, so the
                         record runs under `sudo`

The goldens differ per mode because the observable facts legitimately do.
The macOS live cases self-skip unless euid is 0 or sudo has cached
credentials (`sudo -v` first, or run the whole difftest under sudo) — the
suite never prompts. Interpreter/JIT cases are live-only on macOS: their
value is runtime frames, which the offline synth flow cannot fabricate.
Shapes that only exist on one OS live in matrix-linux and matrix-mac.

Default-on where something is always cheap to run (macOS: the offline
half); opt-in on Linux, where recording needs a setcap'd sismo-run — run it
there with `tools/difftest --suite matrix`.
"""

from __future__ import annotations

import functools
import os
import platform
import subprocess

from python.tools.diff_suites import matrix_linux, matrix_mac
from python.tools.diff_suites.common import (
    SISMO, SISMO_RUN, TP_SHELL, Skip, SuiteContext, run_golden_cases)

NAME = "matrix"
DESCRIPTION = "cross-platform build shapes, one golden per OS/mode"
ENABLED_BY_DEFAULT = platform.system() == "Darwin"

# The canonical cross-platform case list: (name, offline_on_mac). Every
# platform module's cross_variants() must cover exactly these names; cases
# without a mac offline variant are interpreter/JIT runtimes, testable on
# macOS only by live-recording them.
CROSS_CASES = [
    ("c-clang-dwarf4", True),
    ("c-clang-thinlto", True),
    ("c-clang-inline", True),
    ("cpp-clang", True),
    ("rust-debug", True),
    ("rust-release", True),
    ("rust-release-stripped", True),
    ("go-default", True),
    ("zig-debug", True),
    ("zig-releasefast", True),
    ("env-replaced-binary", True),
    ("py-cpython", False),
    ("js-node", False),
    ("js-node-perfmap", False),
    ("jvm-java", False),
]
CROSS_NAMES = [n for n, _ in CROSS_CASES]
MAC_OFFLINE_NAMES = [n for n, offline in CROSS_CASES if offline]


def _check(variants: dict, expected: list[str], side: str) -> None:
    if sorted(variants) != sorted(expected):
        missing = set(expected) - set(variants)
        extra = set(variants) - set(expected)
        raise RuntimeError(f"{side} cross_variants out of sync: "
                           f"missing={missing} extra={extra}")


@functools.lru_cache(maxsize=1)
def _mac_live_ready() -> str | None:
    """None when live capture can run, else the skip reason. Never prompts:
    sudo is only probed non-interactively, against the sismo binary itself so
    a sudoers NOPASSWD rule scoped to sismo is enough."""
    if os.geteuid() != 0:
        probe = subprocess.run(["sudo", "-n", SISMO, "--help"],
                               capture_output=True)
        if probe.returncode != 0:
            return ("live capture needs root (run `sudo -v`, or add a "
                    "NOPASSWD rule for sismo)")
    # Hardened-runtime targets (signed node/JDK builds) deny task_for_pid —
    # even to root — unless sismo carries the debugger entitlement. A cargo
    # rebuild sheds the signature, so re-apply it (ad-hoc, local, idempotent)
    # rather than let those cases quietly record zero samples.
    doc = subprocess.run([SISMO, "doctor"], capture_output=True, text=True)
    if "missing com.apple.security.cs.debugger" in doc.stdout + doc.stderr:
        fix = subprocess.run([SISMO, "doctor", "--fix", "--yes"],
                             capture_output=True)
        if fix.returncode != 0:
            return "sismo doctor --fix failed (task-access entitlement)"
    return None


def _live_case(variant):
    def produce() -> str:
        reason = _mac_live_ready()
        if reason:
            raise Skip(reason)
        return matrix_linux.variant_facts(variant, mac_live=True)
    return produce


def run(ctx: SuiteContext) -> int:
    sysname = platform.system()
    if sysname == "Linux":
        matrix_linux.reserve_cpu_headroom()
        variants = matrix_linux.cross_variants()
        _check(variants, CROSS_NAMES, "linux")
        needs = [SISMO_RUN, TP_SHELL, SISMO]
        cases = [(f"{n}.linux",
                  functools.partial(matrix_linux.variant_facts, variants[n]),
                  needs) for n in CROSS_NAMES]
    elif sysname == "Darwin":
        offline = matrix_mac.cross_variants()
        _check(offline, MAC_OFFLINE_NAMES, "mac offline")
        live = matrix_linux.cross_variants()
        _check(live, CROSS_NAMES, "mac live")
        needs = [SISMO, TP_SHELL]
        cases = [(f"{n}.macos", matrix_mac.variant_case(offline[n]), needs)
                 for n in MAC_OFFLINE_NAMES]
        cases += [(f"{n}.macos-live", _live_case(live[n]), needs)
                  for n in CROSS_NAMES]
    else:
        print(f"skip matrix ({sysname} unsupported)")
        return 0
    _, failed, _ = run_golden_cases(ctx, NAME, cases)
    return failed
