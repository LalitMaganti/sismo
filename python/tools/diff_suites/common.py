# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""Shared plumbing for difftest suites.

Modeled on syntaqlite's diff-test framework: a small set of suites, each a
module exposing NAME / DESCRIPTION / run(ctx), over one shared diff+rebaseline
core. A suite's only job is to produce, per case, normalized text that is
compared against a checked-in golden under tests/diff/<suite>/<name>.txt.
"""

from __future__ import annotations

import dataclasses
import difflib
import os
import subprocess
import sys
import time

# python/tools/diff_suites/common.py -> repo root is four levels up.
ROOT_DIR: str = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

SISMO: str = os.path.join(ROOT_DIR, "crates", "sismo", "target", "debug", "sismo")
SAMPLE_TARGET: str = os.path.join(ROOT_DIR, "crates", "sismo", "target", "debug", "sample-target")
TP_SHELL: str = os.path.join(
    ROOT_DIR, "third_party", "src", "perfetto", "out", "sismo", "trace_processor_shell")
GOLDEN_DIR: str = os.path.join(ROOT_DIR, "tests", "diff")


class Skip(Exception):
    """A case's environment can't run it (missing prereq), vs. a failure."""


def crashmark(msg: str) -> None:
    """Append an fsync'd breadcrumb to $SISMO_CRASHLOG (same file and line
    shape as sismo's own crashlog sink), so a hard machine lockup can be
    bracketed to the exact case and phase in flight. No-op when unset."""
    path = os.environ.get("SISMO_CRASHLOG")
    if not path:
        return
    with open(path, "a") as f:
        f.write(f"{int(time.time() * 1000)} - {os.getpid()} [difftest] {msg}\n")
        f.flush()
        os.fsync(f.fileno())


def sismo_has_caps() -> bool:
    """Whether the sismo binary carries its recording file caps (Linux).

    Every rebuild sheds the security.capability xattr `sismo doctor --fix`
    grants, so recording suites re-check before each run.
    """
    try:
        os.getxattr(SISMO, "security.capability")
        return True
    except OSError:
        return False


def tracefs_usable() -> bool:
    """Same probes the record path uses: tracepoint ids readable (off-CPU)
    and tracing_on writable (ftrace)."""
    for base in ("/sys/kernel/tracing", "/sys/kernel/debug/tracing"):
        if (os.access(os.path.join(base, "events", "syscalls", "sys_enter_futex", "id"),
                      os.R_OK)
                and os.access(os.path.join(base, "tracing_on"), os.W_OK)):
            return True
    return False


def ensure_record_env() -> bool:
    """Make sure sismo can record unprivileged: file caps on the binary
    (rebuilds shed them) and readable tracefs (reboots shed that).

    Tries a passwordless `sudo -n sismo doctor --fix -y` first (a no-op unless
    a NOPASSWD sudoers rule covers it). Returns False when recording would
    still be degraded — callers should skip with a pointer to
    `sudo sismo doctor --fix`.
    """
    if sys.platform != "linux" or not os.path.exists(SISMO):
        return True
    if not (sismo_has_caps() and tracefs_usable()):
        try:
            subprocess.run(["sudo", "-n", SISMO, "doctor", "--fix", "-y"],
                           capture_output=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired):
            pass
    return sismo_has_caps() and tracefs_usable()


@dataclasses.dataclass
class SuiteContext:
    """The shared bag passed to every suite's run(ctx)."""

    rebaseline: bool = False
    name_filter: str | None = None   # substring filter on case names
    verbose: bool = False


def golden_path(suite: str, name: str) -> str:
    return os.path.join(GOLDEN_DIR, suite, name + ".txt")


def run_golden_cases(ctx: SuiteContext, suite: str, cases) -> tuple[int, int, int]:
    """Run (name, produce_fn, needs) cases against on-disk goldens.

    produce_fn returns normalized text or raises Skip. Returns
    (passed, failed, skipped). Honors ctx.rebaseline and ctx.name_filter.
    """
    passed = failed = skipped = 0
    for name, produce, needs in cases:
        label = f"{suite}/{name}"
        if ctx.name_filter and ctx.name_filter not in name:
            continue
        if not all(os.path.exists(p) for p in needs):
            print(f"skip {label} (prereq not built)")
            skipped += 1
            continue
        crashmark(f"case begin {label}")
        try:
            actual = produce()
        except Skip as s:
            print(f"skip {label} ({s})")
            crashmark(f"case skip {label}")
            skipped += 1
            continue
        crashmark(f"case end {label}")

        gp = golden_path(suite, name)
        if ctx.rebaseline:
            os.makedirs(os.path.dirname(gp), exist_ok=True)
            with open(gp, "w") as f:
                f.write(actual)
            print(f"rewrote {label}")
            passed += 1
            continue

        if not os.path.exists(gp):
            print(f"FAIL {label}: no golden (run --rebaseline)")
            failed += 1
            continue
        with open(gp) as f:
            expected = f.read()
        if actual == expected:
            print(f"ok   {label}")
            passed += 1
        else:
            failed += 1
            print(f"FAIL {label}:")
            for line in difflib.unified_diff(
                    expected.splitlines(), actual.splitlines(),
                    "golden", "actual", lineterm=""):
                print(f"  {line}")
    return passed, failed, skipped
