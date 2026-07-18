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

# python/tools/diff_suites/common.py -> repo root is four levels up.
ROOT_DIR: str = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

SISMO: str = os.path.join(ROOT_DIR, "crates", "sismo", "target", "debug", "sismo")
SISMO_RUN: str = os.path.join(ROOT_DIR, "crates", "sismo-run", "target", "debug", "sismo-run")
SAMPLE_TARGET: str = os.path.join(ROOT_DIR, "crates", "sismo", "target", "debug", "sample-target")
TP_SHELL: str = os.path.join(
    ROOT_DIR, "third_party", "src", "perfetto", "out", "sismo", "trace_processor_shell")
GOLDEN_DIR: str = os.path.join(ROOT_DIR, "tests", "diff")


class Skip(Exception):
    """A case's environment can't run it (missing prereq), vs. a failure."""


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
        try:
            actual = produce()
        except Skip as s:
            print(f"skip {label} ({s})")
            skipped += 1
            continue

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
