# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""Sismo diff tests — one harness for all golden tests.

Each case produces normalized text and is compared to a golden file under
tests/diff/<group>/<name>.txt. Modeled on Perfetto's diff testing: declarative
cases, golden files in-tree, `--rewrite` to regenerate.

  tools/difftest                 # every available case
  tools/difftest cli             # only the 'cli' group
  tools/difftest --rewrite       # regenerate goldens for the run cases

Groups:
  cli    — runs the `sismo` binary with fixed argv; goldens the
           stdout/stderr/exit surface. Deterministic, no privileges.
  trace  — records sample-target through the BPF sampler and queries the
           trace; goldens stable structural facts (not raw sample counts).
           Needs zig-out/bin/sismo-run with BPF caps + the Perfetto build, so
           it's hardware-only and not part of the fast CI gate.
"""

from __future__ import annotations

import argparse
import difflib
import os
import subprocess
import sys
import tempfile

ROOT_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIN: str = os.path.join(ROOT_DIR, "zig-out", "bin")
SISMO: str = os.path.join(BIN, "sismo")
SISMO_RUN: str = os.path.join(BIN, "sismo-run")
SAMPLE_TARGET: str = os.path.join(BIN, "sample-target")
TP_SHELL: str = os.path.join(
    ROOT_DIR, "third_party", "src", "perfetto", "out", "sismo", "trace_processor_shell"
)
GOLDEN_DIR: str = os.path.join(ROOT_DIR, "tests", "diff")


class Skip(Exception):
    """Raised by a case fn when its environment can't run it (vs. a failure)."""


# ----- cli group ----------------------------------------------------------


def cli_actual(argv: list[str]) -> str:
    p = subprocess.run([SISMO] + argv, capture_output=True)
    out = p.stdout.decode(errors="replace")
    err = p.stderr.decode(errors="replace")
    return (
        f"$ sismo {' '.join(argv)}\n"
        f"exit: {p.returncode}\n"
        f"--- stdout ---\n{out}\n--- stderr ---\n{err}"
    )


# ----- trace group --------------------------------------------------------


def tp_scalar(trace: str, sql: str) -> int:
    out = subprocess.run(
        [TP_SHELL, "-q", "/dev/stdin", trace],
        input=sql.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ).stdout.decode()
    rows = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return int(rows[-1]) if rows and rows[-1].lstrip("-").isdigit() else 0


def cpu_symbolize_actual() -> str:
    """Record sample-target and assert its own frames symbolize — guards the
    whole user-frame path (proc_maps parse, FFI, base_avma/build-id, symbolizer).
    """
    with tempfile.NamedTemporaryFile(suffix=".pftrace", delete=False) as tf:
        trace = tf.name
    try:
        rec = subprocess.run(
            [SISMO_RUN, "record", "--output", trace, SAMPLE_TARGET, "1500"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
        )
        if rec.returncode != 0 or not os.path.getsize(trace):
            raise Skip("recording produced no trace (BPF caps on sismo-run?)")
        mapping = tp_scalar(
            trace,
            "SELECT count(*) FROM stack_profile_mapping "
            "WHERE name LIKE '%sample-target%';",
        )
        busy = tp_scalar(
            trace,
            "SELECT count(*) FROM stack_profile_symbol s "
            "JOIN stack_profile_frame f USING(symbol_set_id) "
            "JOIN stack_profile_mapping m ON f.mapping = m.id "
            "WHERE m.name LIKE '%sample-target%' AND s.name LIKE '%busyWorker%';",
        )
        return (
            f"sample_target_mapping_present: {mapping >= 1}\n"
            f"busyworker_symbolized: {busy >= 1}\n"
        )
    finally:
        if os.path.exists(trace):
            os.unlink(trace)


# ----- registry -----------------------------------------------------------


class Case:
    def __init__(self, group, name, fn, needs):
        self.group, self.name, self.fn, self.needs = group, name, fn, needs

    def available(self) -> bool:
        return all(os.path.exists(p) for p in self.needs)

    def golden(self) -> str:
        return os.path.join(GOLDEN_DIR, self.group, self.name + ".txt")


CASES: list[Case] = [
    Case("cli", "no_args", lambda: cli_actual([]), [SISMO]),
    Case("cli", "help_flag", lambda: cli_actual(["--help"]), [SISMO]),
    Case("cli", "help_short", lambda: cli_actual(["-h"]), [SISMO]),
    Case("cli", "help_word", lambda: cli_actual(["help"]), [SISMO]),
    Case("cli", "unknown_subcommand", lambda: cli_actual(["boguscmd"]), [SISMO]),
    Case("trace", "cpu_symbolize", cpu_symbolize_actual, [SISMO_RUN, SAMPLE_TARGET, TP_SHELL]),
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("groups", nargs="*", help="groups to run (default: all)")
    parser.add_argument("--rewrite", action="store_true", help="regenerate goldens")
    args = parser.parse_args()

    cases = [c for c in CASES if not args.groups or c.group in args.groups]
    if not cases:
        print(f"no cases for groups {args.groups}", file=sys.stderr)
        return 1

    passed = failed = skipped = 0
    for c in cases:
        label = f"{c.group}/{c.name}"
        if not c.available():
            print(f"skip {label} (binaries not built)")
            skipped += 1
            continue
        try:
            actual = c.fn()
        except Skip as s:
            print(f"skip {label} ({s})")
            skipped += 1
            continue

        if args.rewrite:
            os.makedirs(os.path.dirname(c.golden()), exist_ok=True)
            with open(c.golden(), "w") as f:
                f.write(actual)
            print(f"rewrote {label}")
            passed += 1
            continue

        if not os.path.exists(c.golden()):
            print(f"FAIL {label}: no golden (run --rewrite)")
            failed += 1
            continue
        with open(c.golden()) as f:
            expected = f.read()
        if actual == expected:
            print(f"ok   {label}")
            passed += 1
        else:
            failed += 1
            print(f"FAIL {label}:")
            for line in difflib.unified_diff(
                expected.splitlines(), actual.splitlines(),
                "golden", "actual", lineterm="",
            ):
                print(f"  {line}")

    print(f"\n{passed} passed, {failed} failed, {skipped} skipped")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
