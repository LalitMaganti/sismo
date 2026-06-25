# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""Golden test for the top-level `sismo` CLI dispatcher.

Runs the built `sismo` binary with a fixed set of argv vectors and compares
stdout / stderr / exit code against the goldens in tests/golden/cli/. The
dispatcher (help text, subcommand routing, unknown-subcommand handling) is
deterministic and privilege-free, so it goldens cleanly — unlike the
recording commands it routes to.

Goldens were captured from the Zig dispatcher at the point the Rust port
began, with one deliberate change: an unknown subcommand exits 2 (was 0).

Usage: tools/cli-golden-test [--binary PATH]
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

ROOT_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GOLDEN_DIR: str = os.path.join(ROOT_DIR, "tests", "golden", "cli")

# name -> argv passed after the binary.
CASES: dict[str, list[str]] = {
    "noarg": [],
    "help_flag": ["--help"],
    "h_flag": ["-h"],
    "help_word": ["help"],
    "bogus": ["boguscmd"],
}


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def run_case(binary: str, name: str, argv: list[str]) -> list[str]:
    """Returns a list of human-readable mismatch strings (empty == pass)."""
    proc = subprocess.run([binary] + argv, capture_output=True)
    fails: list[str] = []
    for stream, got in (("out", proc.stdout), ("err", proc.stderr)):
        want = _read(os.path.join(GOLDEN_DIR, f"{name}.{stream}"))
        if got != want:
            fails.append(f"{stream}: got {len(got)}B, want {len(want)}B")
    want_code = int(_read(os.path.join(GOLDEN_DIR, f"{name}.code")).strip())
    if proc.returncode != want_code:
        fails.append(f"exit: got {proc.returncode}, want {want_code}")
    return fails


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary",
        default=os.path.join(ROOT_DIR, "zig-out", "bin", "sismo"),
        help="Path to the sismo binary (default: zig-out/bin/sismo)",
    )
    args = parser.parse_args()

    if not os.path.exists(args.binary):
        print(f"sismo binary not found: {args.binary}\nBuild it with tools/zig build.",
              file=sys.stderr)
        return 1

    ok = True
    for name, argv in CASES.items():
        fails = run_case(args.binary, name, argv)
        if fails:
            ok = False
            print(f"FAIL {name} (sismo {' '.join(argv)})")
            for f in fails:
                print(f"     {f}")
        else:
            print(f"ok   {name} (sismo {' '.join(argv)})")

    print("PASS" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
