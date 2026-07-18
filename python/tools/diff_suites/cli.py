# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""cli suite — sismo's stdout/stderr/exit surface for fixed argv.

Deterministic, no privileges. Part of the default run.
"""

from __future__ import annotations

import subprocess

from python.tools.diff_suites.common import SISMO, SuiteContext, run_golden_cases

NAME = "cli"
DESCRIPTION = "sismo CLI stdout/stderr/exit goldens (fast, no privileges)"
ENABLED_BY_DEFAULT = True
NEEDS_BINARY = True


def _cli_actual(argv: list[str]) -> str:
    p = subprocess.run([SISMO] + argv, capture_output=True)
    out = p.stdout.decode(errors="replace")
    err = p.stderr.decode(errors="replace")
    return (
        f"$ sismo {' '.join(argv)}\n"
        f"exit: {p.returncode}\n"
        f"--- stdout ---\n{out}\n--- stderr ---\n{err}"
    )


def run(ctx: SuiteContext) -> int:
    cases = [
        ("no_args", lambda: _cli_actual([]), [SISMO]),
        ("help_flag", lambda: _cli_actual(["--help"]), [SISMO]),
        ("help_short", lambda: _cli_actual(["-h"]), [SISMO]),
        ("help_word", lambda: _cli_actual(["help"]), [SISMO]),
        ("unknown_subcommand", lambda: _cli_actual(["boguscmd"]), [SISMO]),
    ]
    _passed, failed, _skipped = run_golden_cases(ctx, NAME, cases)
    return failed
