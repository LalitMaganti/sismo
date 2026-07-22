# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""trace suite — record sample-target and golden stable structural facts.

Records sample-target through the BPF sampler and queries the trace, golden-ing
stable facts (not raw sample counts). Needs a caps-granted sismo (see
`sismo doctor --fix`) plus the Perfetto build, so cases self-skip when
unavailable.
"""

from __future__ import annotations

import os
import subprocess
import tempfile

from python.tools.diff_suites.common import (
    SAMPLE_TARGET, SISMO, TP_SHELL, Skip, SuiteContext, ensure_record_env,
    run_golden_cases)

NAME = "trace"
DESCRIPTION = "record sample-target, golden stable trace facts (needs BPF caps)"
ENABLED_BY_DEFAULT = True
NEEDS_BINARY = True


def _tp_scalar(trace: str, sql: str) -> int:
    out = subprocess.run(
        [TP_SHELL, "-q", "/dev/stdin", trace],
        input=sql.encode(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    ).stdout.decode()
    rows = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return int(rows[-1]) if rows and rows[-1].lstrip("-").isdigit() else 0


def _cpu_symbolize_actual() -> str:
    """Record sample-target and assert its own frames symbolize — guards the
    whole user-frame path (proc_maps parse, FFI, base_avma/build-id, symbolizer).
    """
    with tempfile.NamedTemporaryFile(suffix=".pftrace", delete=False) as tf:
        trace = tf.name
    try:
        if not ensure_record_env():
            raise Skip("recording env not ready — run: sudo sismo doctor --fix")
        rec = subprocess.run(
            [SISMO, "record", "--output", trace, SAMPLE_TARGET, "1500"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60,
        )
        if rec.returncode != 0 or not os.path.getsize(trace):
            raise Skip("recording produced no trace (sudo sismo doctor --fix?)")
        if _tp_scalar(trace, "SELECT count(*) FROM perf_sample;") == 0:
            raise Skip("recording captured no CPU samples (sudo sismo doctor --fix?)")
        mapping = _tp_scalar(
            trace,
            "SELECT count(*) FROM stack_profile_mapping "
            "WHERE name LIKE '%sample-target%';",
        )
        busy = _tp_scalar(
            trace,
            "SELECT count(*) FROM stack_profile_symbol s "
            "JOIN stack_profile_frame f USING(symbol_set_id) "
            "JOIN stack_profile_mapping m ON f.mapping = m.id "
            "WHERE m.name LIKE '%sample-target%' AND s.name LIKE '%busy_worker%';",
        )
        return (
            f"sample_target_mapping_present: {mapping >= 1}\n"
            f"busyworker_symbolized: {busy >= 1}\n"
        )
    finally:
        if os.path.exists(trace):
            os.unlink(trace)


def run(ctx: SuiteContext) -> int:
    cases = [
        ("cpu_symbolize", _cpu_symbolize_actual, [SISMO, SAMPLE_TARGET, TP_SHELL]),
    ]
    _passed, failed, _skipped = run_golden_cases(ctx, NAME, cases)
    return failed
