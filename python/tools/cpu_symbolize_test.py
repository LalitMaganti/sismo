# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""Bounded-workload regression test for CPU-sample symbolization (Linux).

Records a short `sample-target` run through the BPF CPU sampler and asserts
that the *main executable's* own functions symbolize — `sample_target.busy
Worker` appearing as a resolved symbol means proc_maps kept the main-binary
mapping and the symbolizer resolved it end to end.

Guards the whole user-frame path: the proc_maps parse + FFI struct layout,
base_avma/build-id plumbing, and the symbolizer. (It exercises the path the
Rust proc_maps port replaced; it is not a discriminator for that port's
specific UB fix, which was layout-dependent and didn't always manifest.)

Linux + BPF caps only: records via zig-out/bin/sismo-run, which must carry
cap_bpf,cap_perfmon,cap_sys_resource (see src/sismo_run.zig). Not part of
the fast CI gate — it needs privileges and the full Perfetto build.

Usage: tools/cpu-symbolize-test [--duration-ms N]
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile

ROOT_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SISMO_RUN: str = os.path.join(ROOT_DIR, "zig-out", "bin", "sismo-run")
SAMPLE_TARGET: str = os.path.join(ROOT_DIR, "zig-out", "bin", "sample-target")
TP_SHELL: str = os.path.join(
    ROOT_DIR, "third_party", "src", "perfetto", "out", "sismo", "trace_processor_shell"
)


def tp_scalar(trace: str, sql: str) -> int:
    """Run a single-value query against `trace`, returning the integer result."""
    out = subprocess.run(
        [TP_SHELL, "-q", "/dev/stdin", trace],
        input=sql.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ).stdout.decode()
    # stdout is CSV: a header line then the value. Take the last non-empty line.
    rows = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return int(rows[-1]) if rows and rows[-1].lstrip("-").isdigit() else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--duration-ms", type=int, default=1500)
    args = parser.parse_args()

    for path, hint in (
        (SISMO_RUN, "tools/zig build"),
        (SAMPLE_TARGET, "tools/zig build"),
        (TP_SHELL, "tools/build-perfetto"),
    ):
        if not os.path.exists(path):
            print(f"missing {path}\nbuild it with: {hint}", file=sys.stderr)
            return 1

    with tempfile.NamedTemporaryFile(suffix=".pftrace", delete=False) as tf:
        trace = tf.name

    print(f"==> recording {args.duration_ms}ms sample-target via sismo-run")
    rec = subprocess.run(
        [SISMO_RUN, "record", "--output", trace,
         SAMPLE_TARGET, str(args.duration_ms)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=60,
    )
    if rec.returncode != 0 or not os.path.getsize(trace):
        sys.stdout.write(rec.stdout.decode())
        print("FAIL: recording produced no trace "
              "(missing BPF caps on sismo-run? see src/sismo_run.zig)")
        return 1

    # The bug dropped the main-binary mapping entirely; its presence + a
    # resolved workload symbol prove the fix.
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

    print(f"  sample-target mappings:            {mapping}")
    print(f"  symbolized busyWorker frames:      {busy}")
    os.unlink(trace)

    if mapping >= 1 and busy >= 1:
        print("PASS: main-binary frames are mapped and symbolized")
        return 0
    print("FAIL: main-binary symbolization missing (proc_maps regression?)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
