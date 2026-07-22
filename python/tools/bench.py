# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""Sismo overhead benchmark.

Measures what `sismo record` costs the profiled workload and the machine:

  workload_overhead  — % drop in workload throughput (iters/s of the
                       canonical matrix workload) while being recorded.
  profiler_cpu_s     — CPU seconds burned by sismo itself (recorder +
                       BPF drain + symbolization), i.e. recorded-tree CPU
                       minus the workload's own baseline CPU.
  stop_latency_s     — wall time from workload exit to `sismo record`
                       returning (trace write + symbolization).
  trace_bytes        — size of the written trace.

Method: N baseline runs of the workload alone, N runs under
`sismo record`, medians reported. The workload is the canonical
tests/matrix/targets/workload.c built with clang -O2 -fno-omit-frame-pointer
(the golden path — clang frames leaf functions, gcc doesn't).

  tools/bench
  tools/bench --runs 5 --duration-ms 3000
  tools/bench --json out/bench/report.json    # tracked over time

Needs a caps-granted sismo (sudo sismo doctor --fix); hardware-only, not part of the fast CI gate.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import resource
import statistics
import subprocess
import sys
import time

ROOT_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SISMO: str = os.path.join(ROOT_DIR, "crates", "sismo", "target", "debug", "sismo")
WL_SRC: str = os.path.join(ROOT_DIR, "tests", "matrix", "targets", "workload.c")
OUT_DIR: str = os.path.join(ROOT_DIR, "out", "bench")
WL_BIN: str = os.path.join(OUT_DIR, "workload")

ITERS_RE = re.compile(r"sismo-workload iters=(\d+)")


def children_cpu_s() -> float:
    ru = resource.getrusage(resource.RUSAGE_CHILDREN)
    return ru.ru_utime + ru.ru_stime


def run_one(cmd: list[str], duration_ms: int) -> dict:
    """Run a workload (optionally under sismo) once; return raw measures."""
    cpu0 = children_cpu_s()
    t0 = time.monotonic()
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    wall = time.monotonic() - t0
    cpu = children_cpu_s() - cpu0
    if p.returncode != 0:
        raise RuntimeError(
            f"run failed ({p.returncode}): {' '.join(cmd)}\n{p.stderr[-2000:]}")
    if "already running" in p.stderr or "lock held" in p.stderr:
        raise RuntimeError(
            "sismo refused (another session holds /tmp/sismo.lock) but still "
            "exited 0 — is a matrixtest/record already running?")
    m = ITERS_RE.search(p.stdout) or ITERS_RE.search(p.stderr)
    if not m:
        raise RuntimeError(
            f"no 'sismo-workload iters=' line in output of {' '.join(cmd)}\n"
            f"stdout: {p.stdout[-500:]}\nstderr: {p.stderr[-500:]}")
    return {
        "iters": int(m.group(1)),
        "iters_per_s": int(m.group(1)) / (duration_ms / 1000.0),
        "wall_s": wall,
        "cpu_s": cpu,
    }


def median(rows: list[dict], key: str) -> float:
    return statistics.median(r[key] for r in rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--duration-ms", type=int, default=3000)
    parser.add_argument("--json", metavar="PATH",
                        default=os.path.join(OUT_DIR, "report.json"))
    args = parser.parse_args()

    if not os.path.exists(SISMO):
        print(f"sismo not built at {SISMO}\n"
              f"  build it:  tools/cargo --hermetic build "
              f"--manifest-path crates/sismo/Cargo.toml", file=sys.stderr)
        return 2
    caps = subprocess.run(["getcap", SISMO], capture_output=True, text=True)
    if "cap_bpf" not in caps.stdout:
        print(f"sismo has no file capabilities (rebuilds shed them)\n"
              f"  grant them: sudo {SISMO} doctor --fix -y",
              file=sys.stderr)
        return 2

    os.makedirs(OUT_DIR, exist_ok=True)
    subprocess.check_call(["clang", "-O2", "-fno-omit-frame-pointer",
                           "-o", WL_BIN, WL_SRC])

    dur = str(args.duration_ms)
    trace = os.path.join(OUT_DIR, "bench.pftrace")
    base_cmd = [WL_BIN, dur]
    rec_cmd = [SISMO, "record", "--output", trace, WL_BIN, dur]

    print(f"warmup + {args.runs} baseline / {args.runs} recorded runs "
          f"of {args.duration_ms} ms each")
    run_one(base_cmd, args.duration_ms)  # warmup

    baseline, recorded = [], []
    for i in range(args.runs):
        baseline.append(run_one(base_cmd, args.duration_ms))
        print(f"  baseline {i + 1}: {baseline[-1]['iters_per_s']:,.0f} iters/s")
    trace_bytes = 0
    for i in range(args.runs):
        if os.path.exists(trace):
            os.unlink(trace)
        recorded.append(run_one(rec_cmd, args.duration_ms))
        trace_bytes = os.path.getsize(trace) if os.path.exists(trace) else 0
        print(f"  recorded {i + 1}: {recorded[-1]['iters_per_s']:,.0f} iters/s")

    base_rate = median(baseline, "iters_per_s")
    rec_rate = median(recorded, "iters_per_s")
    overhead_pct = 100.0 * (base_rate - rec_rate) / base_rate
    profiler_cpu = median(recorded, "cpu_s") - median(baseline, "cpu_s")
    stop_latency = median(recorded, "wall_s") - args.duration_ms / 1000.0

    def spread(rows):
        vals = sorted(r["iters_per_s"] for r in rows)
        return 100.0 * (vals[-1] - vals[0]) / vals[0] if vals[0] else 0.0

    print()
    print(f"  workload throughput   {base_rate:,.0f} -> {rec_rate:,.0f} iters/s "
          f"(spread ±{max(spread(baseline), spread(recorded)) / 2:.1f}%)")
    print(f"  workload_overhead     {overhead_pct:+.1f}%")
    print(f"  profiler_cpu_s        {profiler_cpu:.2f}s over {args.duration_ms} ms run")
    print(f"  stop_latency_s        {stop_latency:.2f}s (trace write + symbolization)")
    print(f"  trace_bytes           {trace_bytes:,}")

    if args.json:
        report = {
            "duration_ms": args.duration_ms,
            "runs": args.runs,
            "baseline_iters_per_s": base_rate,
            "recorded_iters_per_s": rec_rate,
            "workload_overhead_pct": round(overhead_pct, 2),
            "profiler_cpu_s": round(profiler_cpu, 3),
            "stop_latency_s": round(stop_latency, 3),
            "trace_bytes": trace_bytes,
            "baseline": baseline,
            "recorded": recorded,
        }
        with open(args.json, "w") as f:
            json.dump(report, f, indent=1)
        print(f"report: {os.path.relpath(args.json, ROOT_DIR)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
