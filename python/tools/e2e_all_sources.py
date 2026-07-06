# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""Full end-to-end test of `sismo record`.

Builds everything, runs the recorder under sudo (so the in-process heap
and CPU producers can task_for_pid the spawned target), and validates
that every data source landed in the trace via the Perfetto Python API.

Pass criterion: non-zero rows in all four tables —
  slice                    (TrackEvent zones from sample-target)
  heap_profile_allocation  (sismo.heap)
  perf_sample              (sismo.macos_cpu_samples)
  sched_slice              (sismo.macos_sched)

Usage: tools/e2e-all-sources
(Will prompt for sudo password once.)

The script bootstraps a venv under third_party/venv/e2e/ on first run
and pip-installs the `perfetto` package into it; subsequent runs reuse
that venv. The `perfetto` package downloads its own trace_processor
binary, so this script does not require tools/build-perfetto to have
run.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

ROOT_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SISMO_BIN: str = os.path.join(ROOT_DIR, "rust-host", "target", "debug", "sismo")
SAMPLE_TARGET_BIN: str = os.path.join(ROOT_DIR, "zig-out", "bin", "sample-target")
TRACE_PATH: str = "/tmp/sismo-e2e.pftrace"
RUN_LOG: str = "/tmp/sismo-e2e-run.log"
DEFAULT_DURATION_MS: int = 3000

VENV_DIR: str = os.path.join(ROOT_DIR, "third_party", "venv", "e2e")
VENV_PY: str = os.path.join(VENV_DIR, "bin", "python3")
VENV_STAMP: str = os.path.join(VENV_DIR, ".stamp")
# Pin to a known-good version. Bump (and delete the stamp / venv dir) to
# upgrade.
PERFETTO_PKG: str = "perfetto>=0.13.0"

QUERY: str = """
SELECT 'slice (track_event)' AS name, count(*) AS value FROM slice
UNION ALL SELECT 'heap_profile_allocation', count(*) FROM heap_profile_allocation
UNION ALL SELECT 'perf_sample', count(*) FROM perf_sample
UNION ALL SELECT 'sched_slice', count(*) FROM sched_slice
"""

# Regex matching DebugAllocator leak noise that fires at sismo's exit.
# Lines matching are dropped from the surfaced run log.
LEAK_NOISE_PATTERN = re.compile(
    r"^(error\(DebugAllocator\)"
    r"|/opt/homebrew"
    r"|/Users/lalitm/depot/projects/sismo/src/sismo_record\.zig:(68|86):"
    r"|.*in (dupe|maybeSpawn|callMain|wrapMain)"
    r"|$"
    r"|\s*\^"
    r"|return wrapMain"
    r"|stack frames"
    r"|return allocator"
    r"|return maybeSpawnInner"
    r"|const s = try"
    r"|const new_buf"
    r"|        cpu_child"
    r"|        heap_child)"
)


def ensure_venv() -> None:
    """Create the e2e venv with the `perfetto` package if not already present.

    Idempotent: a stamp file gates the (slow) pip install on subsequent runs.
    """
    if os.path.exists(VENV_STAMP) and os.path.exists(VENV_PY):
        return
    print(f"==> bootstrapping e2e venv at {VENV_DIR}")
    os.makedirs(os.path.dirname(VENV_DIR), exist_ok=True)
    subprocess.check_call([sys.executable, "-m", "venv", VENV_DIR])
    subprocess.check_call(
        [VENV_PY, "-m", "pip", "install", "--quiet", "--upgrade", "pip"]
    )
    subprocess.check_call(
        [VENV_PY, "-m", "pip", "install", "--quiet", PERFETTO_PKG]
    )
    with open(VENV_STAMP, "w") as f:
        f.write(PERFETTO_PKG + "\n")


def reexec_in_venv_if_needed() -> None:
    """Re-exec under the venv interpreter if we aren't already running there.

    Detect venv membership via sys.prefix, not by comparing interpreter paths:
    on macOS (homebrew/framework Python) the venv's bin/python3 is a symlink
    whose realpath resolves back to the base interpreter, so a realpath
    comparison wrongly concludes we're already inside the venv, skips the
    re-exec, and then fails to import perfetto from the base site-packages.
    Inside a venv sys.prefix is the venv dir; outside it's the base prefix.
    """
    if os.path.realpath(sys.prefix) == os.path.realpath(VENV_DIR):
        return
    wrapper = os.path.join(ROOT_DIR, "tools", "e2e-all-sources")
    os.execv(VENV_PY, [VENV_PY, wrapper] + sys.argv[1:])


def filter_run_log(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    with open(path) as f:
        lines = f.read().splitlines()
    kept = [ln for ln in lines if not LEAK_NOISE_PATTERN.match(ln)]
    return kept[-50:]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--duration-ms",
        type=int,
        default=DEFAULT_DURATION_MS,
        help=f"Workload duration in milliseconds (default: {DEFAULT_DURATION_MS})",
    )
    args = parser.parse_args()

    ensure_venv()
    reexec_in_venv_if_needed()

    # Imported after re-exec so we're guaranteed to be in the venv.
    from perfetto.trace_processor import TraceProcessor

    print("==> building")
    # cargo drives the whole build (build.rs invokes the Zig staticlib + aux).
    subprocess.check_call(
        [sys.executable, os.path.join(ROOT_DIR, "tools", "cargo"), "--hermetic",
         "build", "--manifest-path", os.path.join(ROOT_DIR, "rust-host", "Cargo.toml")],
        cwd=ROOT_DIR, stdout=subprocess.DEVNULL,
    )

    print("==> priming sudo (password may be asked once)")
    subprocess.check_call(["sudo", "-v"])

    # Trace from prior runs was written under sudo (sismo record needs root
    # for kdebug/task_for_pid), so unlinking it needs sudo too — /tmp's
    # sticky bit blocks regular-user rm of root-owned files.
    subprocess.run(["sudo", "rm", "-f", TRACE_PATH], check=False)

    print()
    print(f"==> sismo record (workload runs {args.duration_ms}ms) -> {TRACE_PATH}")
    with open(RUN_LOG, "wb") as log:
        subprocess.run(
            [
                "sudo", "-E", SISMO_BIN, "record",
                "--output", TRACE_PATH,
                SAMPLE_TARGET_BIN, str(args.duration_ms),
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
            check=False,
        )

    print("--- run log (filtered) ---")
    for line in filter_run_log(RUN_LOG):
        print(line)
    print("--- end run log ---")

    print()
    subprocess.run(["ls", "-la", TRACE_PATH], check=False)

    print()
    print("==> trace_processor SQL")
    with TraceProcessor(trace=TRACE_PATH) as tp:
        result = tp.query(QUERY)
        rows = [(row.name, row.value) for row in result]

    fail = False
    for name, value in rows:
        marker = "" if value > 0 else "  <-- FAIL: 0 rows"
        print(f"  {name:<32} {value}{marker}")
        if value <= 0:
            fail = True

    print()
    if not fail:
        print("PASS: all four data sources captured")
        return 0
    print("PARTIAL: some data sources missing — see above")
    return 1


if __name__ == "__main__":
    sys.exit(main())
