# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""Instrumented stress runner for the hard-lockup hunt.

Runs N full matrix passes with the complete black box armed:
  - SISMO_CRASHLOG breadcrumbs (fsync'd) from difftest AND every sismo record
  - crashmon.py polling per-CPU time / ctxt / intr / PSI every second
  - optional rotating system-wide perf stack sampling (needs passwordless
    sudo for perf; skipped with a note otherwise)
  - CPUQuota via systemd-run so userspace stays somewhat responsive

Everything lands in out/crashbox/ (fsync'd or rotated), so after a hard
reboot the logs show: which case + which sismo phase was in flight, the
system ramp in the final seconds, and (with perf) kernel stacks up to ~10s
before death.

  tools/crashbox            # 3 passes
  tools/crashbox --passes 5
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time

ROOT_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BOX_DIR: str = os.path.join(ROOT_DIR, "out", "crashbox")


def crashmark(path: str, msg: str) -> None:
    with open(path, "a") as f:
        f.write(f"{int(time.time() * 1000)} - {os.getpid()} [crashbox] {msg}\n")
        f.flush()
        os.fsync(f.fileno())


def start_perf(perf_dir: str):
    """Rotating system-wide stack sampling, if passwordless sudo covers perf.
    10s rotations mean completed files survive the crash (crashmon syncs)."""
    probe = subprocess.run(["sudo", "-n", "perf", "--version"],
                           capture_output=True)
    if probe.returncode != 0:
        print("crashbox: no passwordless sudo for perf — stack sampling OFF")
        print("  enable: add a NOPASSWD sudoers rule for /usr/bin/perf")
        return None
    os.makedirs(perf_dir, exist_ok=True)
    return subprocess.Popen(
        ["sudo", "-n", "perf", "record", "-a", "-g", "-F", "99",
         "--switch-output=10s", "-o", os.path.join(perf_dir, "perf.data")],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--passes", type=int, default=3)
    parser.add_argument("--quota", default="800%")
    args = parser.parse_args()

    os.makedirs(BOX_DIR, exist_ok=True)
    crashlog = os.path.join(BOX_DIR, "crashlog.txt")
    monlog = os.path.join(BOX_DIR, "crashmon.jsonl")

    env = dict(os.environ, SISMO_CRASHLOG=crashlog)

    mon = subprocess.Popen(
        [sys.executable, os.path.join(ROOT_DIR, "python", "tools", "crashmon.py"),
         monlog, "1"])
    perf = start_perf(os.path.join(BOX_DIR, "perf"))

    crashmark(crashlog, f"crashbox start passes={args.passes} quota={args.quota}")
    rc = 0
    # Continue pass numbering across invocations so logs never overwrite.
    done = len([f for f in os.listdir(BOX_DIR)
                if f.startswith("pass") and f.endswith(".log")])
    try:
        for i in range(done + 1, done + args.passes + 1):
            crashmark(crashlog, f"pass {i} begin")
            passlog = os.path.join(BOX_DIR, f"pass{i}.log")
            with open(passlog, "w") as out:
                p = subprocess.run(
                    ["systemd-run", "--user", "--scope", "--collect",
                     f"-p", f"CPUQuota={args.quota}",
                     os.path.join(ROOT_DIR, "tools", "difftest"),
                     "--suite", "matrix", "--suite", "matrix-linux"],
                    stdout=out, stderr=subprocess.STDOUT, env=env, cwd=ROOT_DIR)
            crashmark(crashlog, f"pass {i} end rc={p.returncode}")
            if p.returncode != 0:
                rc = p.returncode
        crashmark(crashlog, "crashbox done")
    finally:
        mon.send_signal(signal.SIGTERM)
        if perf is not None:
            subprocess.run(["sudo", "-n", "kill", str(perf.pid)],
                           capture_output=True)
        os.sync()
    return rc


if __name__ == "__main__":
    sys.exit(main())
