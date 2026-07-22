# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""System black-box poller for hard-lockup forensics.

Appends one fsync'd JSON line per interval with the signals that
distinguish storm types after the machine dies: per-CPU time deltas
(user/system/irq/softirq — a kernel-side storm shows as system+irq on
every CPU), context-switch and interrupt rates (a wakeup feedback loop
shows as a ctxt explosion), PSI pressure, and load. The last lines before
the log goes quiet are the ramp.

  python/tools/crashmon.py <logfile> [interval_s]

Runs until killed. Also os.sync()s every ~10s so other buffered logs
(perf.data rotations, suite logs) survive the crash too.
"""

from __future__ import annotations

import json
import os
import sys
import time


def read_stat() -> tuple[dict[str, list[int]], int, int, int]:
    cpus: dict[str, list[int]] = {}
    ctxt = intr = running = 0
    with open("/proc/stat") as f:
        for line in f:
            parts = line.split()
            if not parts:
                continue
            if parts[0].startswith("cpu") and parts[0] != "cpu":
                cpus[parts[0]] = [int(x) for x in parts[1:9]]
            elif parts[0] == "ctxt":
                ctxt = int(parts[1])
            elif parts[0] == "intr":
                intr = int(parts[1])
            elif parts[0] == "procs_running":
                running = int(parts[1])
    return cpus, ctxt, intr, running


def read_pressure() -> dict[str, float]:
    out = {}
    for res in ("cpu", "memory", "io"):
        try:
            with open(f"/proc/pressure/{res}") as f:
                for line in f:
                    kind = line.split()[0]  # some | full
                    avg10 = float(line.split("avg10=")[1].split()[0])
                    out[f"{res}_{kind}_avg10"] = avg10
        except OSError:
            pass
    return out


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    path = sys.argv[1]
    interval = float(sys.argv[2]) if len(sys.argv) > 2 else 1.0

    f = open(path, "a")
    prev_cpus, prev_ctxt, prev_intr, _ = read_stat()
    prev_t = time.monotonic()
    last_sync = prev_t

    while True:
        time.sleep(interval)
        cpus, ctxt, intr, running = read_stat()
        now = time.monotonic()
        dt = max(now - prev_t, 1e-6)
        # Per-CPU busy%, split into (user+nice), system, irq+softirq.
        percpu = {}
        for name, cur in cpus.items():
            old = prev_cpus.get(name, cur)
            d = [c - o for c, o in zip(cur, old)]
            total = max(sum(d), 1)
            percpu[name] = {
                "usr": round(100 * (d[0] + d[1]) / total),
                "sys": round(100 * d[2] / total),
                "irq": round(100 * (d[5] + d[6]) / total),
            }
        rec = {
            "t": int(time.time() * 1000),
            "ctxt_s": int((ctxt - prev_ctxt) / dt),
            "intr_s": int((intr - prev_intr) / dt),
            "running": running,
            "load1": os.getloadavg()[0],
            "cpu": percpu,
            **read_pressure(),
        }
        f.write(json.dumps(rec, separators=(",", ":")) + "\n")
        f.flush()
        os.fsync(f.fileno())
        if now - last_sync > 10:
            os.sync()
            last_sync = now
        prev_cpus, prev_ctxt, prev_intr, prev_t = cpus, ctxt, intr, now


if __name__ == "__main__":
    sys.exit(main())
