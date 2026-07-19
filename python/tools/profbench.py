# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""Comparative profiler overhead benchmark: sismo vs perf, honestly.

Overhead is not one number. This measures a resource *vector* for each profiler,
attributed to the collector alone (not the workload), normalized by the data it
actually delivered:

  target_overhead_pct  — % drop in the workload's own throughput while profiled.
  collector_cpu_s      — CPU the collector burns, split record-phase vs the
                         finalize (stop/flush + symbolize) tail; workload CPU subtracted.
  peak_rss_mb          — collector peak resident memory, record vs finalize
                         phase (getrusage's tree-max can't see this — we poll
                         /proc for the collector processes specifically).
  peak_fds             — collector open file descriptors (where an fd-pinning
                         design's cost lives; invisible to RSS).
  out_bytes            — trace / perf.data size.
  samples              — samples actually delivered (the fidelity denominator).
  mean_depth           — mean recovered stack depth (unwind fidelity).

Fairness rules baked in:
  * Match the sampling *trigger*, not the frequency. sismo overflows on a fixed
    cycle period, so perf runs `-e cycles -c <period>`, not `-F <hz>` — otherwise
    a busy core makes one profiler sample far more than the other.
  * Compare only within equal fidelity: perf's fp and dwarf call-graph modes are
    separate adapters, paired against sismo by what stacks each recovers.
  * Interleave trials across profilers so thermal / frequency drift cancels;
    report median and IQR, discard a warmup.

  tools/profbench
  tools/profbench --trials 9 --duration-ms 2000
  tools/profbench --profilers none,perf-dwarf,sismo --json out/profbench.json

Linux only. Needs a setcap'd sismo-run; perf adapters are skipped if perf is
absent. Not part of the fast CI gate.
"""

from __future__ import annotations

import argparse
import json
import os
import resource
import shutil
import statistics
import subprocess
import sys
import threading
import time

ROOT_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SISMO_RUN: str = os.path.join(ROOT_DIR, "crates", "sismo-run", "target", "debug", "sismo-run")
TP_SHELL: str = os.path.join(
    ROOT_DIR, "third_party", "src", "perfetto", "out", "sismo", "trace_processor_shell")
WL_SRC: str = os.path.join(ROOT_DIR, "tests", "matrix", "targets", "workload.c")
OUT_DIR: str = os.path.join(ROOT_DIR, "out", "profbench")

# sismo's default sampler: PERF_TYPE_HARDWARE cpu-cycles, this overflow period
# (linux_bpf_capture.rs resolve_sampler). perf must match the trigger exactly.
SISMO_CYCLE_PERIOD: int = 1_000_003

CLK_TCK: int = os.sysconf("SC_CLK_TCK")
PAGE_SIZE: int = os.sysconf("SC_PAGE_SIZE")
POLL_INTERVAL_S: float = 0.01

ITERS_MARKER: str = "sismo-workload iters="


# ----- /proc process-tree sampling ----------------------------------------


def _proc_stat(pid: int) -> tuple[int, int, int] | None:
    """(ppid, utime+stime ticks, 0) for `pid`, or None if it's gone. comm can
    hold spaces/parens, so split after the last ')'."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            line = f.read()
        rest = line[line.rindex(")") + 2:].split()
        ppid = int(rest[1])
        cpu_ticks = int(rest[11]) + int(rest[12])  # utime + stime
        return ppid, cpu_ticks, 0
    except (OSError, ValueError, IndexError):
        return None


def _proc_rss_bytes(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/statm") as f:
            return int(f.read().split()[1]) * PAGE_SIZE  # resident pages
    except (OSError, ValueError, IndexError):
        return 0


def _proc_fd_count(pid: int) -> int:
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return 0


def _proc_exe(pid: int) -> str:
    try:
        return os.path.realpath(f"/proc/{pid}/exe")
    except OSError:
        return ""


def _all_ppids() -> dict[int, int]:
    """pid -> ppid for every process, one scan of /proc."""
    out: dict[int, int] = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        st = _proc_stat(int(name))
        if st is not None:
            out[int(name)] = st[0]
    return out


def _subtree(root: int, ppids: dict[int, int]) -> list[int]:
    """Every pid whose ancestor chain reaches `root` (inclusive)."""
    children: dict[int, list[int]] = {}
    for pid, ppid in ppids.items():
        children.setdefault(ppid, []).append(pid)
    seen, stack = [], [root]
    while stack:
        pid = stack.pop()
        seen.append(pid)
        stack.extend(children.get(pid, []))
    return seen


class TreeSampler:
    """Polls a process subtree, partitioning each pid into the workload leaf(s)
    (exe == workload binary) vs the collector (everything else), tracking peak
    RSS/fds and last-seen cumulative CPU per class. Records a phase boundary the
    instant the workload leaf disappears, so record vs finalize costs separate."""

    def __init__(self, root_pid: int, workload_exe: str):
        self.root = root_pid
        self.wl_exe = os.path.realpath(workload_exe)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        # Per-class running state: peak rss, peak fds, last-seen cpu ticks.
        self.col_peak_rss = 0
        self.col_peak_fds = 0
        self.col_cpu_ticks = 0
        self.wl_cpu_ticks = 0
        # Snapshot of collector state at the moment the workload exited.
        self.col_cpu_at_wl_exit: int | None = None
        self.col_rss_peak_record = 0  # peak while workload alive
        self._exe_cache: dict[int, str] = {}

    def _classify(self, pid: int) -> bool:
        """True if `pid` is the workload leaf."""
        exe = self._exe_cache.get(pid)
        if exe is None:
            exe = _proc_exe(pid)
            if exe:  # cache only once resolvable (early reads can be empty)
                self._exe_cache[pid] = exe
        return exe == self.wl_exe

    def _loop(self) -> None:
        while not self._stop.is_set():
            ppids = _all_ppids()
            pids = _subtree(self.root, ppids)
            col_rss = col_fds = col_cpu = wl_cpu = 0
            wl_present = False
            for pid in pids:
                st = _proc_stat(pid)
                if st is None:
                    continue
                if self._classify(pid):
                    wl_present = True
                    wl_cpu += st[1]
                else:
                    col_cpu += st[1]
                    col_rss += _proc_rss_bytes(pid)
                    col_fds += _proc_fd_count(pid)
            # CPU is cumulative per pid; keep the max seen so a just-exited pid's
            # last reading isn't lost.
            self.col_cpu_ticks = max(self.col_cpu_ticks, col_cpu)
            self.wl_cpu_ticks = max(self.wl_cpu_ticks, wl_cpu)
            self.col_peak_rss = max(self.col_peak_rss, col_rss)
            self.col_peak_fds = max(self.col_peak_fds, col_fds)
            if wl_present:
                self.col_rss_peak_record = max(self.col_rss_peak_record, col_rss)
            elif self.col_cpu_at_wl_exit is None and self.col_cpu_ticks > 0:
                # First poll after the workload is gone: freeze the record-phase
                # collector CPU. Everything after is the finalize tail.
                self.col_cpu_at_wl_exit = self.col_cpu_ticks
            self._stop.wait(POLL_INTERVAL_S)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> Measures:
        self._stop.set()
        self._thread.join()
        col_cpu_s = self.col_cpu_ticks / CLK_TCK
        record_cpu_ticks = self.col_cpu_at_wl_exit
        record_cpu_s = (record_cpu_ticks / CLK_TCK) if record_cpu_ticks else col_cpu_s
        return Measures(
            collector_cpu_s=col_cpu_s,
            record_cpu_s=record_cpu_s,
            finalize_cpu_s=max(0.0, col_cpu_s - record_cpu_s),
            workload_cpu_s=self.wl_cpu_ticks / CLK_TCK,
            peak_rss_mb=self.col_peak_rss / (1024 * 1024),
            peak_rss_record_mb=self.col_rss_peak_record / (1024 * 1024),
            peak_fds=self.col_peak_fds,
        )


class Measures:
    """Collector-attributed resource measures for one trial."""

    __slots__ = ("collector_cpu_s", "record_cpu_s", "finalize_cpu_s",
                 "workload_cpu_s", "peak_rss_mb", "peak_rss_record_mb", "peak_fds")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k, 0.0))


# ----- profiler adapters --------------------------------------------------


class Adapter:
    name = "?"

    def available(self) -> bool:
        return True

    def record_cmd(self, wl_argv: list[str], out_path: str) -> list[str]:
        raise NotImplementedError

    def samples(self, out_path: str) -> int | None:
        return None

    def mean_depth(self, out_path: str) -> float | None:
        return None

    def out_bytes(self, out_path: str) -> int:
        return os.path.getsize(out_path) if os.path.exists(out_path) else 0


class NoneAdapter(Adapter):
    name = "none"

    def record_cmd(self, wl_argv, out_path):
        return list(wl_argv)  # the workload alone; it is its own root

    def out_bytes(self, out_path):
        return 0


class PerfAdapter(Adapter):
    def __init__(self, mode: str):
        self.mode = mode  # "fp" | "dwarf"
        self.name = f"perf-{mode}"

    def available(self):
        return shutil.which("perf") is not None

    def record_cmd(self, wl_argv, out_path):
        return ["perf", "record", "-e", "cycles", "-c", str(SISMO_CYCLE_PERIOD),
                "--call-graph", self.mode, "-o", out_path, "--", *wl_argv]

    def samples(self, out_path):
        p = subprocess.run(["perf", "report", "--stats", "-i", out_path],
                           capture_output=True, text=True)
        for line in p.stdout.splitlines():
            if "SAMPLE events:" in line:
                return int(line.split(":")[1].split()[0])
        return None

    def mean_depth(self, out_path):
        # perf script prints a header line per sample, then one indented line per
        # frame, then a blank line. Average the frame counts.
        p = subprocess.run(["perf", "script", "-i", out_path, "--no-demangle"],
                           capture_output=True, text=True)
        depths, cur, in_stack = [], 0, False
        for line in p.stdout.splitlines():
            if line and not line[0].isspace():
                in_stack = True
                cur = 0
            elif in_stack and line.strip():
                cur += 1
            elif in_stack and not line.strip():
                depths.append(cur)
                in_stack = False
        if in_stack:
            depths.append(cur)
        return statistics.mean(depths) if depths else None


class SismoAdapter(Adapter):
    def __init__(self, no_symbolize: bool = False):
        self.no_symbolize = no_symbolize
        self.name = "sismo-nosym" if no_symbolize else "sismo"

    def available(self):
        if not os.path.exists(SISMO_RUN):
            return False
        caps = subprocess.run(["getcap", SISMO_RUN], capture_output=True, text=True)
        return "cap_bpf" in caps.stdout

    def record_cmd(self, wl_argv, out_path):
        extra = ["--no-symbolize"] if self.no_symbolize else []
        return [SISMO_RUN, "record", *extra, "--output", out_path, *wl_argv]

    def _tp(self, out_path, sql):
        if not (os.path.exists(TP_SHELL) and os.path.exists(out_path)):
            return None
        p = subprocess.run([TP_SHELL, "-q", "/dev/stdin", out_path],
                           input=sql, capture_output=True, text=True)
        try:
            return float(p.stdout.strip().splitlines()[-1].strip('"'))
        except (ValueError, IndexError):
            return None

    def samples(self, out_path):
        n = self._tp(out_path, "SELECT count(*) FROM perf_sample;")
        return int(n) if n is not None else None

    def mean_depth(self, out_path):
        return self._tp(out_path,
                        "SELECT avg(depth+1) FROM perf_sample p "
                        "JOIN __intrinsic_stack_profile_callsite c "
                        "ON p.callsite_id = c.id;")


# ----- trial runner -------------------------------------------------------


def children_cpu_s() -> float:
    ru = resource.getrusage(resource.RUSAGE_CHILDREN)
    return ru.ru_utime + ru.ru_stime


def run_trial(adapter: Adapter, wl_argv: list[str], out_path: str,
              duration_ms: int) -> dict:
    if os.path.exists(out_path):
        os.unlink(out_path)
    cmd = adapter.record_cmd(wl_argv, out_path)
    tree_cpu0 = children_cpu_s()
    t0 = time.monotonic()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    sampler = TreeSampler(proc.pid, wl_argv[0])
    sampler.start()
    out, err = proc.communicate(timeout=300)
    wall = time.monotonic() - t0
    m = sampler.stop()
    tree_cpu = children_cpu_s() - tree_cpu0
    if proc.returncode != 0:
        raise RuntimeError(f"{adapter.name} failed ({proc.returncode}): "
                           f"{' '.join(cmd)}\n{err[-1500:]}")
    iters = None
    for stream in (out, err):
        for line in stream.splitlines():
            if ITERS_MARKER in line:
                iters = int(line.split(ITERS_MARKER)[1].split()[0])
    if iters is None:
        raise RuntimeError(f"no '{ITERS_MARKER}' in {adapter.name} output")
    # For the baseline the "collector" is empty; the workload is the whole tree,
    # so fold the getrusage tree CPU in as the workload CPU for reference.
    return {
        "iters_per_s": iters / (duration_ms / 1000.0),
        "wall_s": wall,
        "tree_cpu_s": tree_cpu,
        "collector_cpu_s": m.collector_cpu_s,
        "record_cpu_s": m.record_cpu_s,
        "finalize_cpu_s": m.finalize_cpu_s,
        "workload_cpu_s": m.workload_cpu_s,
        "peak_rss_mb": m.peak_rss_mb,
        "peak_rss_record_mb": m.peak_rss_record_mb,
        "peak_fds": m.peak_fds,
    }


# ----- environment + reporting --------------------------------------------


def environment() -> dict:
    def read(path):
        try:
            with open(path) as f:
                return f.read().strip()
        except OSError:
            return "?"
    gov = read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    model = "?"
    for line in read("/proc/cpuinfo").splitlines():
        if line.startswith("model name"):
            model = line.split(":", 1)[1].strip()
            break
    return {
        "kernel": os.uname().release,
        "cpu": model,
        "nproc": os.cpu_count(),
        "governor": gov,
        "cycle_period": SISMO_CYCLE_PERIOD,
    }


def agg(rows: list[dict], key: str) -> tuple[float, float]:
    """(median, IQR) for `key` across trials."""
    vals = sorted(r[key] for r in rows)
    med = statistics.median(vals)
    if len(vals) >= 4:
        q = statistics.quantiles(vals, n=4)
        return med, q[2] - q[0]
    return med, (vals[-1] - vals[0]) if vals else 0.0


def main() -> int:
    all_adapters = {
        "none": NoneAdapter(),
        "perf-fp": PerfAdapter("fp"),
        "perf-dwarf": PerfAdapter("dwarf"),
        "sismo": SismoAdapter(),
        "sismo-nosym": SismoAdapter(no_symbolize=True),
    }
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--trials", type=int, default=7)
    parser.add_argument("--duration-ms", type=int, default=1500)
    parser.add_argument("--profilers", default=",".join(all_adapters),
                        help="comma list from: " + ",".join(all_adapters))
    parser.add_argument("--json", metavar="PATH",
                        default=os.path.join(OUT_DIR, "report.json"))
    args = parser.parse_args()

    if sys.platform != "linux":
        print("profbench is Linux-only", file=sys.stderr)
        return 2

    chosen = []
    for name in args.profilers.split(","):
        a = all_adapters.get(name)
        if a is None:
            print(f"unknown profiler {name!r}", file=sys.stderr)
            return 2
        if not a.available():
            print(f"  skip {name}: unavailable (not installed / not setcap'd)")
            continue
        chosen.append(a)
    if not any(a.name == "none" for a in chosen):
        chosen.insert(0, all_adapters["none"])  # baseline is mandatory

    os.makedirs(OUT_DIR, exist_ok=True)
    wl_bin = os.path.join(OUT_DIR, "workload")
    subprocess.check_call(["clang", "-O2", "-fno-omit-frame-pointer", "-o", wl_bin, WL_SRC])
    wl_argv = [wl_bin, str(args.duration_ms)]

    env = environment()
    print(f"env: {env['cpu']} | {env['nproc']} cpu | gov={env['governor']} | "
          f"kernel {env['kernel']} | trigger cycles/{env['cycle_period']}")
    if env["governor"] not in ("performance", "?"):
        print(f"  WARNING governor is {env['governor']!r}, not 'performance' — "
              f"numbers will be noisier")
    print(f"{args.trials} interleaved trials of {args.duration_ms} ms "
          f"(+1 warmup), profilers: {', '.join(a.name for a in chosen)}\n")

    trials: dict[str, list[dict]] = {a.name: [] for a in chosen}
    fidelity: dict[str, dict] = {a.name: {} for a in chosen}
    out_paths = {a.name: os.path.join(OUT_DIR, f"{a.name}.data") for a in chosen}

    for a in chosen:  # warmup (also primes build caches / page cache)
        run_trial(a, wl_argv, out_paths[a.name], args.duration_ms)

    for t in range(args.trials):
        for a in chosen:  # interleaved: cancels thermal/frequency drift
            r = run_trial(a, wl_argv, out_paths[a.name], args.duration_ms)
            trials[a.name].append(r)
        print(f"  trial {t + 1}/{args.trials} done")

    # Fidelity + output size read once from each profiler's last trace.
    for a in chosen:
        fidelity[a.name] = {
            "out_bytes": a.out_bytes(out_paths[a.name]),
            "samples": a.samples(out_paths[a.name]),
            "mean_depth": a.mean_depth(out_paths[a.name]),
        }

    base_rate, _ = agg(trials["none"], "iters_per_s")
    dur_s = args.duration_ms / 1000.0

    print(f"\n{'profiler':<12} {'tgt Δ%':>7} {'col CPU':>8} {'rec/fin':>10} "
          f"{'peakRSS':>9} {'fds':>5} {'out':>9} {'samp/s':>8} {'depth':>6}")
    print("-" * 84)
    report = {"env": env, "duration_ms": args.duration_ms, "trials": args.trials,
              "baseline_iters_per_s": base_rate, "profilers": {}}
    for a in chosen:
        rows = trials[a.name]
        rate, rate_iqr = agg(rows, "iters_per_s")
        overhead = 100.0 * (base_rate - rate) / base_rate if base_rate else 0.0
        col_cpu, _ = agg(rows, "collector_cpu_s")
        rec_cpu, _ = agg(rows, "record_cpu_s")
        sym_cpu, _ = agg(rows, "finalize_cpu_s")
        rss, _ = agg(rows, "peak_rss_mb")
        fds, _ = agg(rows, "peak_fds")
        fi = fidelity[a.name]
        samp = fi["samples"]
        samp_s = (samp / dur_s) if samp else 0.0
        depth = fi["mean_depth"] or 0.0
        ob = fi["out_bytes"]
        ob_str = f"{ob / 1024:.0f}K" if ob < 1024 * 1024 else f"{ob / 1024 / 1024:.1f}M"
        tag = "" if a.name != "none" else "  (baseline)"
        print(f"{a.name:<12} {overhead:>6.1f}% {col_cpu:>7.2f}s "
              f"{rec_cpu:>4.2f}/{sym_cpu:<4.2f} {rss:>7.0f}MB {fds:>5.0f} "
              f"{ob_str:>9} {samp_s:>8.0f} {depth:>6.1f}{tag}")
        report["profilers"][a.name] = {
            "target_overhead_pct": round(overhead, 2),
            "iters_per_s": round(rate), "iters_per_s_iqr": round(rate_iqr),
            "collector_cpu_s": round(col_cpu, 3),
            "record_cpu_s": round(rec_cpu, 3), "finalize_cpu_s": round(sym_cpu, 3),
            "peak_rss_mb": round(rss, 1), "peak_fds": round(fds),
            "out_bytes": ob, "samples_per_s": round(samp_s),
            "mean_depth": round(depth, 2), "trials": rows,
        }

    # Symbolization cost is isolated as the sismo vs sismo-nosym collector delta,
    # not the finalize phase (which is dominated by Perfetto's stop/flush).
    p = report["profilers"]
    if "sismo" in p and "sismo-nosym" in p:
        d = p["sismo"]["collector_cpu_s"] - p["sismo-nosym"]["collector_cpu_s"]
        report["symbolize_cpu_s"] = round(d, 3)
        print(f"\nsymbolize CPU (sismo − sismo-nosym): {d:+.2f}s  "
              f"[isolated; the finalize column is mostly Perfetto stop/flush]")

    with open(args.json, "w") as f:
        json.dump(report, f, indent=1)
    print(f"report: {os.path.relpath(args.json, ROOT_DIR)}")
    print("read: compare col-CPU/RSS only within equal fidelity (same samp/s & "
          "depth). perf-dwarf pairs with sismo on stacks; perf-fp only on FP "
          "builds. 'fin' is the post-exit tail (Perfetto flush + symbolize), not "
          "symbolize alone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
