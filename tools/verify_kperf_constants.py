#!/usr/bin/env python3
# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""Verify sismo's hand-maintained kperf/kdebug constants against xnu source.

kperf is a private, versioned interface with no stable ABI. sismo drives it
directly (sched off-CPU today; on-CPU sampling + PMU counters next), so these
constants must track xnu. This tool fetches the relevant xnu headers for a macOS
release and reads the local SDK, then cross-checks every constant sismo declares
and flags drift. Run it when bumping macOS / adding kperf constants.

Sources:
  xnu (apple-oss-distributions/xnu @ rel/xnu-<major>):
    osfmk/kperf/buffer.h   PERF_* subclasses + event codes
    osfmk/kperf/action.h   SAMPLER_* bitmasks
  local macOS SDK:
    sys/kdebug.h           DBG_PERF class
    sys/sysctl.h           KERN_KD* command numbers
    sys/kdebug_private.h   KDBG_TYPEFILTER_BITMAP_SIZE

Usage:
  tools/verify_kperf_constants.py                 # this machine's xnu + SDK
  tools/verify_kperf_constants.py --xnu 12377     # a specific xnu major
Exit status is non-zero if any constant drifts (or a source can't be read).
"""

import argparse
import os
import re
import subprocess
import sys
import urllib.request

XNU_RAW = "https://raw.githubusercontent.com/apple-oss-distributions/xnu/rel/xnu-{ver}/{path}"

# Each check: (label, expected, source_key, regex, reduce). `reduce` maps the
# regex's captured group(s) to the integer the C macro evaluates to. `expected`
# mirrors the value sismo's Rust declares (kperf_offcpu.rs / kdebug.rs).
LIT = lambda m: int(m.group(1), 0)          # decimal or 0x hex
SHIFT = lambda m: 1 << int(m.group(1))       # (1U << n)
EXPR = lambda m: eval(m.group(1), {"__builtins__": {}})  # e.g. (256 * 256) / 8

CHECKS = [
    # DBG_PERF kdebug class (SDK ships it as decimal 37 == 0x25).
    ("DBG_PERF", 0x25, "sdk_kdebug", r"#define\s+DBG_PERF\s+(\d+)", LIT),
    # kperf subclasses (osfmk/kperf/buffer.h).
    ("PERF_THREADINFO", 1, "buffer", r"#define\s+PERF_THREADINFO\s+\((\d+)\)", LIT),
    ("PERF_CALLSTACK", 2, "buffer", r"#define\s+PERF_CALLSTACK\s+\((\d+)\)", LIT),
    ("PERF_TIMER", 3, "buffer", r"#define\s+PERF_TIMER\s+\((\d+)\)", LIT),
    ("PERF_LAZY", 9, "buffer", r"#define\s+PERF_LAZY\s+\((\d+)\)", LIT),
    # kperf event codes — the numeric arg to each *_CODE(n) macro.
    ("PERF_TI_DATA", 1, "buffer", r"#define\s+PERF_TI_DATA\s+PERF_TI_CODE\((\d+)\)", LIT),
    ("PERF_CS_KDATA", 3, "buffer", r"#define\s+PERF_CS_KDATA\s+PERF_CS_CODE\((\d+)\)", LIT),
    ("PERF_CS_UDATA", 4, "buffer", r"#define\s+PERF_CS_UDATA\s+PERF_CS_CODE\((\d+)\)", LIT),
    ("PERF_CS_KHDR", 5, "buffer", r"#define\s+PERF_CS_KHDR\s+PERF_CS_CODE\((\d+)\)", LIT),
    ("PERF_CS_UHDR", 6, "buffer", r"#define\s+PERF_CS_UHDR\s+PERF_CS_CODE\((\d+)\)", LIT),
    # on-CPU timer trigger (the event that precedes each timer sample's stack).
    ("PERF_TM_FIRE", 0, "buffer", r"#define\s+PERF_TM_FIRE\s+PERF_TM_CODE\((\d+)\)", LIT),
    ("PERF_LZ_WAITSAMPLE", 1, "buffer", r"#define\s+PERF_LZ_WAITSAMPLE\s+PERF_LZ_CODE\((\d+)\)", LIT),
    # kperf samplers (osfmk/kperf/action.h).
    ("SAMPLER_TH_INFO", 1 << 0, "action", r"#define\s+SAMPLER_TH_INFO\s+\(1U?\s*<<\s*(\d+)\)", SHIFT),
    ("SAMPLER_KSTACK", 1 << 2, "action", r"#define\s+SAMPLER_KSTACK\s+\(1U?\s*<<\s*(\d+)\)", SHIFT),
    ("SAMPLER_USTACK", 1 << 3, "action", r"#define\s+SAMPLER_USTACK\s+\(1U?\s*<<\s*(\d+)\)", SHIFT),
    # kdebug ring commands (SDK sys/sysctl.h) + typefilter bitmap (kdebug_private.h).
    ("KERN_KDSET_TYPEFILTER", 22, "sdk_sysctl", r"#define\s+KERN_KDSET_TYPEFILTER\s+(\d+)", LIT),
    ("KDBG_TYPEFILTER_BITMAP_SIZE", 8192, "sdk_kdpriv",
     r"#define\s+KDBG_TYPEFILTER_BITMAP_SIZE\s+\(([^)]*\)\s*)/\s*8\)", None),
]


def machine_xnu_major():
    out = subprocess.run(["uname", "-v"], capture_output=True, text=True).stdout
    m = re.search(r"xnu-(\d+)", out)
    return m.group(1) if m else None


def fetch_xnu(ver, path):
    url = XNU_RAW.format(ver=ver, path=path)
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            if r.status != 200:
                return None
            return r.read().decode("utf-8", "replace")
    except Exception:
        # Fall back to curl (some environments block urllib but allow curl).
        r = subprocess.run(["curl", "-fsSL", url], capture_output=True, text=True)
        return r.stdout if r.returncode == 0 else None


def sdk_path():
    r = subprocess.run(["xcrun", "--show-sdk-path"], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def read_file(path):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--xnu", help="xnu major version (default: this machine's)")
    args = ap.parse_args()

    ver = args.xnu or machine_xnu_major()
    if not ver:
        print("error: could not determine xnu version (pass --xnu)", file=sys.stderr)
        return 2
    sdk = sdk_path()
    if not sdk:
        print("error: `xcrun --show-sdk-path` failed (need the macOS SDK)", file=sys.stderr)
        return 2

    kf = os.path.join(sdk, "System/Library/Frameworks/Kernel.framework/Versions/A/Headers/sys")
    sources = {
        "buffer": fetch_xnu(ver, "osfmk/kperf/buffer.h"),
        "action": fetch_xnu(ver, "osfmk/kperf/action.h"),
        "sdk_kdebug": read_file(os.path.join(sdk, "usr/include/sys/kdebug.h")),
        "sdk_sysctl": read_file(os.path.join(sdk, "usr/include/sys/sysctl.h")),
        "sdk_kdpriv": read_file(os.path.join(kf, "kdebug_private.h")),
    }

    print(f"verifying kperf/kdebug constants against xnu-{ver} + SDK {os.path.basename(sdk)}\n")
    bad = 0
    for label, expected, key, pattern, reduce in CHECKS:
        text = sources.get(key)
        if text is None:
            print(f"  FAIL  {label:<28} source '{key}' unavailable")
            bad += 1
            continue
        m = re.search(pattern, text)
        if not m:
            print(f"  FAIL  {label:<28} not found in {key}")
            bad += 1
            continue
        # KDBG_TYPEFILTER_BITMAP_SIZE is `((256 * 256) / 8)`; evaluate the (a*b)/8.
        got = int(eval(m.group(1), {"__builtins__": {}}) / 8) if reduce is None else reduce(m)
        ok = got == expected
        bad += not ok
        print(f"  {'ok  ' if ok else 'FAIL'}  {label:<28} source={got}  ours={expected}"
              + ("" if ok else "   <<< DRIFT"))

    print()
    if bad:
        print(f"{bad} constant(s) drifted or unreadable — update the Rust declarations.")
        return 1
    print("all constants match xnu source.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
