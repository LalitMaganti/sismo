# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""Incremental build of the Perfetto targets sismo links against.

Driven by zig build, but standalone-runnable for debugging the GN side.

By default builds the host out dir (out/sismo). For cross-compile pass
--target / SISMO_TARGET — must match what tools/setup-perfetto was called
with:

    tools/build-perfetto                              # host
    tools/build-perfetto --target x86_64-linux-gnu    # Linux x64 cross
    SISMO_TARGET=x86_64-linux-gnu tools/build-perfetto

Run tools/setup-perfetto (with the same target) once before the first
invocation.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

ROOT_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PERFETTO_DIR: str = os.path.join(ROOT_DIR, "third_party", "src", "perfetto")

# Map of SISMO_TARGET → perfetto out-dir name. None means "host".
TARGET_TO_OUT_NAME: dict[str, str] = {
    "x86_64-linux-gnu": "sismo_linux_x64",
    "x86_64-linux-musl": "sismo_linux_x64",
    "aarch64-linux-gnu": "sismo_linux_arm64",
    "aarch64-linux-musl": "sismo_linux_arm64",
    "x86_64-windows-gnu": "sismo_windows_x64",
    "aarch64-windows-gnu": "sismo_windows_arm64",
}


def resolve_out_name(target: str) -> str:
    if not target:
        return "sismo"
    out = TARGET_TO_OUT_NAME.get(target)
    if out is None:
        sys.exit(f"unsupported SISMO_TARGET '{target}'")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--target",
        default=os.environ.get("SISMO_TARGET", ""),
        help="Target triple for cross-compile (also honored via SISMO_TARGET env)",
    )
    args = parser.parse_args()

    out_name = resolve_out_name(args.target)
    out_dir = os.path.join(PERFETTO_DIR, "out", out_name)
    ninja = os.path.join(PERFETTO_DIR, "tools", "ninja")

    if not os.access(ninja, os.X_OK):
        print(
            f"ninja not found at {ninja} — did you run tools/setup-perfetto?",
            file=sys.stderr,
        )
        return 1
    if not os.path.isfile(os.path.join(out_dir, "args.gn")):
        print(
            f"no args.gn at {out_dir} — did you run "
            f"`SISMO_TARGET={args.target} tools/setup-perfetto`?",
            file=sys.stderr,
        )
        return 1

    # Targets we need (GN labels confirmed from the vendored tree):
    #
    #   //sismo:sismo_libperfetto       — sismo-defined static_library that
    #                                     bundles service + client API +
    #                                     tracing backends + C SDK into one
    #                                     archive (libsismo_libperfetto.a).
    #                                     The target lives in the sismo repo
    #                                     at infra/perfetto-build/sismo/BUILD.gn
    #                                     and is symlinked into //sismo by
    #                                     tools/setup-perfetto — no
    #                                     modifications to Perfetto's BUILD.gn.
    #   traced                          — service binary; linked separately by
    #                                     sismo's process model.
    #   trace_processor_shell           — standalone for E2E validation.
    targets = ["sismo:sismo_libperfetto", "traced"]

    # Native builds also pull in trace_processor_shell (E2E validation).
    # Cross-compiles skip it because SQLite trips zig cc's stricter
    # -Wincompatible-pointer-types-discards-qualifiers under -Werror.
    if not args.target:
        targets.append("trace_processor_shell")

    # traced_perf / traced_probes producer source sets are pulled in
    # transitively by //sismo:sismo_libperfetto on Linux (see deps in
    # infra/perfetto-build/sismo/BUILD.gn) — no need to list them here.

    print(f"==> building Perfetto targets in {out_name}: {' '.join(targets)}")
    rc = subprocess.run([ninja, "-C", out_dir, *targets]).returncode
    if rc != 0:
        return rc

    print()
    print(f"==> built artifacts in {out_dir}/")
    interesting = ("traced", "libperfetto", "libsismo_libperfetto", "trace_processor")
    listed = 0
    for entry in sorted(os.listdir(out_dir)):
        if listed >= 20:
            break
        if any(needle in entry for needle in interesting):
            full = os.path.join(out_dir, entry)
            try:
                size = os.path.getsize(full)
            except OSError:
                size = 0
            print(f"  {size:>12}  {entry}")
            listed += 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
