#!/usr/bin/env bash
# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

# tools/build_perfetto.sh — incremental build of the Perfetto targets
# sismo links against. Driven by zig build, but standalone-runnable
# for debugging the GN side.
#
# By default builds the host out dir (out/sismo). For cross-compile
# pass SISMO_TARGET — must match what tools/setup_perfetto.sh was
# called with:
#
#   tools/build_perfetto.sh                          # host
#   SISMO_TARGET=x86_64-linux-gnu \
#     tools/build_perfetto.sh                        # Linux x64 cross
#
# Run tools/setup_perfetto.sh (with the same SISMO_TARGET) once before
# the first invocation.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PERFETTO_DIR="$REPO/third_party/src/perfetto"
SISMO_TARGET="${SISMO_TARGET:-}"

case "$SISMO_TARGET" in
    "")                                  OUT_NAME="sismo" ;;
    x86_64-linux-gnu|x86_64-linux-musl)  OUT_NAME="sismo_linux_x64" ;;
    aarch64-linux-gnu|aarch64-linux-musl) OUT_NAME="sismo_linux_arm64" ;;
    x86_64-windows-gnu)                  OUT_NAME="sismo_windows_x64" ;;
    aarch64-windows-gnu)                 OUT_NAME="sismo_windows_arm64" ;;
    *) echo "unsupported SISMO_TARGET '$SISMO_TARGET'" >&2 ; exit 1 ;;
esac

OUT_DIR="$PERFETTO_DIR/out/$OUT_NAME"
NINJA="$PERFETTO_DIR/tools/ninja"

if [[ ! -x "$NINJA" ]]; then
    echo "ninja not found at $NINJA — did you run tools/setup_perfetto.sh?" >&2
    exit 1
fi
if [[ ! -f "$OUT_DIR/args.gn" ]]; then
    echo "no args.gn at $OUT_DIR — did you run \`SISMO_TARGET=$SISMO_TARGET tools/setup_perfetto.sh\`?" >&2
    exit 1
fi

# Targets we need (GN labels confirmed from the vendored tree):
#
#   traced                          — bundles libperfetto.a as a side
#                                     effect (sismo-local patch in
#                                     third_party/src/perfetto/BUILD.gn
#                                     makes the archive comprehensive:
#                                     service code + client API +
#                                     tracing backends + C SDK).
#   trace_processor_shell           — standalone for E2E validation.
#   //src/profiling/perf:producer   — Linux-only traced_perf source set,
#                                     linked in-process on Linux.
#   //src/traced/probes:probes_src  — Linux-only traced_probes source set
#                                     (ftrace + procfs); the :probes_src
#                                     target excludes probes.cc's main()
#                                     which is what we want for embedding.
TARGETS=("traced")

# Native builds also pull in trace_processor_shell (E2E validation).
# Cross-compiles skip it because SQLite trips zig cc's stricter
# -Wincompatible-pointer-types-discards-qualifiers under -Werror.
if [[ -z "$SISMO_TARGET" ]]; then
    TARGETS+=("trace_processor_shell")
fi

# traced_perf and traced_probes are Linux-only producers we link in
# process. traced_perf pulls in buildtools/android-unwinding for stack
# unwinding; traced_probes pulls in the ftrace + procfs machinery. Both
# need to be built on every Linux build (native and cross).
case "${SISMO_TARGET:-$(uname -s)}" in
    *linux*|Linux)
        TARGETS+=("src/profiling/perf:producer")
        TARGETS+=("src/traced/probes:probes_src")
        ;;
esac

echo "==> building Perfetto targets in $OUT_NAME: ${TARGETS[*]}"
"$NINJA" -C "$OUT_DIR" "${TARGETS[@]}"

echo
echo "==> built artifacts in $OUT_DIR/"
ls -la "$OUT_DIR/" | grep -E "(traced|libperfetto|trace_processor)" | head -20
