#!/bin/bash
# tools/heap_reattach_test.sh — runs sismo-record twice against the
# same long-lived target to verify the heap producer's
# dormant→active→dormant→active cycle. Each run is its own attached
# session; the target stays alive between them.
#
# Sismo-record always orchestrates the full pipeline (traced + IPC
# socket + spawning the producers + writing the unified trace). There
# is no longer a standalone heap-profiler invocation.
#
# usage: tools/heap_reattach_test.sh
# (requires sudo for sismo-heap's task_for_pid; will prompt once.)

set -e

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SISMO_RECORD="$REPO/zig-out/bin/sismo-record"
RUN1_TRACE=/tmp/sismo-reattach-run1.pftrace
RUN2_TRACE=/tmp/sismo-reattach-run2.pftrace

cd "$REPO"

echo "==> building"
zig build >/dev/null

echo "==> priming sudo (password may be asked once)"
sudo -v

DURATION_MS=1500
GAP_SECS=2

echo
echo "==> RUN 1: sismo-record orchestrates ${DURATION_MS}ms of capture"
sudo "$SISMO_RECORD" "$DURATION_MS" "$RUN1_TRACE" 2>&1 | tail -8

echo
echo "==> IDLE: ${GAP_SECS}s — no recording in flight"
sleep "$GAP_SECS"

echo
echo "==> RUN 2: sismo-record reattaches + records again"
sudo "$SISMO_RECORD" "$DURATION_MS" "$RUN2_TRACE" 2>&1 | tail -8

echo
echo "==> SUMMARY"
ls -la "$RUN1_TRACE" "$RUN2_TRACE" 2>/dev/null

QUERY="
SELECT 'slice' AS data_source, count(*) AS rows FROM slice
UNION ALL SELECT 'sched_slice', count(*) FROM sched_slice
UNION ALL SELECT 'cpu_profile_stack_sample', count(*) FROM cpu_profile_stack_sample
UNION ALL SELECT 'heap_profile_allocation', count(*) FROM heap_profile_allocation;
"
TP="$REPO/third_party/src/perfetto/out/sismo/trace_processor_shell"

echo
echo "----- run 1 contents -----"
"$TP" "$RUN1_TRACE" -q /dev/stdin <<<"$QUERY" 2>&1 | tail -8

echo
echo "----- run 2 contents -----"
"$TP" "$RUN2_TRACE" -q /dev/stdin <<<"$QUERY" 2>&1 | tail -8
