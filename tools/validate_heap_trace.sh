#!/usr/bin/env bash
# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

# tools/validate_heap_trace.sh — assert /tmp/sismo-heap.pftrace
# (or $1) loads in trace_processor and contains heap_profile_allocation
# rows. Used as the validation step in plans/07-unified-e2e.md Phase 4.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
TRACE="${1:-/tmp/sismo-heap.pftrace}"
TP="$REPO/third_party/src/perfetto/out/sismo/trace_processor_shell"

if [[ ! -f "$TRACE" ]]; then
    echo "FAIL: trace not found at $TRACE" >&2
    exit 1
fi

if [[ ! -x "$TP" ]]; then
    echo "FAIL: trace_processor_shell not found at $TP" >&2
    echo "      Run tools/build_perfetto.sh first." >&2
    exit 1
fi

QUERY="
SELECT 'heap_profile_allocation' AS tbl, count(*) AS rows FROM heap_profile_allocation
UNION ALL
SELECT 'stack_profile_callsite', count(*) FROM stack_profile_callsite
UNION ALL
SELECT 'stack_profile_frame', count(*) FROM stack_profile_frame
UNION ALL
SELECT 'stack_profile_mapping', count(*) FROM stack_profile_mapping;
"

echo "==> validating $TRACE"
RESULTS=$("$TP" "$TRACE" -q /dev/stdin <<<"$QUERY" 2>&1)
echo "$RESULTS"

ALLOCS=$(echo "$RESULTS" | awk -F'"|,' '/heap_profile_allocation/ {print $4}' | tr -d ' "')
if [[ -z "$ALLOCS" || "$ALLOCS" == "0" ]]; then
    echo
    echo "FAIL: heap_profile_allocation has 0 rows" >&2
    exit 1
fi

echo
echo "PASS: heap_profile_allocation has $ALLOCS rows"
