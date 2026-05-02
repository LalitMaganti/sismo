#!/usr/bin/env bash
# tools/e2e_all_sources.sh — full end-to-end test of `sismo record`.
# Builds everything, runs the recorder under sudo (so the in-process
# heap and CPU producers can task_for_pid the spawned target), and
# validates that every data source landed in the trace via
# trace_processor SQL.
#
# Pass criterion: non-zero rows in all four tables —
#   slice                    (TrackEvent zones from sample-target)
#   heap_profile_allocation  (sismo.heap)
#   perf_sample              (sismo.macos_cpu_samples)
#   sched_slice              (sismo.macos_sched)
#
# usage: tools/e2e_all_sources.sh
# (will prompt for sudo password once.)

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SISMO="$REPO/zig-out/bin/sismo"
TRACE=/tmp/sismo-e2e.pftrace
TP="$REPO/third_party/src/perfetto/out/sismo/trace_processor_shell"
DURATION_MS=3000

cd "$REPO"

echo "==> building"
zig build >/dev/null

echo "==> priming sudo (password may be asked once)"
sudo -v

rm -f "$TRACE"
echo
echo "==> sismo record (workload runs ${DURATION_MS}ms) -> $TRACE"
RUNLOG=/tmp/sismo-e2e-run.log
sudo -E "$SISMO" record \
    --output "$TRACE" \
    "$REPO/zig-out/bin/sample-target" "$DURATION_MS" \
    >"$RUNLOG" 2>&1 || true
# Show diagnostic prints (filter out DebugAllocator leak noise that
# fires at sismo's exit).
echo "--- run log (filtered) ---"
grep -vE "^(error\(DebugAllocator\)|/opt/homebrew|/Users/lalitm/depot/projects/sismo/src/sismo_record.zig:(68|86):|.*in (dupe|maybeSpawn|callMain|wrapMain)|^$|^\s*\^|return wrapMain|stack frames|return allocator|return maybeSpawnInner|const s = try|const new_buf|        cpu_child|        heap_child)" "$RUNLOG" | tail -50
echo "--- end run log ---"

echo
ls -la "$TRACE"

QUERY="
SELECT name, value FROM (
  SELECT 'slice (track_event)' AS name, count(*) AS value FROM slice
  UNION ALL SELECT 'heap_profile_allocation', count(*) FROM heap_profile_allocation
  UNION ALL SELECT 'perf_sample', count(*) FROM perf_sample
  UNION ALL SELECT 'sched_slice', count(*) FROM sched_slice
);
"

echo
echo "==> trace_processor SQL"
RESULTS=$("$TP" "$TRACE" -q /dev/stdin <<<"$QUERY" 2>&1 | grep -E '^"' | tail -10)
echo "$RESULTS"

# Pass = every row has value > 0.
fail=0
while IFS= read -r line; do
    name=$(echo "$line" | awk -F'"|,' '{print $2}')
    val=$(echo "$line" | awk -F'"|,' '{print $4}' | tr -d ' "')
    # Skip the header row.
    [[ "$name" == "name" || -z "$name" ]] && continue
    if [[ "$val" == "0" || -z "$val" ]]; then
        echo "FAIL: $name has 0 rows"
        fail=1
    fi
done <<< "$RESULTS"

echo
if [[ $fail -eq 0 ]]; then
    echo "PASS: all four data sources captured"
else
    echo "PARTIAL: some data sources missing — see above"
    exit 1
fi
