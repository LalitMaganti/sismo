// Copyright (C) 2026 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import type {Engine} from '../../../trace_processor/engine';
import {
  LONG_NULL,
  NUM,
  NUM_NULL,
  STR_NULL,
} from '../../../trace_processor/query_result';
import type {PrivilegedSet} from '../privileged_set';
import {sampleScopePredicate} from './sql';

// One time-bucket of the Activity board. Slices are bucketed by their start ts
// — for a coarse board (~hundreds of buckets, each far wider than a sched
// slice) that's a faithful-enough approximation without per-bucket interval
// splitting. avg concurrency in a bucket = privBusyNs / bucketWidth. Churn is
// the count of run→sleep transitions (the scoped set entering S/D), NOT sched
// slice starts — preemptions and migrations aren't churn. avgRunNs (mean
// Running-interval length) separates batched work (long runs) from thrash
// (many short runs).
export interface ActivityBucket {
  startTs: bigint;
  endTs: bigint;
  busyNs: bigint;
  privBusyNs: bigint;
  sleeps: number;
  avgRunNs: number;
  // Cycles delivered in this bucket, from the eBPF leader-sampled counters
  // (cumulative per thread → consecutive-sample deltas). 0 on traces without
  // perf counters; lets the board show compute intensity without cpufreq.
  cyclesDelta: bigint;
}

export interface ActivityBoard {
  hasData: boolean;
  numCpus: number;
  bucketWidthNs: bigint;
  buckets: ActivityBucket[];
}

const EMPTY_BOARD: ActivityBoard = {
  hasData: false,
  numCpus: 0,
  bucketWidthNs: 0n,
  buckets: [],
};

// Quantises the trace into `numBuckets` equal time slices and, per bucket,
// measures machine-busy time, the scoped set's busy time (→ utilisation and
// average concurrency), and the scoped set's run-starts (→ churn). The shared
// time axis is what lets the Activity board's lanes be read against each other.
export async function loadActivityBoard(
  engine: Engine,
  priv: PrivilegedSet,
  numBuckets = 160,
): Promise<ActivityBoard> {
  const bounds = await engine.query(
    `SELECT min(ts) AS lo, max(ts + dur) AS hi FROM sched WHERE dur > 0`,
  );
  const b = bounds.firstRow({lo: LONG_NULL, hi: LONG_NULL});
  const lo = b.lo;
  const hi = b.hi;
  if (lo === null || hi === null || hi <= lo) return EMPTY_BOARD;

  const span = hi - lo;
  const width = span / BigInt(numBuckets) > 0n ? span / BigInt(numBuckets) : 1n;
  const numCpusRes = await engine.query(`SELECT count(*) AS n FROM cpu`);
  const numCpus = numCpusRes.firstRow({n: NUM}).n;

  // `1` (always-true) when there's no privileged set, so the scoped lanes show
  // the whole workload rather than nothing.
  const privExpr =
    priv.upids.length > 0
      ? `thread.upid IN (${priv.upids.join(',')})`
      : '1';

  const buckets: ActivityBucket[] = [];
  for (let i = 0; i < numBuckets; i++) {
    const start = lo + BigInt(i) * width;
    buckets.push({
      startTs: start,
      endTs: start + width,
      busyNs: 0n,
      privBusyNs: 0n,
      sleeps: 0,
      avgRunNs: 0,
      cyclesDelta: 0n,
    });
  }

  // Busy / scoped-busy time per bucket (utilisation + concurrency), from sched.
  const sched = await engine.query(`
    WITH s AS (
      SELECT
        CAST((sched.ts - ${lo}) / ${width} AS INT) AS bucket,
        sched.dur AS dur,
        (CASE WHEN ${privExpr} THEN 1 ELSE 0 END) AS is_priv
      FROM sched
      JOIN thread USING (utid)
      WHERE sched.dur > 0
        AND NOT (sched.utid IN (SELECT utid FROM thread WHERE is_idle))
    )
    SELECT
      bucket,
      sum(dur) AS busy,
      sum(CASE WHEN is_priv = 1 THEN dur ELSE 0 END) AS priv_busy
    FROM s
    WHERE bucket >= 0 AND bucket < ${numBuckets}
    GROUP BY bucket
  `);
  let hasData = false;
  for (
    const it = sched.iter({bucket: NUM, busy: LONG_NULL, priv_busy: LONG_NULL});
    it.valid();
    it.next()
  ) {
    const slot = buckets[it.bucket];
    if (slot === undefined) continue;
    slot.busyNs = it.busy ?? 0n;
    slot.privBusyNs = it.priv_busy ?? 0n;
    if (slot.busyNs > 0n) hasData = true;
  }

  // Run↔sleep churn and mean run length per bucket, from thread_state. Churn =
  // the scoped set entering an off-CPU sleep (S/D); avgRun = mean length of its
  // Running intervals (long → batched, short → thrashy). Bucketed by the
  // interval's start (these are point-in-time events / short relative to a
  // bucket).
  const states = await engine.query(`
    WITH ts AS (
      SELECT
        CAST((thread_state.ts - ${lo}) / ${width} AS INT) AS bucket,
        thread_state.state AS state,
        thread_state.dur AS dur
      FROM thread_state
      JOIN thread USING (utid)
      WHERE thread_state.dur > 0
        AND NOT (thread.utid IN (SELECT utid FROM thread WHERE is_idle))
        AND (${privExpr})
    )
    SELECT
      bucket,
      sum(CASE WHEN state IN ('S', 'D') THEN 1 ELSE 0 END) AS sleeps,
      sum(CASE WHEN state = 'Running' THEN 1 ELSE 0 END) AS run_starts,
      sum(CASE WHEN state = 'Running' THEN dur ELSE 0 END) AS run_dur
    FROM ts
    WHERE bucket >= 0 AND bucket < ${numBuckets}
    GROUP BY bucket
  `);
  for (
    const it = states.iter({
      bucket: NUM,
      sleeps: NUM,
      run_starts: NUM,
      run_dur: LONG_NULL,
    });
    it.valid();
    it.next()
  ) {
    const slot = buckets[it.bucket];
    if (slot === undefined) continue;
    slot.sleeps = it.sleeps;
    slot.avgRunNs =
      it.run_starts > 0 ? Number(it.run_dur ?? 0n) / it.run_starts : 0;
  }

  // Cycles delivered per bucket, from the eBPF leader-sampled counters. The
  // counter is cumulative per thread, so the per-bucket delta is the difference
  // between consecutive samples of the same (utid, track); the first sample of
  // each series has a NULL delta and drops out. Guarded — the perf module /
  // table is absent on traces recorded without counters, in which case the
  // Cycles lane simply stays empty.
  try {
    await engine.query('INCLUDE PERFETTO MODULE linux.perf.counters;');
    const cycScope = sampleScopePredicate(priv);
    const cyc = await engine.query(`
      WITH d AS (
        SELECT
          CAST((s.ts - ${lo}) / ${width} AS INT) AS bucket,
          s.counter_value - lag(s.counter_value) OVER (
            PARTITION BY s.utid, s.track_id ORDER BY s.ts
          ) AS dv
        FROM linux_perf_sample_with_counters s
        JOIN track t ON t.id = s.track_id
        WHERE t.name = 'cpu-cycles' ${cycScope}
      )
      SELECT bucket, sum(dv) AS cycles
      FROM d
      WHERE dv IS NOT NULL AND dv >= 0
        AND bucket >= 0 AND bucket < ${numBuckets}
      GROUP BY bucket
    `);
    for (
      const it = cyc.iter({bucket: NUM, cycles: LONG_NULL});
      it.valid();
      it.next()
    ) {
      const slot = buckets[it.bucket];
      if (slot !== undefined) slot.cyclesDelta = it.cycles ?? 0n;
    }
  } catch {
    // No perf counters in this trace — leave cyclesDelta at 0.
  }

  return {hasData, numCpus, bucketWidthNs: width, buckets};
}

// Top threads active in an arbitrary time window [loTs, hiTs), by their runtime
// clipped to that window. Drives the Activity board's "who was busy in this
// slice" drill. `upid` lets the view mark which rows are the profiled set.
export interface WindowThreadRow {
  utid: number;
  tid: number | null;
  upid: number | null;
  threadName: string;
  processName: string | null;
  runtimeNs: bigint;
}

export async function loadWindowConsumers(
  engine: Engine,
  loTs: bigint,
  hiTs: bigint,
  limit = 10,
): Promise<WindowThreadRow[]> {
  const res = await engine.query(`
    SELECT
      th.utid AS utid,
      th.tid AS tid,
      th.upid AS upid,
      coalesce(th.name, '[utid ' || th.utid || ']') AS thread_name,
      p.name AS process_name,
      sum(min(sched.ts + sched.dur, ${hiTs}) - max(sched.ts, ${loTs})) AS rt
    FROM sched
    JOIN thread th USING (utid)
    LEFT JOIN process p ON p.upid = th.upid
    WHERE sched.dur > 0
      AND sched.ts < ${hiTs}
      AND sched.ts + sched.dur > ${loTs}
      AND NOT (th.utid IN (SELECT utid FROM thread WHERE is_idle))
    GROUP BY th.utid
    ORDER BY rt DESC
    LIMIT ${limit}
  `);
  const rows: WindowThreadRow[] = [];
  for (
    const it = res.iter({
      utid: NUM,
      tid: NUM_NULL,
      upid: NUM_NULL,
      thread_name: STR_NULL,
      process_name: STR_NULL,
      rt: LONG_NULL,
    });
    it.valid();
    it.next()
  ) {
    rows.push({
      utid: it.utid,
      tid: it.tid,
      upid: it.upid,
      threadName: it.thread_name ?? '<unknown>',
      processName: it.process_name,
      runtimeNs: it.rt ?? 0n,
    });
  }
  return rows;
}
