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
import {clamp01} from '../format';
import {getSchedBounds, privInClause, privNotInClause} from './sql';
import {
  clipDurExpr,
  overlapClause,
  tsRangeClause,
  type FocusWindow,
} from './focus_window';

export interface CpuCoreRow {
  cpu: number;
  clusterId: number | null;
  // Relative core capacity (ARM DynamIQ / Apple AMP: bigger = performance
  // core). Null on uniform x86. Used to label clusters P/E.
  capacity: number | null;
  processor: string | null;
  runtimeNs: bigint | null;
  privilegedRuntimeNs: bigint | null;
}

export interface CpuProcessRow {
  upid: number;
  pid: number | null;
  name: string;
  runtimeNs: bigint;
}

export interface CpuThreadRow {
  utid: number;
  tid: number | null;
  upid: number | null;
  threadName: string;
  processName: string | null;
  runtimeNs: bigint;
}

export interface CpuIdleStateRow {
  cpu: number;
  state: string;
  residencyUs: number;
  percentage: number;
}

export interface ThreadStateRow {
  utid: number;
  tid: number | null;
  threadName: string;
  processName: string | null;
  runningNs: bigint;
  runnableNs: bigint;
  uninterruptibleNs: bigint;
  sleepingNs: bigint;
  otherNs: bigint;
  // Count of Running intervals — a proxy for context switches onto the CPU.
  numRunSlices: number;
}

export interface CoreActivityRow {
  cpu: number;
  busyNs: bigint;
  threads: number;
}

export interface CpuBlameRow {
  upid: number;
  pid: number | null;
  name: string;
  blockedNs: bigint;
}
export interface CpuThreadBlameRow {
  utid: number;
  tid: number | null;
  threadName: string;
  processName: string | null;
  blockedNs: bigint;
}

// Total non-idle CPU time in the window (or whole trace), and the profiled
// set's slice of it. The denominator for "% of CPU" on the windowed Threads and
// Cores tables — the preloaded whole-trace summary's total can't be reused once
// a focus is set.
export interface CpuRuntimeTotals {
  totalNs: bigint;
  privilegedNs: bigint | null;
}

export async function loadCpuTotals(
  engine: Engine,
  priv: PrivilegedSet,
  window?: FocusWindow,
): Promise<CpuRuntimeTotals> {
  const clip = clipDurExpr(window, 'sched.ts', 'sched.dur');
  const overlap = overlapClause(window, 'sched.ts', 'sched.dur');
  const hasPriv = priv.upids.length > 0;
  const privIn = privInClause(priv);
  const res = await engine.query(`
    SELECT
      sum(${clip}) AS total,
      sum(CASE WHEN thread.upid ${privIn} THEN ${clip} ELSE 0 END) AS priv
    FROM sched
    JOIN thread USING (utid)
    WHERE sched.dur > 0
      AND NOT (sched.utid IN (SELECT utid FROM thread WHERE is_idle))${overlap}
  `);
  const r = res.firstRow({total: LONG_NULL, priv: LONG_NULL});
  return {
    totalNs: r.total ?? 0n,
    privilegedNs: hasPriv ? (r.priv ?? 0n) : null,
  };
}

export async function loadPerCore(
  engine: Engine,
  priv: PrivilegedSet,
  window?: FocusWindow,
): Promise<CpuCoreRow[]> {
  // Aggregate by `ucpu` not `cpu` so multi-machine traces don't collapse CPUs
  // that share a number across machines.
  const privIn = privInClause(priv);
  const bareOverlap = overlapClause(window, 'ts', 'dur');
  const bareClip = clipDurExpr(window, 'ts', 'dur');
  const overlap = overlapClause(window, 'sched.ts', 'sched.dur');
  const clip = clipDurExpr(window, 'sched.ts', 'sched.dur');
  const res = await engine.query(`
    WITH sched_per_cpu AS (
      SELECT
        ucpu,
        sum(${bareClip}) AS runtime
      FROM sched
      WHERE dur > 0
        AND NOT (utid IN (SELECT utid FROM thread WHERE is_idle))${bareOverlap}
      GROUP BY ucpu
    ),
    priv_per_cpu AS (
      SELECT
        sched.ucpu AS ucpu,
        sum(${clip}) AS runtime
      FROM sched
      JOIN thread USING (utid)
      WHERE thread.upid ${privIn}
        AND sched.dur > 0
        AND NOT (sched.utid IN (SELECT utid FROM thread WHERE is_idle))${overlap}
      GROUP BY sched.ucpu
    )
    SELECT
      cpu.cpu AS cpu,
      cpu.cluster_id AS cluster_id,
      cpu.capacity AS capacity,
      cpu.processor AS processor,
      sched_per_cpu.runtime AS runtime_ns,
      priv_per_cpu.runtime AS priv_runtime_ns
    FROM cpu
    LEFT JOIN sched_per_cpu USING (ucpu)
    LEFT JOIN priv_per_cpu USING (ucpu)
    ORDER BY cpu.cpu
  `);
  const rows: CpuCoreRow[] = [];
  for (
    const it = res.iter({
      cpu: NUM_NULL,
      cluster_id: NUM_NULL,
      capacity: NUM_NULL,
      processor: STR_NULL,
      runtime_ns: LONG_NULL,
      priv_runtime_ns: LONG_NULL,
    });
    it.valid();
    it.next()
  ) {
    if (it.cpu === null) continue;
    rows.push({
      cpu: it.cpu,
      clusterId: it.cluster_id,
      capacity: it.capacity,
      processor: it.processor,
      runtimeNs: it.runtime_ns ?? null,
      privilegedRuntimeNs:
        priv.upids.length > 0 ? (it.priv_runtime_ns ?? 0n) : null,
    });
  }
  return rows;
}

export async function loadProcessRows(
  engine: Engine,
  priv: PrivilegedSet,
  kind: 'privileged' | 'context',
  limit?: number,
  window?: FocusWindow,
): Promise<CpuProcessRow[]> {
  if (kind === 'privileged' && priv.upids.length === 0) return [];
  const upidClause =
    kind === 'privileged' ? privInClause(priv) : privNotInClause(priv);
  const limitClause = limit !== undefined ? `LIMIT ${limit}` : '';
  const clip = clipDurExpr(window, 'sched.ts', 'sched.dur');
  const overlap = overlapClause(window, 'sched.ts', 'sched.dur');
  const res = await engine.query(`
    WITH per_process AS (
      SELECT
        thread.upid AS upid,
        sum(${clip}) AS runtime_ns
      FROM sched
      JOIN thread USING (utid)
      WHERE thread.upid IS NOT NULL
        AND thread.upid ${upidClause}
        AND sched.dur > 0
        AND NOT (utid IN (SELECT utid FROM thread WHERE is_idle))${overlap}
      GROUP BY thread.upid
    )
    SELECT
      per_process.upid AS upid,
      process.pid AS pid,
      coalesce(process.name, '[upid ' || per_process.upid || ']') AS name,
      per_process.runtime_ns AS runtime_ns
    FROM per_process
    JOIN process USING (upid)
    ORDER BY runtime_ns DESC
    ${limitClause}
  `);
  const rows: CpuProcessRow[] = [];
  for (
    const it = res.iter({
      upid: NUM,
      pid: NUM_NULL,
      name: STR_NULL,
      runtime_ns: LONG_NULL,
    });
    it.valid();
    it.next()
  ) {
    rows.push({
      upid: it.upid,
      pid: it.pid,
      name: it.name ?? '<unknown>',
      runtimeNs: it.runtime_ns ?? 0n,
    });
  }
  return rows;
}

export async function loadThreadRows(
  engine: Engine,
  priv: PrivilegedSet,
  kind: 'privileged' | 'context',
  limit?: number,
  window?: FocusWindow,
): Promise<CpuThreadRow[]> {
  if (kind === 'privileged' && priv.upids.length === 0) return [];
  const upidClause =
    kind === 'privileged' ? privInClause(priv) : privNotInClause(priv);
  const limitClause = limit !== undefined ? `LIMIT ${limit}` : '';
  const clip = clipDurExpr(window, 'sched.ts', 'sched.dur');
  const overlap = overlapClause(window, 'sched.ts', 'sched.dur');
  const res = await engine.query(`
    WITH per_thread AS (
      SELECT
        sched.utid AS utid,
        sum(${clip}) AS runtime_ns
      FROM sched
      JOIN thread USING (utid)
      WHERE thread.upid IS NOT NULL
        AND thread.upid ${upidClause}
        AND sched.dur > 0
        AND NOT (sched.utid IN (SELECT utid FROM thread WHERE is_idle))${overlap}
      GROUP BY sched.utid
    )
    SELECT
      thread.utid AS utid,
      thread.tid AS tid,
      thread.upid AS upid,
      coalesce(thread.name, '[utid ' || thread.utid || ']') AS thread_name,
      process.name AS process_name,
      per_thread.runtime_ns AS runtime_ns
    FROM per_thread
    JOIN thread USING (utid)
    LEFT JOIN process USING (upid)
    ORDER BY runtime_ns DESC
    ${limitClause}
  `);
  const rows: CpuThreadRow[] = [];
  for (
    const it = res.iter({
      utid: NUM,
      tid: NUM_NULL,
      upid: NUM_NULL,
      thread_name: STR_NULL,
      process_name: STR_NULL,
      runtime_ns: LONG_NULL,
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
      runtimeNs: it.runtime_ns ?? 0n,
    });
  }
  return rows;
}

// No same-CPU partition: trace_processor only populates thread_state.cpu for
// Running rows (NULL for R/R+), so we can't tell which runqueue our thread
// was on. On multi-core, if a thread is runnable-not-running then all cores
// are busy — so every concurrent context-running process is collectively
// keeping us off the CPU. Sum-overlap captures that.
export async function loadBlame(
  engine: Engine,
  priv: PrivilegedSet,
  limit: number,
): Promise<CpuBlameRow[]> {
  if (priv.upids.length === 0) return [];
  const privIn = privInClause(priv);
  const privNotIn = privNotInClause(priv);
  await engine.query('INCLUDE PERFETTO MODULE intervals.intersect;');
  const res = await engine.query(`
    WITH priv_runnable AS (
      SELECT
        thread_state.id AS id,
        thread_state.ts AS ts,
        thread_state.dur AS dur
      FROM thread_state
      JOIN thread USING (utid)
      WHERE thread_state.state IN ('R', 'R+')
        AND thread.upid ${privIn}
        AND thread_state.dur > 0
      ORDER BY ts
    ),
    ctx_running AS (
      SELECT
        sched.id AS id,
        sched.ts AS ts,
        sched.dur AS dur,
        thread.upid AS upid
      FROM sched
      JOIN thread USING (utid)
      WHERE thread.upid IS NOT NULL
        AND thread.upid ${privNotIn}
        AND NOT (sched.utid IN (SELECT utid FROM thread WHERE is_idle))
        AND sched.dur > 0
      ORDER BY ts
    ),
    intersected AS (
      SELECT dur, id_1 AS ctx_id
      FROM _interval_intersect!((priv_runnable, ctx_running), ())
    )
    SELECT
      process.upid AS upid,
      process.pid AS pid,
      coalesce(process.name, '[upid ' || process.upid || ']') AS name,
      sum(intersected.dur) AS blocked_ns
    FROM intersected
    JOIN ctx_running ON ctx_running.id = intersected.ctx_id
    JOIN process ON process.upid = ctx_running.upid
    GROUP BY process.upid
    HAVING blocked_ns > 0
    ORDER BY blocked_ns DESC
    LIMIT ${limit}
  `);
  const rows: CpuBlameRow[] = [];
  for (
    const it = res.iter({
      upid: NUM,
      pid: NUM_NULL,
      name: STR_NULL,
      blocked_ns: LONG_NULL,
    });
    it.valid();
    it.next()
  ) {
    rows.push({
      upid: it.upid,
      pid: it.pid,
      name: it.name ?? '<unknown>',
      blockedNs: it.blocked_ns ?? 0n,
    });
  }
  return rows;
}

export async function loadThreadBlame(
  engine: Engine,
  priv: PrivilegedSet,
  limit: number,
): Promise<CpuThreadBlameRow[]> {
  if (priv.upids.length === 0) return [];
  const privIn = privInClause(priv);
  const privNotIn = privNotInClause(priv);
  await engine.query('INCLUDE PERFETTO MODULE intervals.intersect;');
  const res = await engine.query(`
    WITH priv_runnable AS (
      SELECT
        thread_state.id AS id,
        thread_state.ts AS ts,
        thread_state.dur AS dur
      FROM thread_state
      JOIN thread USING (utid)
      WHERE thread_state.state IN ('R', 'R+')
        AND thread.upid ${privIn}
        AND thread_state.dur > 0
      ORDER BY ts
    ),
    ctx_running AS (
      SELECT
        sched.id AS id,
        sched.ts AS ts,
        sched.dur AS dur,
        sched.utid AS utid
      FROM sched
      JOIN thread USING (utid)
      WHERE thread.upid IS NOT NULL
        AND thread.upid ${privNotIn}
        AND NOT (sched.utid IN (SELECT utid FROM thread WHERE is_idle))
        AND sched.dur > 0
      ORDER BY ts
    ),
    intersected AS (
      SELECT dur, id_1 AS ctx_id
      FROM _interval_intersect!((priv_runnable, ctx_running), ())
    )
    SELECT
      thread.utid AS utid,
      thread.tid AS tid,
      coalesce(thread.name, '[utid ' || thread.utid || ']') AS thread_name,
      process.name AS process_name,
      sum(intersected.dur) AS blocked_ns
    FROM intersected
    JOIN ctx_running ON ctx_running.id = intersected.ctx_id
    JOIN thread ON thread.utid = ctx_running.utid
    LEFT JOIN process USING (upid)
    GROUP BY thread.utid
    HAVING blocked_ns > 0
    ORDER BY blocked_ns DESC
    LIMIT ${limit}
  `);
  const rows: CpuThreadBlameRow[] = [];
  for (
    const it = res.iter({
      utid: NUM,
      tid: NUM_NULL,
      thread_name: STR_NULL,
      process_name: STR_NULL,
      blocked_ns: LONG_NULL,
    });
    it.valid();
    it.next()
  ) {
    rows.push({
      utid: it.utid,
      tid: it.tid,
      threadName: it.thread_name ?? '<unknown>',
      processName: it.process_name,
      blockedNs: it.blocked_ns ?? 0n,
    });
  }
  return rows;
}

export async function loadIdleStates(
  engine: Engine,
): Promise<CpuIdleStateRow[]> {
  // Both the INCLUDE and the SELECT below fail silently on traces without
  // cpuidle counters; falls back to an empty list.
  try {
    await engine.query(
      'INCLUDE PERFETTO MODULE linux.cpu.idle_time_in_state;',
    );
  } catch {
    return [];
  }
  const res = await engine
    .query(
      `
      SELECT
        cpu,
        state,
        sum(total_residency) AS residency_us,
        100.0 * sum(total_residency) / nullif(sum(time_slice), 0)
          AS percentage
      FROM linux_per_cpu_idle_time_in_state_counters
      GROUP BY cpu, state
      ORDER BY cpu, percentage DESC
    `,
    )
    .catch(() => undefined);
  if (res === undefined) return [];
  const rows: CpuIdleStateRow[] = [];
  for (
    const it = res.iter({
      cpu: NUM_NULL,
      state: STR_NULL,
      residency_us: NUM_NULL,
      percentage: NUM_NULL,
    });
    it.valid();
    it.next()
  ) {
    if (it.cpu === null || it.state === null) continue;
    rows.push({
      cpu: it.cpu,
      state: it.state,
      residencyUs: it.residency_us ?? 0,
      percentage: it.percentage ?? 0,
    });
  }
  return rows;
}

export async function loadThreadStates(
  engine: Engine,
  priv: PrivilegedSet,
  limit = 100,
  window?: FocusWindow,
): Promise<ThreadStateRow[]> {
  const upidFilter =
    priv.upids.length > 0 ? `AND th.upid IN (${priv.upids.join(',')})` : '';
  const cd = clipDurExpr(window, 'ts.ts', 'ts.dur');
  const overlap = overlapClause(window, 'ts.ts', 'ts.dur');
  const res = await engine.query(`
    SELECT
      th.utid AS utid,
      th.tid AS tid,
      coalesce(th.name, '[utid ' || th.utid || ']') AS thread_name,
      p.name AS process_name,
      sum(CASE WHEN ts.state = 'Running' THEN ${cd} ELSE 0 END) AS running,
      sum(CASE WHEN ts.state IN ('R', 'R+') THEN ${cd} ELSE 0 END) AS runnable,
      sum(CASE WHEN ts.state = 'D' THEN ${cd} ELSE 0 END) AS uninterruptible,
      sum(CASE WHEN ts.state = 'S' THEN ${cd} ELSE 0 END) AS sleeping,
      sum(CASE WHEN ts.state NOT IN ('Running', 'R', 'R+', 'D', 'S')
               THEN ${cd} ELSE 0 END) AS other,
      sum(CASE WHEN ts.state = 'Running' THEN 1 ELSE 0 END) AS num_run_slices
    FROM thread_state ts
    JOIN thread th USING (utid)
    LEFT JOIN process p USING (upid)
    WHERE ts.dur > 0
      AND NOT (th.utid IN (SELECT utid FROM thread WHERE is_idle))
      ${upidFilter}${overlap}
    GROUP BY th.utid
    ORDER BY running DESC
    LIMIT ${limit}
  `);
  const rows: ThreadStateRow[] = [];
  for (
    const it = res.iter({
      utid: NUM,
      tid: NUM_NULL,
      thread_name: STR_NULL,
      process_name: STR_NULL,
      running: LONG_NULL,
      runnable: LONG_NULL,
      uninterruptible: LONG_NULL,
      sleeping: LONG_NULL,
      other: LONG_NULL,
      num_run_slices: NUM,
    });
    it.valid();
    it.next()
  ) {
    rows.push({
      utid: it.utid,
      tid: it.tid,
      threadName: it.thread_name ?? '<unknown>',
      processName: it.process_name,
      runningNs: it.running ?? 0n,
      runnableNs: it.runnable ?? 0n,
      uninterruptibleNs: it.uninterruptible ?? 0n,
      sleepingNs: it.sleeping ?? 0n,
      otherNs: it.other ?? 0n,
      numRunSlices: it.num_run_slices,
    });
  }
  return rows;
}

export async function loadCoreActivity(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<CoreActivityRow[]> {
  const upidFilter =
    priv.upids.length > 0
      ? `AND sched.utid IN (SELECT utid FROM thread WHERE upid IN (${priv.upids.join(',')}))`
      : '';
  const res = await engine.query(`
    SELECT
      cpu.cpu AS cpu,
      sum(sched.dur) AS busy,
      count(DISTINCT sched.utid) AS threads
    FROM sched
    JOIN cpu USING (ucpu)
    WHERE sched.dur > 0
      AND NOT (sched.utid IN (SELECT utid FROM thread WHERE is_idle))
      ${upidFilter}
    GROUP BY cpu.cpu
    ORDER BY cpu.cpu
  `);
  const rows: CoreActivityRow[] = [];
  for (
    const it = res.iter({cpu: NUM_NULL, busy: LONG_NULL, threads: NUM});
    it.valid();
    it.next()
  ) {
    if (it.cpu === null) continue;
    rows.push({
      cpu: it.cpu,
      busyNs: it.busy ?? 0n,
      threads: it.threads,
    });
  }
  return rows;
}

export interface CoreSeries {
  numBuckets: number;
  // cpu -> busy fraction (0..1) per bucket. Cpus with no slices are absent;
  // buckets with no slices read 0.
  byCpu: Map<number, number[]>;
}

// Per-core utilisation over time: the trace quantised into `numBuckets` equal
// slices, each value the fraction of that slice the core spent non-idle.
// Bucketed by slice start (slices are short relative to a coarse bucket). Drives
// the inline sparklines on the Cores tab — the bridge from a core's aggregate
// busy% to *when* it was busy.
export async function loadCoreSeries(
  engine: Engine,
  priv?: PrivilegedSet,
  numBuckets = 48,
  window?: FocusWindow,
): Promise<CoreSeries> {
  // When focused, the sparkline spans the window; otherwise the whole trace.
  let lo: bigint;
  let hi: bigint;
  if (window !== undefined) {
    lo = window.start;
    hi = window.end;
  } else {
    const bounds = await getSchedBounds(engine);
    if (bounds === undefined) {
      return {numBuckets, byCpu: new Map()};
    }
    lo = bounds.lo;
    hi = bounds.hi;
  }
  const span = hi - lo;
  const width = span / BigInt(numBuckets) > 0n ? span / BigInt(numBuckets) : 1n;
  // Scope to the profiled set when asked, so the sparklines read "your work's
  // utilisation of this core over time" rather than the whole machine's.
  const privClause =
    priv !== undefined && priv.upids.length > 0
      ? `AND sched.utid IN (
           SELECT utid FROM thread WHERE upid IN (${priv.upids.join(',')})
         )`
      : '';
  const res = await engine.query(`
    WITH s AS (
      SELECT
        cpu.cpu AS cpu,
        CAST((sched.ts - ${lo}) / ${width} AS INT) AS bucket,
        sched.dur AS dur
      FROM sched
      JOIN cpu USING (ucpu)
      WHERE sched.dur > 0
        AND NOT (sched.utid IN (SELECT utid FROM thread WHERE is_idle))
        ${privClause}
    )
    SELECT cpu, bucket, sum(dur) AS busy
    FROM s
    WHERE bucket >= 0 AND bucket < ${numBuckets}
    GROUP BY cpu, bucket
  `);
  const widthNum = Number(width);
  const byCpu = new Map<number, number[]>();
  for (
    const it = res.iter({cpu: NUM_NULL, bucket: NUM, busy: LONG_NULL});
    it.valid();
    it.next()
  ) {
    if (it.cpu === null) continue;
    let arr = byCpu.get(it.cpu);
    if (arr === undefined) {
      arr = new Array<number>(numBuckets).fill(0);
      byCpu.set(it.cpu, arr);
    }
    arr[it.bucket] = clamp01(Number(it.busy ?? 0n) / widthNum);
  }
  return {numBuckets, byCpu};
}

// Per-core contention signals from sched: how many distinct threads shared the
// core, and how many times a thread migrated onto it (its previous slice ran on
// a different core). Machine-wide (not privileged-scoped) — this is about the
// core, not your set. Keyed by cpu.
export interface CoreContentionRow {
  threads: number;
  migrationsIn: number;
}

export async function loadCoreContention(
  engine: Engine,
  window?: FocusWindow,
): Promise<Map<number, CoreContentionRow>> {
  const byCpu = new Map<number, CoreContentionRow>();
  const res = await engine
    .query(`
      WITH s AS (
        SELECT
          cpu.cpu AS cpu,
          sched.utid AS utid,
          lag(cpu.cpu) OVER (PARTITION BY sched.utid ORDER BY sched.ts) AS prev_cpu
        FROM sched
        JOIN cpu USING (ucpu)
        WHERE sched.dur > 0
          AND NOT (sched.utid IN (SELECT utid FROM thread WHERE is_idle))${tsRangeClause(window, 'sched.ts')}
      )
      SELECT
        cpu,
        count(DISTINCT utid) AS threads,
        sum(CASE WHEN prev_cpu IS NOT NULL AND prev_cpu != cpu THEN 1 ELSE 0 END)
          AS migrations_in
      FROM s
      GROUP BY cpu
    `)
    .catch(() => undefined);
  if (res === undefined) return byCpu;
  for (
    const it = res.iter({cpu: NUM_NULL, threads: NUM, migrations_in: NUM});
    it.valid();
    it.next()
  ) {
    if (it.cpu === null) continue;
    byCpu.set(it.cpu, {threads: it.threads, migrationsIn: it.migrations_in});
  }
  return byCpu;
}

// Top threads that ran on each core, by their runtime on that specific core.
// Drives the per-core "what ran here" drill-down. Keyed by cpu, each list
// already truncated to `perCpuLimit` and runtime-descending.
export interface CoreThreadRow {
  utid: number;
  tid: number | null;
  threadName: string;
  processName: string | null;
  runtimeNs: bigint;
}

// The per-core drill, focused on the profiled set: `threads` are YOUR top
// threads on the core (or the top threads overall when nothing is profiled);
// `othersNs` is the time everything else spent on the core — a side total, not
// the focus.
export interface CoreThreadDetail {
  threads: CoreThreadRow[];
  othersNs: bigint;
}

export async function loadCoreThreads(
  engine: Engine,
  priv: PrivilegedSet,
  perCpuLimit = 6,
  window?: FocusWindow,
): Promise<Map<number, CoreThreadDetail>> {
  const byCpu = new Map<number, CoreThreadDetail>();
  const clip = clipDurExpr(window, 'sched.ts', 'sched.dur');
  const overlap = overlapClause(window, 'sched.ts', 'sched.dur');
  const res = await engine
    .query(`
      WITH per AS (
        SELECT cpu.cpu AS cpu, sched.utid AS utid, sum(${clip}) AS rt
        FROM sched
        JOIN cpu USING (ucpu)
        WHERE sched.dur > 0
          AND NOT (sched.utid IN (SELECT utid FROM thread WHERE is_idle))${overlap}
        GROUP BY cpu.cpu, sched.utid
      )
      SELECT
        per.cpu AS cpu,
        per.utid AS utid,
        th.upid AS upid,
        th.tid AS tid,
        coalesce(th.name, '[utid ' || th.utid || ']') AS thread_name,
        p.name AS process_name,
        per.rt AS rt
      FROM per
      JOIN thread th USING (utid)
      LEFT JOIN process p ON p.upid = th.upid
      ORDER BY per.cpu, per.rt DESC
    `)
    .catch(() => undefined);
  if (res === undefined) return byCpu;
  const privSet = new Set(priv.upids);
  const hasPriv = priv.upids.length > 0;
  for (
    const it = res.iter({
      cpu: NUM_NULL,
      utid: NUM,
      upid: NUM_NULL,
      tid: NUM_NULL,
      thread_name: STR_NULL,
      process_name: STR_NULL,
      rt: LONG_NULL,
    });
    it.valid();
    it.next()
  ) {
    if (it.cpu === null) continue;
    let d = byCpu.get(it.cpu);
    if (d === undefined) {
      d = {threads: [], othersNs: 0n};
      byCpu.set(it.cpu, d);
    }
    const mine = hasPriv ? it.upid !== null && privSet.has(it.upid) : true;
    if (mine) {
      if (d.threads.length < perCpuLimit) {
        d.threads.push({
          utid: it.utid,
          tid: it.tid,
          threadName: it.thread_name ?? '<unknown>',
          processName: it.process_name,
          runtimeNs: it.rt ?? 0n,
        });
      }
    } else {
      d.othersNs += it.rt ?? 0n;
    }
  }
  return byCpu;
}
