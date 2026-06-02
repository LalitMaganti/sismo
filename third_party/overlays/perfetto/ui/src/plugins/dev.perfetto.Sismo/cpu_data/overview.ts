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
} from '../../../trace_processor/query_result';
import type {PrivilegedSet} from '../privileged_set';
import {privInClause, privNotInClause} from './sql';
import type {
  CpuBlameRow,
  CpuCoreRow,
  CpuIdleStateRow,
  CpuProcessRow,
  CpuThreadBlameRow,
  CpuThreadRow,
} from './cores';
import {
  loadBlame,
  loadIdleStates,
  loadPerCore,
  loadProcessRows,
  loadThreadBlame,
  loadThreadRows,
} from './cores';
import type {MicroarchData} from './microarch';
import {EMPTY_MICROARCH, loadMicroarch} from './microarch';

export interface CpuSummary {
  hasSched: boolean;
  numCpus: number;
  numClusters: number;
  numProcesses: number;
  numThreads: number;
  totalRuntimeNs: bigint | null;
  walltimeNs: bigint | null;
  privilegedRuntimeNs: bigint | null;
  // Wall-clock time during which at least one non-idle thread was running
  // anywhere (union of all running intervals). The denominator for whole-trace
  // parallelism: runtime ÷ this = avg cores busy while anything ran.
  activeWalltimeNs: bigint | null;
  // Same, restricted to privileged threads: time ≥1 privileged thread ran.
  // Null if no priv set. privilegedRuntimeNs ÷ this = avg cores your processes
  // held while they were actually running (idle gaps excluded).
  privilegedActiveWalltimeNs: bigint | null;
  // Same for context (everything not privileged). Null if no priv set.
  contextActiveWalltimeNs: bigint | null;
}

// Time-at-concurrency-level for the scoped set: of the active window (≥1 thread
// running), how much was spent with exactly 1 core busy (effectively serial),
// 2–4, or 5+. The distribution behind the single parallelism number.
export interface ConcurrencyDist {
  hasData: boolean;
  activeNs: bigint;
  serialNs: bigint;
  fewNs: bigint;
  manyNs: bigint;
  maxConcurrency: number;
}

// Work-burst shape for the scoped set. A burst is a maximal interval where ≥1
// thread ran; gaps between bursts are idle. Many short bursts (thrash) keep the
// frequency governor from ramping; long sustained bursts let it. The governor
// ramp window below is the threshold between "sustained" and "short".
const GOVERNOR_RAMP_NS = 30_000_000n; // ~30 ms

interface BurstShape {
  hasData: boolean;
  numBursts: number;
  activeNs: bigint;
  // Active time spent in bursts long enough for the governor to ramp (≥ ramp
  // window) vs too short for it to (< ramp window).
  longBurstNs: bigint;
  shortBurstNs: bigint;
}

export interface CpuDetail {
  summary: CpuSummary;
  perCore: CpuCoreRow[];
  privilegedProcesses: CpuProcessRow[];
  topContextProcesses: CpuProcessRow[];
  privilegedThreads: CpuThreadRow[];
  topContextThreads: CpuThreadRow[];
  microarch: MicroarchData;
  concurrency: ConcurrencyDist;
  bursts: BurstShape;
}

const EMPTY_CONCURRENCY: ConcurrencyDist = {
  hasData: false,
  activeNs: 0n,
  serialNs: 0n,
  fewNs: 0n,
  manyNs: 0n,
  maxConcurrency: 0,
};

const EMPTY_BURSTS: BurstShape = {
  hasData: false,
  numBursts: 0,
  activeNs: 0n,
  longBurstNs: 0n,
  shortBurstNs: 0n,
};

export async function loadCpuSummary(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<CpuSummary> {
  await engine.query('INCLUDE PERFETTO MODULE linux.cpu.utilization.system;');

  const hasSchedRes = await engine.query(
    `SELECT (SELECT count() FROM sched LIMIT 1) > 0 AS has_sched`,
  );
  const hasSched = hasSchedRes.firstRow({has_sched: NUM}).has_sched === 1;

  if (!hasSched) {
    return {
      hasSched: false,
      numCpus: 0,
      numClusters: 0,
      numProcesses: 0,
      numThreads: 0,
      totalRuntimeNs: null,
      walltimeNs: null,
      privilegedRuntimeNs: null,
      activeWalltimeNs: null,
      privilegedActiveWalltimeNs: null,
      contextActiveWalltimeNs: null,
    };
  }

  const privIn = privInClause(priv);

  const topo = await engine.query(`
    SELECT
      (SELECT count(*) FROM cpu) AS num_cpus,
      (SELECT count(DISTINCT cluster_id) FROM cpu) AS num_clusters,
      (SELECT count(DISTINCT thread.upid)
         FROM sched
         JOIN thread USING (utid)
         WHERE thread.upid IS NOT NULL) AS num_processes,
      (SELECT count(DISTINCT utid) FROM sched
         WHERE NOT (utid IN (SELECT utid FROM thread WHERE is_idle))) AS num_threads,
      (SELECT max(ts) - min(ts) FROM sched) AS walltime_ns,
      (SELECT sum(dur) FROM sched
         WHERE dur > 0
           AND NOT (utid IN (SELECT utid FROM thread WHERE is_idle))
      ) AS total_runtime_ns,
      (SELECT sum(sched.dur)
         FROM sched JOIN thread USING (utid)
         WHERE thread.upid ${privIn}
           AND sched.dur > 0
           AND NOT (utid IN (SELECT utid FROM thread WHERE is_idle))
      ) AS privileged_runtime_ns
  `);
  const topoRow = topo.firstRow({
    num_cpus: NUM,
    num_clusters: NUM,
    num_processes: NUM,
    num_threads: NUM,
    walltime_ns: LONG_NULL,
    total_runtime_ns: LONG_NULL,
    privileged_runtime_ns: LONG_NULL,
  });

  const numCpus = topoRow.num_cpus;
  const totalRuntime = topoRow.total_runtime_ns ?? null;
  const walltime = topoRow.walltime_ns ?? null;

  // Active walltime = union of running intervals. Whole-trace always; per-set
  // only when there's a privileged set to split by. These are the parallelism
  // denominators: runtime ÷ active = avg cores busy *while anything ran*.
  await engine.query('INCLUDE PERFETTO MODULE intervals.overlap;');
  const activeWalltimeNs = await loadActiveWalltime(engine, '');
  let privilegedActiveWalltimeNs: bigint | null = null;
  let contextActiveWalltimeNs: bigint | null = null;
  if (priv.upids.length > 0) {
    privilegedActiveWalltimeNs = await loadActiveWalltime(
      engine,
      `AND thread.upid ${privIn}`,
    );
    // NULL upids (kernel threads) belong to context, so guard the NOT IN.
    contextActiveWalltimeNs = await loadActiveWalltime(
      engine,
      `AND (thread.upid IS NULL OR thread.upid ${privNotInClause(priv)})`,
    );
  }

  return {
    hasSched: true,
    numCpus,
    numClusters: topoRow.num_clusters,
    numProcesses: topoRow.num_processes,
    numThreads: topoRow.num_threads,
    totalRuntimeNs: totalRuntime,
    walltimeNs: walltime,
    privilegedRuntimeNs:
      priv.upids.length > 0 ? (topoRow.privileged_runtime_ns ?? 0n) : null,
    activeWalltimeNs,
    privilegedActiveWalltimeNs,
    contextActiveWalltimeNs,
  };
}

// Wall-clock time during which at least one matching sched slice was running,
// i.e. the union (not sum) of running intervals. `schedFilter` is appended to
// the WHERE on `sched JOIN thread` to scope to a set (privileged / context);
// empty for the whole trace. intervals_overlap_count gives a (ts, depth)
// step function; we sum the spans where depth ≥ 1.
async function loadActiveWalltime(
  engine: Engine,
  schedFilter: string,
): Promise<bigint | null> {
  const res = await engine.query(`
    WITH running AS (
      SELECT sched.ts AS ts, sched.dur AS dur
      FROM sched
      JOIN thread USING (utid)
      WHERE sched.dur > 0
        AND NOT (sched.utid IN (SELECT utid FROM thread WHERE is_idle))
        ${schedFilter}
    ),
    depth AS (
      SELECT ts, value FROM intervals_overlap_count!(running, ts, dur)
    ),
    spans AS (
      SELECT ts, value, lead(ts) OVER (ORDER BY ts) AS next_ts FROM depth
    )
    SELECT sum(next_ts - ts) AS active_ns
    FROM spans
    WHERE value >= 1 AND next_ts IS NOT NULL
  `);
  return res.firstRow({active_ns: LONG_NULL}).active_ns ?? null;
}

export async function loadCpuDetail(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<CpuDetail> {
  const summary = await loadCpuSummary(engine, priv);
  if (!summary.hasSched) {
    return {
      summary,
      perCore: [],
      privilegedProcesses: [],
      topContextProcesses: [],
      privilegedThreads: [],
      topContextThreads: [],
      microarch: EMPTY_MICROARCH,
      concurrency: EMPTY_CONCURRENCY,
      bursts: EMPTY_BURSTS,
    };
  }

  await engine.query('INCLUDE PERFETTO MODULE linux.cpu.utilization.process;');
  await engine.query('INCLUDE PERFETTO MODULE linux.cpu.utilization.thread;');

  const perCore = await loadPerCore(engine, priv);
  const privilegedProcesses = await loadProcessRows(engine, priv, 'privileged');
  const topContextProcesses = await loadProcessRows(engine, priv, 'context', 20);
  const privilegedThreads = await loadThreadRows(engine, priv, 'privileged');
  const topContextThreads = await loadThreadRows(engine, priv, 'context', 20);
  const microarch = await loadMicroarch(engine, priv);
  const concurrency = await loadConcurrencyDistribution(engine, priv);
  const bursts = await loadBurstShape(engine, priv);
  return {
    summary,
    perCore,
    privilegedProcesses,
    topContextProcesses,
    privilegedThreads,
    topContextThreads,
    microarch,
    concurrency,
    bursts,
  };
}

// Coalesces the scoped running intervals into bursts (maximal ≥1-running runs)
// and measures their shape. Builds the same overlap step function as
// loadConcurrencyDistribution, then islands the busy spans: a busy span starts
// a new burst when it doesn't abut the previous one (i.e. an idle gap sat
// between them).
async function loadBurstShape(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<BurstShape> {
  const schedFilter =
    priv.upids.length > 0 ? `AND thread.upid ${privInClause(priv)}` : '';
  await engine.query('INCLUDE PERFETTO MODULE intervals.overlap;');
  const res = await engine.query(`
    WITH running AS (
      SELECT sched.ts AS ts, sched.dur AS dur
      FROM sched
      JOIN thread USING (utid)
      WHERE sched.dur > 0
        AND NOT (sched.utid IN (SELECT utid FROM thread WHERE is_idle))
        ${schedFilter}
    ),
    spans AS (
      SELECT ts, value, lead(ts) OVER (ORDER BY ts) AS next_ts
      FROM intervals_overlap_count!(running, ts, dur)
    ),
    busy AS (
      SELECT ts, next_ts FROM spans WHERE value >= 1 AND next_ts IS NOT NULL
    ),
    flagged AS (
      SELECT
        ts,
        next_ts,
        CASE WHEN ts = lag(next_ts) OVER (ORDER BY ts) THEN 0 ELSE 1 END
          AS is_start
      FROM busy
    ),
    grouped AS (
      SELECT ts, next_ts, sum(is_start) OVER (ORDER BY ts) AS burst_id
      FROM flagged
    ),
    bursts AS (
      SELECT max(next_ts) - min(ts) AS dur FROM grouped GROUP BY burst_id
    )
    SELECT
      count(*) AS num_bursts,
      sum(dur) AS active,
      sum(CASE WHEN dur >= ${GOVERNOR_RAMP_NS} THEN dur ELSE 0 END) AS long_ns,
      sum(CASE WHEN dur < ${GOVERNOR_RAMP_NS} THEN dur ELSE 0 END) AS short_ns
    FROM bursts
  `);
  const r = res.firstRow({
    num_bursts: NUM,
    active: LONG_NULL,
    long_ns: LONG_NULL,
    short_ns: LONG_NULL,
  });
  return {
    hasData: r.num_bursts > 0,
    numBursts: r.num_bursts,
    activeNs: r.active ?? 0n,
    longBurstNs: r.long_ns ?? 0n,
    shortBurstNs: r.short_ns ?? 0n,
  };
}

// Buckets the active window by how many of the scoped threads were running at
// once. intervals_overlap_count gives a (ts, depth) step function over the
// union of running intervals; weight each step by its span and bucket by depth.
// Mirrors loadActiveWalltime's running-set construction.
async function loadConcurrencyDistribution(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<ConcurrencyDist> {
  const schedFilter =
    priv.upids.length > 0 ? `AND thread.upid ${privInClause(priv)}` : '';
  await engine.query('INCLUDE PERFETTO MODULE intervals.overlap;');
  const res = await engine.query(`
    WITH running AS (
      SELECT sched.ts AS ts, sched.dur AS dur
      FROM sched
      JOIN thread USING (utid)
      WHERE sched.dur > 0
        AND NOT (sched.utid IN (SELECT utid FROM thread WHERE is_idle))
        ${schedFilter}
    ),
    depth AS (
      SELECT ts, value FROM intervals_overlap_count!(running, ts, dur)
    ),
    spans AS (
      SELECT ts, value, lead(ts) OVER (ORDER BY ts) AS next_ts FROM depth
    )
    SELECT
      sum(CASE WHEN value >= 1 THEN next_ts - ts ELSE 0 END) AS active,
      sum(CASE WHEN value = 1 THEN next_ts - ts ELSE 0 END) AS serial,
      sum(CASE WHEN value BETWEEN 2 AND 4 THEN next_ts - ts ELSE 0 END) AS few,
      sum(CASE WHEN value >= 5 THEN next_ts - ts ELSE 0 END) AS many,
      max(value) AS max_conc
    FROM spans
    WHERE next_ts IS NOT NULL
  `);
  const r = res.firstRow({
    active: LONG_NULL,
    serial: LONG_NULL,
    few: LONG_NULL,
    many: LONG_NULL,
    max_conc: NUM_NULL,
  });
  const active = r.active ?? 0n;
  return {
    hasData: active > 0n,
    activeNs: active,
    serialNs: r.serial ?? 0n,
    fewNs: r.few ?? 0n,
    manyNs: r.many ?? 0n,
    maxConcurrency: r.max_conc ?? 0,
  };
}

export interface LatencyDetail {
  hasSched: boolean;
  hasPriv: boolean;
  // Per-CPU cpuidle residency. Lives on the latency page because deep C-states
  // have higher exit latency — a wakeup-latency signal, not a CPU-usage one.
  idleStates: CpuIdleStateRow[];
  // Other processes/threads that held the CPU while one of your threads was
  // runnable-but-not-running — i.e. what your scheduling latency is owed to.
  blame: CpuBlameRow[];
  threadBlame: CpuThreadBlameRow[];
}

export async function loadLatencyDetail(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<LatencyDetail> {
  const hasSchedRes = await engine.query(
    `SELECT (SELECT count() FROM sched LIMIT 1) > 0 AS has_sched`,
  );
  const hasSched = hasSchedRes.firstRow({has_sched: NUM}).has_sched === 1;
  const hasPriv = priv.upids.length > 0;
  if (!hasSched) {
    return {hasSched: false, hasPriv, blame: [], threadBlame: [], idleStates: []};
  }
  const blame = await loadBlame(engine, priv, 20);
  const threadBlame = await loadThreadBlame(engine, priv, 20);
  const idleStates = await loadIdleStates(engine);
  return {hasSched: true, hasPriv, blame, threadBlame, idleStates};
}
