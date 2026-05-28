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

import type {Engine} from '../../trace_processor/engine';
import {
  LONG,
  LONG_NULL,
  NUM,
  NUM_NULL,
  STR_NULL,
} from '../../trace_processor/query_result';
import type {PrivilegedSet} from './privileged_set';

export interface CpuSummary {
  hasSched: boolean;
  numCpus: number;
  numClusters: number;
  numProcesses: number;
  numThreads: number;
  totalRuntimeNs: bigint | null;
  walltimeNs: bigint | null;
  avgUtilization: number | null;
  megacycles: bigint | null;
  minFreqKhz: bigint | null;
  maxFreqKhz: bigint | null;
  avgFreqKhz: bigint | null;
  privilegedRuntimeNs: bigint | null;
  privilegedMegacycles: bigint | null;
  // Cycle-budget framing: cycles the SoC *could* have delivered across all
  // cores at their peak observed frequency for the trace walltime. Used as
  // the denominator for bandwidth utilization. Null if no cpufreq data.
  peakMegacycles: number | null;
  // Total cycles delivered / peak cycles available. 100% means every core
  // ran at peak freq for the entire trace.
  bandwidthUtilization: number | null;
  // Avg cores in use over walltime (totalRuntimeNs / walltimeNs). 1.0 means
  // a single-thread workload kept one core busy continuously; numCpus means
  // every core was saturated.
  effectiveConcurrency: number | null;
  // Same, restricted to privileged processes. Null if no priv set.
  privilegedConcurrency: number | null;
  // Count of distinct utids belonging to privileged processes that ran at
  // least once. The "threads you actually used" denominator for the
  // parallelism question.
  numPrivilegedThreads: number | null;
}

export interface CpuCoreRow {
  cpu: number;
  clusterId: number | null;
  // Relative core capacity (ARM DynamIQ / Apple AMP: bigger = performance
  // core). Null on uniform x86. Used to label clusters P/E.
  capacity: number | null;
  processor: string | null;
  runtimeNs: bigint | null;
  privilegedRuntimeNs: bigint | null;
  megacycles: bigint | null;
  minFreqKhz: bigint | null;
  maxFreqKhz: bigint | null;
  avgFreqKhz: bigint | null;
}

export interface CpuProcessRow {
  upid: number;
  pid: number | null;
  name: string;
  runtimeNs: bigint;
  megacycles: bigint | null;
}

export interface CpuThreadRow {
  utid: number;
  tid: number | null;
  threadName: string;
  processName: string | null;
  runtimeNs: bigint;
  megacycles: bigint | null;
}

export interface CpuIdleStateRow {
  cpu: number;
  state: string;
  residencyUs: number;
  percentage: number;
}

export interface HotSymbolRow {
  name: string;
  mappingName: string | null;
  samples: number;
  share: number;
}

export interface HotMappingRow {
  name: string;
  samples: number;
  share: number;
}

export interface MicroarchData {
  // True if perf_sample has any rows (with or without symbols). Lets the UI
  // distinguish "no sampler ran" from "sampler ran but symbols are missing".
  hasSamples: boolean;
  // True if at least one sample's leaf frame has a non-null name. If false
  // we have raw samples but symbolisation didn't resolve anything — likely
  // missing debuginfo / dSYMs.
  hasSymbols: boolean;
  // Total samples used as the denominator for `share` below. When the
  // privileged set is non-empty this counts only privileged threads.
  totalSamples: number;
  hotSymbols: HotSymbolRow[];
  hotMappings: HotMappingRow[];
}

// Detail-pane view rows. These power the whole-trace detail tab (detail_tab.ts)
// and are scoped to the privileged set when present, else the whole trace.

export interface HeaviestFunctionRow {
  name: string;
  samples: number;
  share: number;
}

export interface SampleListRow {
  ts: bigint;
  utid: number;
  tid: number | null;
  threadName: string;
  leaf: string;
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

export interface CpuDetail {
  summary: CpuSummary;
  perCore: CpuCoreRow[];
  privilegedProcesses: CpuProcessRow[];
  topContextProcesses: CpuProcessRow[];
  privilegedThreads: CpuThreadRow[];
  topContextThreads: CpuThreadRow[];
  microarch: MicroarchData;
}

// `IN (-1)` stands in for the unrepresentable `IN ()` so SQL stays valid
// when the privileged set is empty.
function privInClause(priv: PrivilegedSet): string {
  if (priv.upids.length === 0) return 'IN (-1)';
  return `IN (${priv.upids.join(',')})`;
}

function privNotInClause(priv: PrivilegedSet): string {
  if (priv.upids.length === 0) return 'NOT IN (-1)';
  return `NOT IN (${priv.upids.join(',')})`;
}

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
      avgUtilization: null,
      megacycles: null,
      minFreqKhz: null,
      maxFreqKhz: null,
      avgFreqKhz: null,
      privilegedRuntimeNs: null,
      privilegedMegacycles: null,
      peakMegacycles: null,
      bandwidthUtilization: null,
      effectiveConcurrency: null,
      privilegedConcurrency: null,
      numPrivilegedThreads: null,
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

  // cpu_cycles requires cpufreq data; the stdlib module load can also fail
  // on exotic traces. Both cases land in the catch and leave the fields null.
  let megacycles: bigint | null = null;
  let minFreq: bigint | null = null;
  let maxFreq: bigint | null = null;
  let avgFreq: bigint | null = null;
  // Per-CPU peak-frequency sum, in kHz. Used for the cycle-budget denominator:
  // if every covered core had run at its observed peak for the entire trace,
  // sumPeakFreqKhz × walltime would be the total cycles delivered.
  let sumPeakFreqKhz: bigint | null = null;
  try {
    const cyc = await engine.query(`
      SELECT
        megacycles,
        min_freq,
        max_freq,
        avg_freq
      FROM cpu_cycles
    `);
    if (cyc.numRows() > 0) {
      const r = cyc.firstRow({
        megacycles: LONG_NULL,
        min_freq: LONG_NULL,
        max_freq: LONG_NULL,
        avg_freq: LONG_NULL,
      });
      megacycles = r.megacycles ?? null;
      minFreq = r.min_freq ?? null;
      maxFreq = r.max_freq ?? null;
      avgFreq = r.avg_freq ?? null;
    }
    const peak = await engine.query(`
      SELECT sum(max_freq) AS sum_peak_freq_khz FROM cpu_cycles_per_cpu
    `);
    if (peak.numRows() > 0) {
      sumPeakFreqKhz =
        peak.firstRow({sum_peak_freq_khz: LONG_NULL}).sum_peak_freq_khz ?? null;
    }
  } catch {}

  let privilegedMegacycles: bigint | null = null;
  if (priv.upids.length > 0 && megacycles !== null) {
    try {
      await engine.query(
        'INCLUDE PERFETTO MODULE linux.cpu.utilization.process;',
      );
      const r = await engine.query(`
        SELECT sum(megacycles) AS mcyc
        FROM cpu_cycles_per_process
        WHERE upid ${privIn}
      `);
      privilegedMegacycles = r.firstRow({mcyc: LONG_NULL}).mcyc ?? 0n;
    } catch {}
  }

  const numCpus = topoRow.num_cpus;
  const totalRuntime = topoRow.total_runtime_ns ?? null;
  const walltime = topoRow.walltime_ns ?? null;
  let avgUtilization: number | null = null;
  if (totalRuntime !== null && walltime !== null && walltime > 0n && numCpus > 0) {
    avgUtilization = Number(totalRuntime) / (Number(walltime) * numCpus);
  }

  // 1 kHz × 1 ns = 1e-6 cycles, divided by 1e6 = megacycles. So
  // sum_peak_khz × walltime_ns × 1e-12 = peak megacycles available.
  let peakMegacycles: number | null = null;
  let bandwidthUtilization: number | null = null;
  if (sumPeakFreqKhz !== null && walltime !== null && walltime > 0n) {
    peakMegacycles = (Number(sumPeakFreqKhz) * Number(walltime)) / 1e12;
    if (peakMegacycles > 0 && megacycles !== null) {
      bandwidthUtilization = Number(megacycles) / peakMegacycles;
    }
  }

  // Avg cores in use over walltime. Same numerator as utilization, but
  // divided by walltime instead of (walltime × numCpus) — so the unit is
  // "cores", not a fraction. More legible at a glance than utilization for
  // a multi-core SoC.
  let effectiveConcurrency: number | null = null;
  if (totalRuntime !== null && walltime !== null && walltime > 0n) {
    effectiveConcurrency = Number(totalRuntime) / Number(walltime);
  }

  let privilegedConcurrency: number | null = null;
  let numPrivilegedThreads: number | null = null;
  if (priv.upids.length > 0) {
    const privRuntime = topoRow.privileged_runtime_ns ?? 0n;
    if (walltime !== null && walltime > 0n) {
      privilegedConcurrency = Number(privRuntime) / Number(walltime);
    }
    // Only count threads that actually ran. A process can have hundreds of
    // declared threads but only a handful that did any work; the
    // parallelism question is about the latter.
    const tcountRes = await engine.query(`
      SELECT count(DISTINCT sched.utid) AS n
      FROM sched
      JOIN thread USING (utid)
      WHERE thread.upid ${privIn}
        AND sched.dur > 0
        AND NOT (sched.utid IN (SELECT utid FROM thread WHERE is_idle))
    `);
    numPrivilegedThreads = tcountRes.firstRow({n: NUM}).n;
  }

  return {
    hasSched: true,
    numCpus,
    numClusters: topoRow.num_clusters,
    numProcesses: topoRow.num_processes,
    numThreads: topoRow.num_threads,
    totalRuntimeNs: totalRuntime,
    walltimeNs: walltime,
    avgUtilization,
    megacycles,
    minFreqKhz: minFreq,
    maxFreqKhz: maxFreq,
    avgFreqKhz: avgFreq,
    privilegedRuntimeNs:
      priv.upids.length > 0 ? (topoRow.privileged_runtime_ns ?? 0n) : null,
    privilegedMegacycles,
    peakMegacycles,
    bandwidthUtilization,
    effectiveConcurrency,
    privilegedConcurrency,
    numPrivilegedThreads,
  };
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
  return {
    summary,
    perCore,
    privilegedProcesses,
    topContextProcesses,
    privilegedThreads,
    topContextThreads,
    microarch,
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

// Empty microarch result used as a fallback when perf_sample is missing.
const EMPTY_MICROARCH: MicroarchData = {
  hasSamples: false,
  hasSymbols: false,
  totalSamples: 0,
  hotSymbols: [],
  hotMappings: [],
};

async function loadMicroarch(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<MicroarchData> {
  // perf_sample is only populated when a sampling data source ran (linux.perf
  // on Linux, sismo's mach_sampler on macOS). Missing table or empty table
  // both land in EMPTY_MICROARCH so the UI can render a "no samples" state.
  const hasTable = await engine
    .query(
      `SELECT name FROM sqlite_master WHERE name = 'perf_sample' LIMIT 1`,
    )
    .catch(() => undefined);
  if (hasTable === undefined || hasTable.numRows() === 0) {
    return EMPTY_MICROARCH;
  }

  // Privileged-scope clause used by every microarch query below.
  const scope =
    priv.upids.length > 0
      ? `AND s.utid IN (
           SELECT utid FROM thread WHERE upid IN (${priv.upids.join(',')})
         )`
      : '';

  const totalsRes = await engine.query(`
    SELECT
      (SELECT count() FROM perf_sample s
        WHERE s.callsite_id IS NOT NULL ${scope}
      ) AS total_with_stack,
      (SELECT count() FROM perf_sample s
        WHERE s.callsite_id IS NOT NULL ${scope}
          AND s.callsite_id IN (
            SELECT c.id
            FROM stack_profile_callsite c
            JOIN stack_profile_frame f ON f.id = c.frame_id
            WHERE f.name IS NOT NULL AND f.name != ''
          )
      ) AS total_with_symbol
  `);
  const totalsRow = totalsRes.firstRow({
    total_with_stack: NUM,
    total_with_symbol: NUM,
  });
  const totalSamples = totalsRow.total_with_stack;
  if (totalSamples === 0) return EMPTY_MICROARCH;
  const hasSymbols = totalsRow.total_with_symbol > 0;

  if (!hasSymbols) {
    return {
      hasSamples: true,
      hasSymbols: false,
      totalSamples,
      hotSymbols: [],
      hotMappings: [],
    };
  }

  // NULLIF folds empty-string frame names (returned for addresses that didn't
  // resolve to a symbol) into NULL so they coalesce to a clear placeholder.
  const hotSymRes = await engine.query(`
    SELECT
      coalesce(NULLIF(spf.name, ''), '[unsymbolised]') AS name,
      spm.name AS mapping_name,
      count(*) AS samples
    FROM perf_sample s
    JOIN stack_profile_callsite c ON c.id = s.callsite_id
    JOIN stack_profile_frame spf ON spf.id = c.frame_id
    LEFT JOIN stack_profile_mapping spm ON spm.id = spf.mapping
    WHERE s.callsite_id IS NOT NULL ${scope}
    GROUP BY coalesce(NULLIF(spf.name, ''), '[unsymbolised]'), spm.name
    ORDER BY samples DESC
    LIMIT 20
  `);
  const hotSymbols: HotSymbolRow[] = [];
  for (
    const it = hotSymRes.iter({
      name: STR_NULL,
      mapping_name: STR_NULL,
      samples: NUM,
    });
    it.valid();
    it.next()
  ) {
    hotSymbols.push({
      name: it.name ?? '[unknown]',
      mappingName: it.mapping_name,
      samples: it.samples,
      share: it.samples / totalSamples,
    });
  }

  const hotMapRes = await engine.query(`
    SELECT
      coalesce(spm.name, '[unknown mapping]') AS name,
      count(*) AS samples
    FROM perf_sample s
    JOIN stack_profile_callsite c ON c.id = s.callsite_id
    JOIN stack_profile_frame spf ON spf.id = c.frame_id
    LEFT JOIN stack_profile_mapping spm ON spm.id = spf.mapping
    WHERE s.callsite_id IS NOT NULL ${scope}
    GROUP BY spm.name
    ORDER BY samples DESC
    LIMIT 20
  `);
  const hotMappings: HotMappingRow[] = [];
  for (
    const it = hotMapRes.iter({
      name: STR_NULL,
      samples: NUM,
    });
    it.valid();
    it.next()
  ) {
    hotMappings.push({
      name: it.name ?? '[unknown mapping]',
      samples: it.samples,
      share: it.samples / totalSamples,
    });
  }

  return {
    hasSamples: true,
    hasSymbols: true,
    totalSamples,
    hotSymbols,
    hotMappings,
  };
}

async function loadPerCore(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<CpuCoreRow[]> {
  // Aggregate by `ucpu` not `cpu` so multi-machine traces don't collapse CPUs
  // that share a number across machines.
  const privIn = privInClause(priv);
  const res = await engine.query(`
    WITH sched_per_cpu AS (
      SELECT
        ucpu,
        sum(dur) AS runtime
      FROM sched
      WHERE dur > 0
        AND NOT (utid IN (SELECT utid FROM thread WHERE is_idle))
      GROUP BY ucpu
    ),
    priv_per_cpu AS (
      SELECT
        sched.ucpu AS ucpu,
        sum(sched.dur) AS runtime
      FROM sched
      JOIN thread USING (utid)
      WHERE thread.upid ${privIn}
        AND sched.dur > 0
        AND NOT (sched.utid IN (SELECT utid FROM thread WHERE is_idle))
      GROUP BY sched.ucpu
    )
    SELECT
      cpu.cpu AS cpu,
      cpu.cluster_id AS cluster_id,
      cpu.capacity AS capacity,
      cpu.processor AS processor,
      sched_per_cpu.runtime AS runtime_ns,
      priv_per_cpu.runtime AS priv_runtime_ns,
      cyc.megacycles AS megacycles,
      cyc.min_freq AS min_freq,
      cyc.max_freq AS max_freq,
      cyc.avg_freq AS avg_freq
    FROM cpu
    LEFT JOIN sched_per_cpu USING (ucpu)
    LEFT JOIN priv_per_cpu USING (ucpu)
    LEFT JOIN cpu_cycles_per_cpu cyc USING (ucpu)
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
      megacycles: LONG_NULL,
      min_freq: LONG_NULL,
      max_freq: LONG_NULL,
      avg_freq: LONG_NULL,
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
      megacycles: it.megacycles ?? null,
      minFreqKhz: it.min_freq ?? null,
      maxFreqKhz: it.max_freq ?? null,
      avgFreqKhz: it.avg_freq ?? null,
    });
  }
  return rows;
}

async function loadProcessRows(
  engine: Engine,
  priv: PrivilegedSet,
  kind: 'privileged' | 'context',
  limit?: number,
): Promise<CpuProcessRow[]> {
  if (kind === 'privileged' && priv.upids.length === 0) return [];
  const upidClause =
    kind === 'privileged' ? privInClause(priv) : privNotInClause(priv);
  const limitClause = limit !== undefined ? `LIMIT ${limit}` : '';
  const res = await engine.query(`
    WITH per_process AS (
      SELECT
        thread.upid AS upid,
        sum(sched.dur) AS runtime_ns
      FROM sched
      JOIN thread USING (utid)
      WHERE thread.upid IS NOT NULL
        AND thread.upid ${upidClause}
        AND sched.dur > 0
        AND NOT (utid IN (SELECT utid FROM thread WHERE is_idle))
      GROUP BY thread.upid
    )
    SELECT
      per_process.upid AS upid,
      process.pid AS pid,
      coalesce(process.name, '[upid ' || per_process.upid || ']') AS name,
      per_process.runtime_ns AS runtime_ns,
      cyc.megacycles AS megacycles
    FROM per_process
    JOIN process USING (upid)
    LEFT JOIN cpu_cycles_per_process cyc USING (upid)
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
      megacycles: LONG_NULL,
    });
    it.valid();
    it.next()
  ) {
    rows.push({
      upid: it.upid,
      pid: it.pid,
      name: it.name ?? '<unknown>',
      runtimeNs: it.runtime_ns ?? 0n,
      megacycles: it.megacycles ?? null,
    });
  }
  return rows;
}

async function loadThreadRows(
  engine: Engine,
  priv: PrivilegedSet,
  kind: 'privileged' | 'context',
  limit?: number,
): Promise<CpuThreadRow[]> {
  if (kind === 'privileged' && priv.upids.length === 0) return [];
  const upidClause =
    kind === 'privileged' ? privInClause(priv) : privNotInClause(priv);
  const limitClause = limit !== undefined ? `LIMIT ${limit}` : '';
  const res = await engine.query(`
    WITH per_thread AS (
      SELECT
        sched.utid AS utid,
        sum(sched.dur) AS runtime_ns
      FROM sched
      JOIN thread USING (utid)
      WHERE thread.upid IS NOT NULL
        AND thread.upid ${upidClause}
        AND sched.dur > 0
        AND NOT (sched.utid IN (SELECT utid FROM thread WHERE is_idle))
      GROUP BY sched.utid
    )
    SELECT
      thread.utid AS utid,
      thread.tid AS tid,
      coalesce(thread.name, '[utid ' || thread.utid || ']') AS thread_name,
      process.name AS process_name,
      per_thread.runtime_ns AS runtime_ns,
      cyc.megacycles AS megacycles
    FROM per_thread
    JOIN thread USING (utid)
    LEFT JOIN process USING (upid)
    LEFT JOIN cpu_cycles_per_thread cyc USING (utid)
    ORDER BY runtime_ns DESC
    ${limitClause}
  `);
  const rows: CpuThreadRow[] = [];
  for (
    const it = res.iter({
      utid: NUM,
      tid: NUM_NULL,
      thread_name: STR_NULL,
      process_name: STR_NULL,
      runtime_ns: LONG_NULL,
      megacycles: LONG_NULL,
    });
    it.valid();
    it.next()
  ) {
    rows.push({
      utid: it.utid,
      tid: it.tid,
      threadName: it.thread_name ?? '<unknown>',
      processName: it.process_name,
      runtimeNs: it.runtime_ns ?? 0n,
      megacycles: it.megacycles ?? null,
    });
  }
  return rows;
}

// No same-CPU partition: trace_processor only populates thread_state.cpu for
// Running rows (NULL for R/R+), so we can't tell which runqueue our thread
// was on. On multi-core, if a thread is runnable-not-running then all cores
// are busy — so every concurrent context-running process is collectively
// keeping us off the CPU. Sum-overlap captures that.
async function loadBlame(
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

async function loadThreadBlame(
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

async function loadIdleStates(engine: Engine): Promise<CpuIdleStateRow[]> {
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

// Sample-scope predicate for perf_sample queries: restrict to threads of the
// privileged processes when set, else no restriction (whole trace).
function sampleScopePredicate(priv: PrivilegedSet): string {
  if (priv.upids.length === 0) return '';
  return `AND s.utid IN (
    SELECT utid FROM thread WHERE upid IN (${priv.upids.join(',')})
  )`;
}

export async function loadHeaviestFunctions(
  engine: Engine,
  priv: PrivilegedSet,
  limit = 100,
): Promise<HeaviestFunctionRow[]> {
  const scope = sampleScopePredicate(priv);
  // Self time: each sample's leaf frame (the callsite frame) is the function
  // executing at the sample instant. Group by symbol name, summing across the
  // mappings it appears in — the flat self-time view.
  const totalRes = await engine.query(`
    SELECT count() AS n FROM perf_sample s
    WHERE s.callsite_id IS NOT NULL ${scope}
  `);
  const total = totalRes.firstRow({n: NUM}).n;
  if (total === 0) return [];

  const res = await engine.query(`
    SELECT
      coalesce(NULLIF(spf.name, ''), '[unsymbolised]') AS name,
      count(*) AS samples
    FROM perf_sample s
    JOIN stack_profile_callsite c ON c.id = s.callsite_id
    JOIN stack_profile_frame spf ON spf.id = c.frame_id
    WHERE s.callsite_id IS NOT NULL ${scope}
    GROUP BY coalesce(NULLIF(spf.name, ''), '[unsymbolised]')
    ORDER BY samples DESC
    LIMIT ${limit}
  `);
  const rows: HeaviestFunctionRow[] = [];
  for (
    const it = res.iter({name: STR_NULL, samples: NUM});
    it.valid();
    it.next()
  ) {
    rows.push({
      name: it.name ?? '[unsymbolised]',
      samples: it.samples,
      share: it.samples / total,
    });
  }
  return rows;
}

export async function loadSampleList(
  engine: Engine,
  priv: PrivilegedSet,
  limit = 500,
): Promise<SampleListRow[]> {
  const scope = sampleScopePredicate(priv);
  const res = await engine.query(`
    SELECT
      s.ts AS ts,
      s.utid AS utid,
      th.tid AS tid,
      coalesce(th.name, '[utid ' || s.utid || ']') AS thread_name,
      coalesce(NULLIF(spf.name, ''), '[unsymbolised]') AS leaf
    FROM perf_sample s
    JOIN thread th USING (utid)
    JOIN stack_profile_callsite c ON c.id = s.callsite_id
    JOIN stack_profile_frame spf ON spf.id = c.frame_id
    WHERE s.callsite_id IS NOT NULL ${scope}
    ORDER BY s.ts
    LIMIT ${limit}
  `);
  const rows: SampleListRow[] = [];
  for (
    const it = res.iter({
      ts: LONG,
      utid: NUM,
      tid: NUM_NULL,
      thread_name: STR_NULL,
      leaf: STR_NULL,
    });
    it.valid();
    it.next()
  ) {
    rows.push({
      ts: it.ts,
      utid: it.utid,
      tid: it.tid,
      threadName: it.thread_name ?? '<unknown>',
      leaf: it.leaf ?? '[unsymbolised]',
    });
  }
  return rows;
}

export async function loadThreadStates(
  engine: Engine,
  priv: PrivilegedSet,
  limit = 100,
): Promise<ThreadStateRow[]> {
  const upidFilter =
    priv.upids.length > 0 ? `AND th.upid IN (${priv.upids.join(',')})` : '';
  const res = await engine.query(`
    SELECT
      th.utid AS utid,
      th.tid AS tid,
      coalesce(th.name, '[utid ' || th.utid || ']') AS thread_name,
      p.name AS process_name,
      sum(CASE WHEN ts.state = 'Running' THEN ts.dur ELSE 0 END) AS running,
      sum(CASE WHEN ts.state IN ('R', 'R+') THEN ts.dur ELSE 0 END) AS runnable,
      sum(CASE WHEN ts.state = 'D' THEN ts.dur ELSE 0 END) AS uninterruptible,
      sum(CASE WHEN ts.state = 'S' THEN ts.dur ELSE 0 END) AS sleeping,
      sum(CASE WHEN ts.state NOT IN ('Running', 'R', 'R+', 'D', 'S')
               THEN ts.dur ELSE 0 END) AS other,
      sum(CASE WHEN ts.state = 'Running' THEN 1 ELSE 0 END) AS num_run_slices
    FROM thread_state ts
    JOIN thread th USING (utid)
    LEFT JOIN process p USING (upid)
    WHERE ts.dur > 0
      AND NOT (th.utid IN (SELECT utid FROM thread WHERE is_idle))
      ${upidFilter}
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
