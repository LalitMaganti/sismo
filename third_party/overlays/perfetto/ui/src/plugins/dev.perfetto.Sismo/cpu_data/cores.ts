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
  LONG,
  LONG_NULL,
  NUM,
  NUM_NULL,
  STR,
  STR_NULL,
} from '../../../trace_processor/query_result';
import type {PrivilegedSet} from '../privileged_set';
import {clamp01} from '../format';
import {getSchedBounds, privInClause, privNotInClause} from './sql';
import {
  LATENCY_MODULE_BASE,
  LATENCY_MODULE_CONTENTION,
  LATENCY_MODULE_LOCKS,
  LATENCY_MODULE_WAIT_TYPES,
} from './latency_sql';
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

// A single occupant (your thread, or another process) of a core while your
// threads were runnable-but-not-scheduled, with its SHARE of that occupied
// core-time. Share not seconds: the interval-intersect over-counts across cores
// (while one thread waits, every busy core is credited), so absolute time is
// inflated ~Ncores; the share is honest because that denominator cancels.
export interface OccupantShare {
  // Representative utid for a self group; upid for a context process. For a
  // multi-thread group it's the heaviest member (so a link still lands on a real
  // thread).
  id: number;
  label: string;
  tid: number | null;
  pid: number | null;
  frac: number;
  // Threads rolled up under this row — self threads are grouped by name, so a
  // pool of N same-named threads is one row with count = N (1 otherwise).
  count: number;
}

// Why your threads sat runnable-but-not-scheduled: the wall-clock lost, whether
// a core was even free (placement) vs every core busy (contention), and — when
// busy — how that CPU split between YOUR OWN threads (self-contention, the
// common case) and OTHER processes.
export interface RunnableDelay {
  hasPriv: boolean;
  // The scheduling delay itself: your threads' R/R+ wall-clock. Honest seconds.
  totalNs: bigint;
  // Share of the occupied core-time (during your runnable windows) that was your
  // own threads vs other processes. selfFrac + contextFrac == 1 (or both 0).
  selfFrac: number;
  contextFrac: number;
  // Fraction of the runnable delay during which at least one core was idle —
  // i.e. the scheduler could have placed you but didn't (affinity, cgroup caps,
  // wakeup latency), not contention.
  idleAvailFrac: number;
  // Your own threads, ranked by share of the CPU that ran while others waited.
  selfThreads: OccupantShare[];
  // Other processes that held cores while you waited (the noisy-neighbour case).
  contextProcs: OccupantShare[];
}

// The landing L3 headline. Reads the shared, cached _sismo_runnable_occ (built
// once by the latency_contention module) so it's the same exact split the "Who
// it waited on" tab shows — just aggregated to totals instead of per-thread.
export interface RunnableSummary {
  hasPriv: boolean;
  totalNs: bigint;
  selfFrac: number;
  contextFrac: number;
  // Heaviest self thread-name group during your runnable windows.
  topSelfLabel: string | null;
}

export async function loadRunnableSummary(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<RunnableSummary> {
  if (priv.upids.length === 0) {
    return {hasPriv: false, totalNs: 0n, selfFrac: 0, contextFrac: 0, topSelfLabel: null};
  }
  await engine.query(`INCLUDE PERFETTO MODULE ${LATENCY_MODULE_CONTENTION};`);
  // Runnable delay: a flat sum joined to the profiled-thread table.
  const t = await engine.query(`
    SELECT sum(ts.dur) AS total
    FROM thread_state ts JOIN _sismo_priv p ON p.utid = ts.utid
    WHERE ts.state IN ('R', 'R+') AND ts.dur > 0
  `);
  const totalNs = t.firstRow({total: LONG_NULL}).total ?? 0n;

  const s = await engine.query(`
    SELECT
      sum(iif(is_self = 1, occ, 0)) AS self_ns,
      sum(iif(is_self = 0, occ, 0)) AS ctx_ns
    FROM _sismo_runnable_occ
  `);
  const sr = s.firstRow({self_ns: LONG_NULL, ctx_ns: LONG_NULL});
  const selfNs = Number(sr.self_ns ?? 0n);
  const ctxNs = Number(sr.ctx_ns ?? 0n);
  const denom = selfNs + ctxNs > 0 ? selfNs + ctxNs : 1;

  const top = await engine.query(`
    SELECT coalesce(th.name, 'utid ' || o.utid) AS nm
    FROM _sismo_runnable_occ o JOIN thread th ON th.utid = o.utid
    WHERE o.is_self = 1
    GROUP BY th.name
    ORDER BY sum(o.occ) DESC
    LIMIT 1
  `);
  const topSelfLabel = top.numRows() > 0 ? top.firstRow({nm: STR_NULL}).nm : null;

  return {
    hasPriv: true,
    totalNs,
    selfFrac: selfNs / denom,
    contextFrac: ctxNs / denom,
    topSelfLabel,
  };
}

export async function loadRunnableDelay(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<RunnableDelay> {
  const empty: RunnableDelay = {
    hasPriv: false,
    totalNs: 0n,
    selfFrac: 0,
    contextFrac: 0,
    idleAvailFrac: 0,
    selfThreads: [],
    contextProcs: [],
  };
  if (priv.upids.length === 0) return empty;
  // Build (once) + read the shared occupancy table. The interval_intersect lives
  // in the latency_contention module, so it runs at most once per trace.
  await engine.query(`INCLUDE PERFETTO MODULE ${LATENCY_MODULE_CONTENTION};`);

  const totalRes = await engine.query(`
    SELECT sum(ts.dur) AS total
    FROM thread_state ts JOIN _sismo_priv p ON p.utid = ts.utid
    WHERE ts.state IN ('R', 'R+') AND ts.dur > 0
  `);
  const totalNs = totalRes.firstRow({total: LONG_NULL}).total ?? 0n;
  if (totalNs === 0n) return {...empty, hasPriv: true};

  // Read the cached per-thread occupancy and attach names (a flat join over the
  // ~dozens of grouped rows).
  const res = await engine.query(`
    SELECT o.is_self AS is_self, o.utid AS utid, th.upid AS upid,
      th.tid AS tid, process.pid AS pid,
      coalesce(th.name, 'utid ' || o.utid) AS thread_name,
      coalesce(process.name, 'pid ' || process.pid) AS proc_name,
      o.occ AS occ
    FROM _sismo_runnable_occ o
    JOIN thread th ON th.utid = o.utid
    LEFT JOIN process ON process.upid = th.upid
    WHERE o.occ > 0
  `);
  let selfTotal = 0;
  let ctxTotal = 0;
  const selfRaw: {id: number; label: string; tid: number | null; occ: number}[] =
    [];
  const ctxAgg = new Map<
    number,
    {id: number; label: string; pid: number | null; occ: number}
  >();
  for (
    const it = res.iter({
      is_self: NUM,
      utid: NUM,
      upid: NUM_NULL,
      tid: NUM_NULL,
      pid: NUM_NULL,
      thread_name: STR_NULL,
      proc_name: STR_NULL,
      occ: LONG_NULL,
    });
    it.valid();
    it.next()
  ) {
    const occ = Number(it.occ ?? 0n);
    if (it.is_self === 1) {
      selfTotal += occ;
      selfRaw.push({
        id: it.utid,
        label: it.thread_name ?? `utid ${it.utid}`,
        tid: it.tid,
        occ,
      });
    } else {
      ctxTotal += occ;
      const key = it.upid ?? -1;
      const cur = ctxAgg.get(key);
      if (cur === undefined) {
        ctxAgg.set(key, {
          id: key,
          label: it.proc_name ?? `pid ${it.pid}`,
          pid: it.pid,
          occ,
        });
      } else {
        cur.occ += occ;
      }
    }
  }
  const occTotal = selfTotal + ctxTotal;
  const denom = occTotal > 0 ? occTotal : 1;

  // "At least one core idle" while you were runnable — union the idle intervals
  // across CPUs first (else the intersect over-counts idle cores), then
  // intersect with your runnable time. That's honest wall-clock, so it divides
  // the real delay.
  await engine.query('INCLUDE PERFETTO MODULE intervals.overlap;');
  const idleRes = await engine.query(`
    WITH pr AS (
      SELECT ts.id, ts.ts, ts.dur
      FROM thread_state ts JOIN _sismo_priv p ON p.utid = ts.utid
      WHERE ts.state IN ('R', 'R+') AND ts.dur > 0
    ),
    idle_raw AS (
      SELECT sched.ts, sched.dur FROM sched JOIN thread USING (utid)
      WHERE sched.dur > 0 AND thread.is_idle = 1
    ),
    -- Merge idle intervals across CPUs so "a core was free" is counted once per
    -- instant, not once per idle core.
    idle_union AS (
      SELECT row_number() OVER (ORDER BY ts) AS id, ts, dur
      FROM interval_merge_overlapping!(idle_raw, 0)
    )
    SELECT sum(ii.dur) AS idle_avail
    FROM _interval_intersect!((pr, idle_union), ()) ii
  `).catch(() => undefined);
  let idleAvailFrac = 0;
  if (idleRes !== undefined) {
    const ia = idleRes.firstRow({idle_avail: LONG_NULL}).idle_avail ?? 0n;
    idleAvailFrac = Number(ia) / Number(totalNs);
  }

  // Roll up your own threads by NAME: a pool of N same-named worker threads is
  // one row (count = N), keeping the heaviest member as the link target. This is
  // what you want for real apps — "all my `worker` threads held 60%", not 200
  // near-identical tids.
  const selfByName = new Map<
    string,
    {
      label: string;
      occ: number;
      count: number;
      repId: number;
      repTid: number | null;
      repOcc: number;
    }
  >();
  for (const r of selfRaw) {
    const g = selfByName.get(r.label);
    if (g === undefined) {
      selfByName.set(r.label, {
        label: r.label,
        occ: r.occ,
        count: 1,
        repId: r.id,
        repTid: r.tid,
        repOcc: r.occ,
      });
    } else {
      g.occ += r.occ;
      g.count += 1;
      if (r.occ > g.repOcc) {
        g.repOcc = r.occ;
        g.repId = r.id;
        g.repTid = r.tid;
      }
    }
  }
  const selfGroups = [...selfByName.values()].sort((a, b) => b.occ - a.occ);
  const ctxRaw = [...ctxAgg.values()].sort((a, b) => b.occ - a.occ);
  return {
    hasPriv: true,
    totalNs,
    selfFrac: selfTotal / denom,
    contextFrac: ctxTotal / denom,
    idleAvailFrac,
    selfThreads: selfGroups.slice(0, 12).map((g) => ({
      id: g.repId,
      label: g.label,
      tid: g.repTid,
      pid: null,
      frac: g.occ / denom,
      count: g.count,
    })),
    contextProcs: ctxRaw.slice(0, 12).map((r) => ({
      id: r.id,
      label: r.label,
      tid: null,
      pid: r.pid,
      frac: r.occ / denom,
      count: 1,
    })),
  };
}

// One thread that woke your threads out of a voluntary block, plus how much
// wall-clock your threads spent blocked before it did.
export interface WakerRow {
  utid: number;
  tid: number | null;
  threadName: string;
  processName: string | null;
  pid: number | null;
  // Sum of the blocked (S/D) intervals that ended in a wakeup by this thread.
  wokeNs: bigint;
  wakeups: number;
}

export interface WakerSummary {
  // Wakeups that came from another thread (process context) — the causal
  // "someone released the lock / signalled you", ranked by blocked time.
  threadWakers: WakerRow[];
  // Blocked time that ended in a thread wakeup vs a timer/device IRQ (a sleep or
  // timeout expiring, where no thread is the real cause).
  threadNs: bigint;
  timerIrqNs: bigint;
}

// "Who woke you": for each blocked (S/D) interval of a privileged thread, the
// wakeup that ended it carries a waker (thread_state.waker_utid on the R state
// the block transitions into). Attribute the blocked duration to that waker,
// split by whether the wakeup fired in process context (another thread) or in a
// timer/device IRQ (no meaningful waker). Needs sched_wakeup/sched_waking in the
// trace; trace_processor fills waker_utid from it.
export async function loadWakers(
  engine: Engine,
  priv: PrivilegedSet,
  limit: number,
): Promise<WakerSummary> {
  const empty: WakerSummary = {threadWakers: [], threadNs: 0n, timerIrqNs: 0n};
  if (priv.upids.length === 0) return empty;
  await engine.query(`INCLUDE PERFETTO MODULE ${LATENCY_MODULE_BASE};`);
  const res = await engine.query(`
    WITH wake AS (
      SELECT ts.utid AS utid, ts.ts AS r_ts, ts.waker_utid AS waker_utid,
        ts.irq_context AS irq_context
      FROM thread_state ts
      JOIN _sismo_priv p ON p.utid = ts.utid
      WHERE ts.state = 'R'
        AND ts.waker_utid IS NOT NULL
    ),
    blocked AS (
      SELECT utid, dur, ts + dur AS end_ts
      FROM thread_state
      WHERE state IN ('S', 'D') AND dur > 0
    ),
    -- Pair each wakeup to the block it ended (same thread, contiguous), so the
    -- blocked duration is what we attribute to the waker.
    paired AS (
      SELECT wake.waker_utid AS waker_utid, wake.irq_context AS irq_context,
        blocked.dur AS dur
      FROM wake
      JOIN blocked ON blocked.utid = wake.utid AND blocked.end_ts = wake.r_ts
    )
    SELECT
      thread.utid AS utid,
      thread.tid AS tid,
      coalesce(thread.name, '[utid ' || thread.utid || ']') AS thread_name,
      process.name AS process_name,
      process.pid AS pid,
      sum(paired.dur) AS woke_ns,
      count(*) AS wakeups,
      max(paired.irq_context) AS any_irq
    FROM paired
    JOIN thread ON thread.utid = paired.waker_utid
    LEFT JOIN process USING (upid)
    WHERE coalesce(paired.irq_context, 0) = 0 AND thread.is_idle = 0
    GROUP BY thread.utid
    HAVING woke_ns > 0
    ORDER BY woke_ns DESC
    LIMIT ${limit}
  `);
  const threadWakers: WakerRow[] = [];
  for (
    const it = res.iter({
      utid: NUM,
      tid: NUM_NULL,
      thread_name: STR_NULL,
      process_name: STR_NULL,
      pid: NUM_NULL,
      woke_ns: LONG_NULL,
      wakeups: NUM,
    });
    it.valid();
    it.next()
  ) {
    threadWakers.push({
      utid: it.utid,
      tid: it.tid,
      threadName: it.thread_name ?? '<unknown>',
      processName: it.process_name,
      pid: it.pid,
      wokeNs: it.woke_ns ?? 0n,
      wakeups: it.wakeups,
    });
  }
  // The thread-context vs timer/IRQ totals across all paired wakeups.
  const totals = await engine.query(`
    WITH wake AS (
      SELECT ts.utid AS utid, ts.ts AS r_ts, ts.irq_context AS irq_context
      FROM thread_state ts
      JOIN _sismo_priv p ON p.utid = ts.utid
      WHERE ts.state = 'R' AND ts.waker_utid IS NOT NULL
    ),
    blocked AS (
      SELECT utid, dur, ts + dur AS end_ts FROM thread_state
      WHERE state IN ('S', 'D') AND dur > 0
    )
    SELECT
      sum(CASE WHEN coalesce(wake.irq_context, 0) = 0 THEN blocked.dur ELSE 0 END) AS thread_ns,
      sum(CASE WHEN coalesce(wake.irq_context, 0) = 1 THEN blocked.dur ELSE 0 END) AS irq_ns
    FROM wake
    JOIN blocked ON blocked.utid = wake.utid AND blocked.end_ts = wake.r_ts
  `);
  const t = totals.firstRow({thread_ns: LONG_NULL, irq_ns: LONG_NULL});
  return {
    threadWakers,
    threadNs: t.thread_ns ?? 0n,
    timerIrqNs: t.irq_ns ?? 0n,
  };
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

// ---- Lock contention (futex uaddr = lock identity) -----------------------

export interface LockRow {
  // The futex uaddr the block waited on — the lock's stable identity within the
  // trace. Two locks taken at the same code site have distinct addresses.
  readonly addr: bigint;
  // Dominant contention site: the function that took the lock (caller of the
  // lock primitive).
  readonly site: string;
  // Distinct sites that take this lock (>1 = one lock contended from several
  // places).
  readonly siteCount: number;
  readonly waitNs: bigint;
  readonly waits: number;
  readonly threads: number;
}

export interface LockContention {
  readonly hasPriv: boolean;
  readonly totalWaitNs: bigint;
  readonly locks: ReadonlyArray<LockRow>;
}

// Rank the profiled processes' locks by the wall-clock their threads lost
// blocked on each. Reads the shared _sismo_locks table (built once per trace).
export async function loadLockContention(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<LockContention> {
  if (priv.upids.length === 0) {
    return {hasPriv: false, totalWaitNs: 0n, locks: []};
  }
  await engine.query(`INCLUDE PERFETTO MODULE ${LATENCY_MODULE_LOCKS};`);
  const res = await engine.query(`
    SELECT lock_addr, site, site_count, wait_ns, waits, threads
    FROM _sismo_locks
    ORDER BY wait_ns DESC
  `);
  const it = res.iter({
    lock_addr: LONG,
    site: STR,
    site_count: NUM,
    wait_ns: LONG,
    waits: NUM,
    threads: NUM,
  });
  const locks: LockRow[] = [];
  let totalWaitNs = 0n;
  for (; it.valid(); it.next()) {
    totalWaitNs += it.wait_ns;
    locks.push({
      addr: it.lock_addr,
      site: it.site,
      siteCount: it.site_count,
      waitNs: it.wait_ns,
      waits: it.waits,
      threads: it.threads,
    });
  }
  return {hasPriv: true, totalWaitNs, locks};
}

export interface LockSiteRow {
  readonly site: string;
  readonly waitNs: bigint;
  readonly waits: number;
}

export interface LockWaiterRow {
  readonly threadName: string;
  readonly threads: number;
  readonly waitNs: bigint;
  readonly waits: number;
}

export interface LockDetail {
  readonly addr: bigint;
  readonly waitNs: bigint;
  readonly waits: number;
  readonly threads: number;
  // Acquisition sites that block on this lock (the money view for a lock taken
  // from several places); one row for a single-site lock.
  readonly sites: ReadonlyArray<LockSiteRow>;
  // Waiter threads rolled up by name (a pool of N shows as one row, count N).
  readonly waiters: ReadonlyArray<LockWaiterRow>;
}

// Everything about one lock instance (keyed by its futex uaddr): its
// acquisition sites and the threads that blocked on it. Reads the cached
// _sismo_lock_waits table filtered to this address.
export async function loadLockDetail(
  engine: Engine,
  addr: bigint,
): Promise<LockDetail> {
  await engine.query(`INCLUDE PERFETTO MODULE ${LATENCY_MODULE_LOCKS};`);
  const tot = await engine.query(`
    SELECT CAST(sum(w) AS INT) AS wait_ns, count(*) AS waits,
           count(DISTINCT utid) AS threads
    FROM _sismo_lock_waits WHERE lock = ${addr}
  `);
  const t = tot.firstRow({wait_ns: LONG_NULL, waits: NUM, threads: NUM});

  const siteRes = await engine.query(`
    SELECT coalesce(s.site, '?') AS site,
           CAST(sum(w.w) AS INT) AS wait_ns, count(*) AS waits
    FROM _sismo_lock_waits w
    LEFT JOIN _sismo_lock_site s ON s.leaf_cs = w.cs
    WHERE w.lock = ${addr}
    GROUP BY coalesce(s.site, '?')
    ORDER BY sum(w.w) DESC
  `);
  const sites: LockSiteRow[] = [];
  for (
    const it = siteRes.iter({site: STR, wait_ns: LONG_NULL, waits: NUM});
    it.valid();
    it.next()
  ) {
    sites.push({site: it.site, waitNs: it.wait_ns ?? 0n, waits: it.waits});
  }

  const waiterRes = await engine.query(`
    SELECT coalesce(th.name, 'utid ' || w.utid) AS nm,
           count(DISTINCT w.utid) AS threads,
           CAST(sum(w.w) AS INT) AS wait_ns, count(*) AS waits
    FROM _sismo_lock_waits w
    JOIN thread th ON th.utid = w.utid
    WHERE w.lock = ${addr}
    GROUP BY coalesce(th.name, 'utid ' || w.utid)
    ORDER BY sum(w.w) DESC
  `);
  const waiters: LockWaiterRow[] = [];
  for (
    const it = waiterRes.iter({
      nm: STR,
      threads: NUM,
      wait_ns: LONG_NULL,
      waits: NUM,
    });
    it.valid();
    it.next()
  ) {
    waiters.push({
      threadName: it.nm,
      threads: it.threads,
      waitNs: it.wait_ns ?? 0n,
      waits: it.waits,
    });
  }

  return {
    addr,
    waitNs: t.wait_ns ?? 0n,
    waits: t.waits,
    threads: t.threads,
    sites,
    waiters,
  };
}

// ---- Wait-type breakdown (the quality axis) -------------------------------

export interface WaitTypeRow {
  // 'lock' | 'signaling' | 'disk' | 'network' | 'pipe' | 'sleep' | 'poll' |
  // 'memory' | 'other'
  readonly type: string;
  readonly waitNs: bigint;
  readonly waits: number;
}

export interface WaitBreakdown {
  readonly hasPriv: boolean;
  readonly totalNs: bigint;
  readonly types: ReadonlyArray<WaitTypeRow>;
}

// Split the profiled threads' blocked (voluntary) off-CPU time by WHAT they
// waited on. Involuntary preemption is excluded (it's the runnable-delay story,
// not a wait-for). Reads the shared _sismo_wait table.
export async function loadWaitBreakdown(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<WaitBreakdown> {
  if (priv.upids.length === 0) {
    return {hasPriv: false, totalNs: 0n, types: []};
  }
  await engine.query(`INCLUDE PERFETTO MODULE ${LATENCY_MODULE_WAIT_TYPES};`);
  const res = await engine.query(`
    SELECT wait_type, CAST(sum(w) AS INT) AS ns, count(*) AS waits
    FROM _sismo_wait
    WHERE wait_type != 'scheduling'
    GROUP BY wait_type
    ORDER BY sum(w) DESC
  `);
  const types: WaitTypeRow[] = [];
  let totalNs = 0n;
  for (
    const it = res.iter({wait_type: STR, ns: LONG_NULL, waits: NUM});
    it.valid();
    it.next()
  ) {
    const waitNs = it.ns ?? 0n;
    totalNs += waitNs;
    types.push({type: it.wait_type, waitNs, waits: it.waits});
  }
  return {hasPriv: true, totalNs, types};
}

// ---- Network waits (peer = who you're blocked on) -------------------------

export interface NetPeerRow {
  // The raw tagged block_id (bit 63 set); the drill key.
  readonly peerId: bigint;
  readonly addr: string;   // dotted IPv4
  readonly port: number;
  readonly waitNs: bigint;
  readonly blocks: number;
  readonly threads: number;
}

export interface NetworkPeers {
  readonly hasPriv: boolean;
  readonly totalWaitNs: bigint;
  readonly peers: ReadonlyArray<NetPeerRow>;
}

export interface NetWaiterRow {
  readonly threadName: string;
  readonly threads: number;
  readonly waitNs: bigint;
  readonly blocks: number;
}

export interface NetPeerDetail {
  readonly peerId: bigint;
  readonly waitNs: bigint;
  readonly blocks: number;
  readonly threads: number;
  readonly waiters: ReadonlyArray<NetWaiterRow>;
}

// Rank the remotes the profiled threads blocked on in recv, by wall-clock lost
// waiting. Reads the shared _sismo_net table.
export async function loadNetworkPeers(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<NetworkPeers> {
  if (priv.upids.length === 0) {
    return {hasPriv: false, totalWaitNs: 0n, peers: []};
  }
  await engine.query(`INCLUDE PERFETTO MODULE ${LATENCY_MODULE_WAIT_TYPES};`);
  const res = await engine.query(`
    SELECT peer_id, addr, port, wait_ns, blocks, threads
    FROM _sismo_net ORDER BY wait_ns DESC
  `);
  const peers: NetPeerRow[] = [];
  let totalWaitNs = 0n;
  for (
    const it = res.iter({
      peer_id: LONG,
      addr: STR,
      port: NUM,
      wait_ns: LONG_NULL,
      blocks: NUM,
      threads: NUM,
    });
    it.valid();
    it.next()
  ) {
    const waitNs = it.wait_ns ?? 0n;
    totalWaitNs += waitNs;
    peers.push({
      peerId: it.peer_id,
      addr: it.addr,
      port: it.port,
      waitNs,
      blocks: it.blocks,
      threads: it.threads,
    });
  }
  return {hasPriv: true, totalWaitNs, peers};
}

// The threads that blocked on one peer, rolled up by name.
export async function loadNetPeerDetail(
  engine: Engine,
  peerId: bigint,
): Promise<NetPeerDetail> {
  await engine.query(`INCLUDE PERFETTO MODULE ${LATENCY_MODULE_WAIT_TYPES};`);
  const res = await engine.query(`
    SELECT coalesce(th.name, 'utid ' || ow.utid) AS nm,
           count(DISTINCT ow.utid) AS threads,
           CAST(sum(ow.w) AS INT) AS wait_ns, count(*) AS blocks
    FROM _sismo_offcpu_waits ow
    JOIN thread th ON th.utid = ow.utid
    WHERE ow.lock = ${peerId}
    GROUP BY coalesce(th.name, 'utid ' || ow.utid)
    ORDER BY sum(ow.w) DESC
  `);
  const waiters: NetWaiterRow[] = [];
  let waitNs = 0n;
  let blocks = 0;
  const utids = new Set<string>();
  for (
    const it = res.iter({nm: STR, threads: NUM, wait_ns: LONG_NULL, blocks: NUM});
    it.valid();
    it.next()
  ) {
    waitNs += it.wait_ns ?? 0n;
    blocks += it.blocks;
    utids.add(it.nm);
    waiters.push({
      threadName: it.nm,
      threads: it.threads,
      waitNs: it.wait_ns ?? 0n,
      blocks: it.blocks,
    });
  }
  const threads = waiters.reduce((n, w) => n + w.threads, 0);
  return {peerId, waitNs, blocks, threads, waiters};
}
