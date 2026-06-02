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

// Data for the entity detail tabs (a function / thread / process drilled out of
// the CPU views). Everything here is LEAF-BASED self time — the function the
// sample was actually executing — which is the honest number a timer-sampled
// profile can report (no PEBS, so we don't pretend to attribute counters to a
// single function). The call-shape evidence (who calls whom) is left to the
// flamegraph the detail tab renders alongside these splits.

import type {Engine} from '../../../trace_processor/engine';
import {LONG, NUM, NUM_NULL, STR_NULL} from '../../../trace_processor/query_result';
import type {PrivilegedSet} from '../privileged_set';
import {frameNameExpr, sampleScopePredicate} from './sql';

// One row of a "where did this entity's samples land" split: a named bucket
// (thread / module / function), its self-sample count, its share of the entity's
// samples, and — for a thread bucket — the ids needed to drill or reveal it.
export interface EntitySplitRow {
  readonly name: string;
  readonly samples: number;
  readonly share: number;
  readonly utid?: number;
  readonly tid?: number | null;
  readonly upid?: number;
  readonly process?: string;
}

// What "why is this FUNCTION slow" shows beyond the flamegraph: how its own
// (self) samples spread across the threads that ran it and the modules it lives
// in, plus the headline self-share of the profiled CPU.
export interface FunctionDetail {
  readonly name: string;
  // Samples whose leaf frame is this function (it was on-CPU at the tick).
  readonly selfSamples: number;
  // Samples whose stack passes through this function ANYWHERE (self + the cost
  // of everything it called). The VTune "Total" to selfSamples' "Self".
  readonly inclusiveSamples: number;
  // All in-scope samples — the denominator for the headline share.
  readonly scopeSamples: number;
  readonly byThread: ReadonlyArray<EntitySplitRow>;
  readonly byModule: ReadonlyArray<EntitySplitRow>;
}

// Max rows per split table; the detail tab reports coverage when it bites.
export const SPLIT_LIMIT = 50;

export async function loadFunctionDetail(
  engine: Engine,
  priv: PrivilegedSet,
  name: string,
): Promise<FunctionDetail> {
  const scope = sampleScopePredicate(priv);
  const esc = name.replace(/'/g, "''");
  const nameExpr = frameNameExpr('f', null);

  // Inclusive ("Total") = samples whose stack passes through any callsite of
  // this function or a descendant of one (the function may sit at many sites).
  const descCte = `
    WITH RECURSIVE
      matchcs AS (
        SELECT c.id AS id
        FROM stack_profile_callsite c
        JOIN stack_profile_frame f ON f.id = c.frame_id
        WHERE ${nameExpr} = '${esc}'
      ),
      descendants(id) AS (
        SELECT id FROM matchcs
        UNION
        SELECT c.id FROM stack_profile_callsite c
        JOIN descendants d ON c.parent_id = d.id
      )`;

  const totals = await engine.query(`
    ${descCte}
    SELECT
      (SELECT count(*) FROM perf_sample s
        WHERE s.callsite_id IS NOT NULL ${scope}) AS scope_samples,
      (SELECT count(*) FROM perf_sample s
        JOIN stack_profile_callsite c ON c.id = s.callsite_id
        JOIN stack_profile_frame f ON f.id = c.frame_id
        WHERE ${nameExpr} = '${esc}' ${scope}) AS self_samples,
      (SELECT count(*) FROM perf_sample s
        WHERE s.callsite_id IN (SELECT id FROM descendants) ${scope}) AS inclusive
  `);
  const tr = totals.firstRow({
    scope_samples: NUM,
    self_samples: NUM_NULL,
    inclusive: NUM,
  });
  const selfSamples = tr.self_samples ?? 0;
  const inclusiveSamples = tr.inclusive;
  const scopeSamples = tr.scope_samples;
  const denom = selfSamples > 0 ? selfSamples : 1;

  const byThread: EntitySplitRow[] = [];
  if (selfSamples > 0) {
    const res = await engine.query(`
      SELECT
        coalesce(th.name, 'utid ' || th.utid) AS name,
        th.utid AS utid,
        th.tid AS tid,
        th.upid AS upid,
        pr.name AS process,
        count(*) AS samples
      FROM perf_sample s
      JOIN stack_profile_callsite c ON c.id = s.callsite_id
      JOIN stack_profile_frame f ON f.id = c.frame_id
      JOIN thread th ON th.utid = s.utid
      LEFT JOIN process pr ON pr.upid = th.upid
      WHERE s.callsite_id IS NOT NULL AND ${nameExpr} = '${esc}' ${scope}
      GROUP BY th.utid
      ORDER BY samples DESC
      LIMIT ${SPLIT_LIMIT}
    `);
    for (
      const it = res.iter({
        name: STR_NULL,
        utid: NUM,
        tid: NUM_NULL,
        upid: NUM_NULL,
        process: STR_NULL,
        samples: NUM,
      });
      it.valid();
      it.next()
    ) {
      byThread.push({
        name: it.name ?? `utid ${it.utid}`,
        utid: it.utid,
        tid: it.tid,
        upid: it.upid ?? undefined,
        process: it.process ?? undefined,
        samples: it.samples,
        share: it.samples / denom,
      });
    }
  }

  const byModule: EntitySplitRow[] = [];
  if (selfSamples > 0) {
    const res = await engine.query(`
      SELECT
        coalesce(spm.name, '[unknown module]') AS name,
        count(*) AS samples
      FROM perf_sample s
      JOIN stack_profile_callsite c ON c.id = s.callsite_id
      JOIN stack_profile_frame f ON f.id = c.frame_id
      LEFT JOIN stack_profile_mapping spm ON spm.id = f.mapping
      WHERE s.callsite_id IS NOT NULL AND ${nameExpr} = '${esc}' ${scope}
      GROUP BY spm.name
      ORDER BY samples DESC
      LIMIT ${SPLIT_LIMIT}
    `);
    for (
      const it = res.iter({name: STR_NULL, samples: NUM});
      it.valid();
      it.next()
    ) {
      byModule.push({
        name: it.name ?? '[unknown module]',
        samples: it.samples,
        share: it.samples / denom,
      });
    }
  }

  return {name, selfSamples, inclusiveSamples, scopeSamples, byThread, byModule};
}

// What "why is this THREAD slow" shows beyond the flamegraph: its on-CPU sample
// count and share of the profiled set, the wall time it actually ran, and the
// functions it spent that time in.
export interface ThreadDetail {
  readonly utid: number;
  readonly tid: number | null;
  readonly threadName: string;
  readonly process?: string;
  readonly upid?: number;
  // Samples whose thread is this one (on-CPU at the tick).
  readonly samples: number;
  // All in-scope samples — denominator for the headline share.
  readonly scopeSamples: number;
  // Wall time the thread was actually scheduled on a CPU.
  readonly onCpuNs: bigint;
  readonly byFunction: ReadonlyArray<EntitySplitRow>;
}

export async function loadThreadDetail(
  engine: Engine,
  priv: PrivilegedSet,
  utid: number,
): Promise<ThreadDetail> {
  const scope = sampleScopePredicate(priv);
  const nameExpr = frameNameExpr('spf');

  const head = await engine.query(`
    SELECT
      th.tid AS tid,
      th.name AS thread_name,
      th.upid AS upid,
      pr.name AS process
    FROM thread th
    LEFT JOIN process pr ON pr.upid = th.upid
    WHERE th.utid = ${utid}
  `);
  const hr = head.firstRow({
    tid: NUM_NULL,
    thread_name: STR_NULL,
    upid: NUM_NULL,
    process: STR_NULL,
  });

  const counts = await engine.query(`
    SELECT
      (SELECT count(*) FROM perf_sample s
        WHERE s.callsite_id IS NOT NULL ${scope}) AS scope_samples,
      (SELECT count(*) FROM perf_sample s
        WHERE s.callsite_id IS NOT NULL AND s.utid = ${utid}) AS samples,
      (SELECT coalesce(sum(dur), 0) FROM sched
        WHERE utid = ${utid} AND dur > 0) AS on_cpu_ns
  `);
  const cr = counts.firstRow({
    scope_samples: NUM,
    samples: NUM,
    on_cpu_ns: LONG,
  });
  const denom = cr.samples > 0 ? cr.samples : 1;

  const byFunction: EntitySplitRow[] = [];
  if (cr.samples > 0) {
    const res = await engine.query(`
      SELECT ${nameExpr} AS name, count(*) AS samples
      FROM perf_sample s
      JOIN stack_profile_callsite c ON c.id = s.callsite_id
      JOIN stack_profile_frame spf ON spf.id = c.frame_id
      WHERE s.callsite_id IS NOT NULL AND s.utid = ${utid}
      GROUP BY 1
      ORDER BY samples DESC
      LIMIT ${SPLIT_LIMIT}
    `);
    for (
      const it = res.iter({name: STR_NULL, samples: NUM});
      it.valid();
      it.next()
    ) {
      byFunction.push({
        name: it.name ?? '[unsymbolised]',
        samples: it.samples,
        share: it.samples / denom,
      });
    }
  }

  return {
    utid,
    tid: hr.tid,
    threadName: hr.thread_name ?? `utid ${utid}`,
    process: hr.process ?? undefined,
    upid: hr.upid ?? undefined,
    samples: cr.samples,
    scopeSamples: cr.scope_samples,
    onCpuNs: cr.on_cpu_ns,
    byFunction,
  };
}
