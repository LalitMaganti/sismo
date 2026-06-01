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

// Block 2 — "Were your threads running in parallel, or serialized?" Shows how
// much of the active time had 1 / 2-4 / 5+ of the profiled threads on a CPU at
// once, as a table. Single-threaded processes get an honest one-liner. The
// full concurrency-over-time view is the Threads-over-time tab.

import m from 'mithril';
import type {Engine} from '../../../trace_processor/engine';
import {LONG_NULL, NUM} from '../../../trace_processor/query_result';
import type {PrivilegedSet} from '../privileged_set';
import {fmtDurationNs, fmtPercent} from '../format';
import {renderStatCard, type StatCard} from '../page_common';
import {questionBlock} from './block';
import {breakdownGrid, type BreakdownGridRow} from './grid';

export interface ParallelSummary {
  readonly threadCount: number;
  readonly avgConcurrency: number;
  // Fraction of active time with exactly one thread on a CPU (serial).
  readonly serialFrac: number;
  // Active time split by how many threads were on a CPU at once.
  readonly distribution: ReadonlyArray<BreakdownGridRow>;
}

const QUESTION = 'Were your threads running in parallel, or serialized?';

export async function loadParallelSummary(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<ParallelSummary> {
  const scope =
    priv.upids.length > 0
      ? `thread.upid IN (${priv.upids.join(',')})`
      : 'thread.upid IS NOT NULL';
  const where = `sched.dur > 0 AND ${scope}
    AND NOT (sched.utid IN (SELECT utid FROM thread WHERE is_idle))`;

  const head = await engine.query(`
    SELECT
      count(DISTINCT sched.utid) AS threads,
      sum(sched.dur) AS total,
      max(sched.ts + sched.dur) - min(sched.ts) AS span
    FROM sched JOIN thread USING (utid)
    WHERE ${where}
  `);
  const h = head.firstRow({threads: NUM, total: LONG_NULL, span: LONG_NULL});
  const total = Number(h.total ?? 0n);
  const span = Number(h.span ?? 0n);
  const threadCount = h.threads;

  // Sweep the profiled threads' on-CPU intervals: +1 at each start, -1 at each
  // end, running sum = how many were on a CPU at that instant; weight each gap
  // by its duration. The `d DESC` tie-break makes a start at the same ts as an
  // end count first (peak concurrency). Run it even single-threaded, where it
  // simply reports 100% at one thread.
  const dist = await engine.query(`
    WITH ev AS (
      SELECT sched.ts AS t, 1 AS d FROM sched JOIN thread USING (utid)
      WHERE ${where}
      UNION ALL
      SELECT sched.ts + sched.dur AS t, -1 AS d FROM sched JOIN thread USING (utid)
      WHERE ${where}
    ),
    run AS (
      SELECT t,
        sum(d) OVER (ORDER BY t, d DESC
          ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS cc,
        lead(t) OVER (ORDER BY t, d DESC) AS nt
      FROM ev
    )
    SELECT
      sum(CASE WHEN cc = 1 THEN nt - t ELSE 0 END) AS c1,
      sum(CASE WHEN cc BETWEEN 2 AND 4 THEN nt - t ELSE 0 END) AS c24,
      sum(CASE WHEN cc >= 5 THEN nt - t ELSE 0 END) AS c5
    FROM run WHERE nt IS NOT NULL AND nt > t
  `);
  const d = dist.firstRow({c1: LONG_NULL, c24: LONG_NULL, c5: LONG_NULL});
  const c1 = Number(d.c1 ?? 0n);
  const c24 = Number(d.c24 ?? 0n);
  const c5 = Number(d.c5 ?? 0n);
  const active = c1 + c24 + c5 || 1;
  const serialFrac = c1 / active;
  const distribution: BreakdownGridRow[] = [
    {name: '1 thread at a time', value: c1, share: c1 / active},
    {name: '2–4 threads', value: c24, share: c24 / active},
    {name: '5+ threads', value: c5, share: c5 / active},
  ].filter((r) => r.share > 0);

  return {
    threadCount,
    avgConcurrency: span > 0 ? total / span : 0,
    serialFrac,
    distribution,
  };
}

export function renderParallelBlock(s: ParallelSummary): m.Children {
  const avg = s.avgConcurrency;
  const answer =
    s.threadCount < 2
      ? 'This ran on a single thread — one thread on a CPU the whole time.'
      : avg <= 1.3
        ? `Mostly serial — about one thread ran at a time ` +
          `(avg ${avg.toFixed(1)} of ${s.threadCount}).`
        : avg >= s.threadCount * 0.7
          ? `Largely parallel — on average ${avg.toFixed(1)} of ` +
            `${s.threadCount} threads ran at once.`
          : `Partly parallel — on average ${avg.toFixed(1)} of ` +
            `${s.threadCount} threads ran at once.`;
  const cards: StatCard[] = [
    {label: 'Threads', value: String(s.threadCount)},
    {label: 'Avg at once', value: avg.toFixed(1)},
    {label: 'Serial', value: fmtPercent(s.serialFrac)},
  ];
  return questionBlock({question: QUESTION, answer}, [
    m('.pf-sismo-page__stat-row', cards.map(renderStatCard)),
    breakdownGrid({
      nameTitle: 'Threads at once',
      valueTitle: 'Active time',
      formatValue: fmtDurationNs,
      rows: s.distribution,
    }),
  ]);
}
