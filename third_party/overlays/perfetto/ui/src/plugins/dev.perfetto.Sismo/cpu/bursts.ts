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

// Block 3 — "Steady work, or lots of small bursts?" Raw run-length facts: how
// many on-CPU bursts, a typical / the longest length, and the CPU time split by
// burst length. Deliberately NO good-vs-bad split and NO governor-ramp
// threshold — those would assert a verdict the tool can't make.

import m from 'mithril';
import type {Engine} from '../../../trace_processor/engine';
import {LONG_NULL, NUM} from '../../../trace_processor/query_result';
import type {PrivilegedSet} from '../privileged_set';
import {fmtDurationNs, fmtPercent} from '../format';
import {renderStatCard, type StatCard} from '../page_common';
import {questionBlock} from './block';
import type {BreakdownGridRow} from './grid';
import {
  Meter,
  meterReadout,
  type MeterColor,
} from '../../dev.perfetto.SismoWidgets/meter';

export interface BurstSummary {
  readonly count: number;
  readonly medianNs: number;
  readonly maxNs: number;
  // CPU time split by how long each on-CPU burst lasted.
  readonly distribution: ReadonlyArray<BreakdownGridRow>;
}

const QUESTION = 'Steady work, or lots of small bursts?';

// Meter colour per burst-length bucket, keyed by the names the loader builds the
// distribution rows with. Purely categorical — the bars distinguish buckets,
// they do NOT rank them; this block asserts no good/bad burst length.
const BUCKET_COLORS: ReadonlyArray<readonly [string, MeterColor]> = [
  ['under 100 µs', 'idle'],
  ['100 µs – 1 ms', 'info'],
  ['1 – 10 ms', 'secondary'],
  ['10 – 100 ms', 'caution'],
  ['100 ms and up', 'primary'],
];

function bucketColor(name: string): MeterColor {
  return BUCKET_COLORS.find(([n]) => n === name)?.[1] ?? 'idle';
}

export async function loadBurstSummary(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<BurstSummary> {
  const scope =
    priv.upids.length > 0
      ? `thread.upid IN (${priv.upids.join(',')})`
      : 'thread.upid IS NOT NULL';
  const slices = `sched.dur AS d
    FROM sched JOIN thread USING (utid)
    WHERE sched.dur > 0 AND ${scope}
      AND NOT (sched.utid IN (SELECT utid FROM thread WHERE is_idle))`;

  const head = await engine.query(`
    WITH s AS (SELECT ${slices})
    SELECT
      (SELECT count(*) FROM s) AS cnt,
      (SELECT max(d) FROM s) AS mx,
      (SELECT d FROM s ORDER BY d
        LIMIT 1 OFFSET (SELECT count(*) FROM s) / 2) AS median
  `);
  const h = head.firstRow({cnt: NUM, mx: LONG_NULL, median: LONG_NULL});

  // CPU time by burst-length bucket (sub-100us / 100us-1ms / 1-10ms / 10-100ms
  // / 100ms+). Raw distribution, no good/bad boundary.
  const dist = await engine.query(`
    WITH s AS (SELECT ${slices})
    SELECT
      sum(CASE WHEN d < 100000 THEN d ELSE 0 END) AS b0,
      sum(CASE WHEN d >= 100000 AND d < 1000000 THEN d ELSE 0 END) AS b1,
      sum(CASE WHEN d >= 1000000 AND d < 10000000 THEN d ELSE 0 END) AS b2,
      sum(CASE WHEN d >= 10000000 AND d < 100000000 THEN d ELSE 0 END) AS b3,
      sum(CASE WHEN d >= 100000000 THEN d ELSE 0 END) AS b4
    FROM s
  `);
  const d = dist.firstRow({
    b0: LONG_NULL,
    b1: LONG_NULL,
    b2: LONG_NULL,
    b3: LONG_NULL,
    b4: LONG_NULL,
  });
  const buckets: ReadonlyArray<[string, number]> = [
    ['under 100 µs', Number(d.b0 ?? 0n)],
    ['100 µs – 1 ms', Number(d.b1 ?? 0n)],
    ['1 – 10 ms', Number(d.b2 ?? 0n)],
    ['10 – 100 ms', Number(d.b3 ?? 0n)],
    ['100 ms and up', Number(d.b4 ?? 0n)],
  ];
  const totalNs = buckets.reduce((sum, [, ns]) => sum + ns, 0) || 1;
  const distribution: BreakdownGridRow[] = buckets
    .filter(([, ns]) => ns > 0)
    .map(([name, ns]) => ({name, value: ns, share: ns / totalNs}));

  return {
    count: h.cnt,
    medianNs: Number(h.median ?? 0n),
    maxNs: Number(h.mx ?? 0n),
    distribution,
  };
}

export function renderBurstBlock(s: BurstSummary): m.Children {
  if (s.count === 0) {
    return questionBlock({
      question: QUESTION,
      answer: 'No on-CPU bursts were recorded for these threads.',
    });
  }
  const answer =
    `Ran in ${s.count.toLocaleString()} on-CPU ` +
    `burst${s.count === 1 ? '' : 's'}; a typical one lasted ` +
    `${fmtDurationNs(s.medianNs)} (longest ${fmtDurationNs(s.maxNs)}).`;
  const cards: StatCard[] = [
    {label: 'Bursts', value: s.count.toLocaleString()},
    {label: 'Typical', value: fmtDurationNs(s.medianNs)},
    {label: 'Longest', value: fmtDurationNs(s.maxNs)},
  ];
  const dominant = s.distribution.reduce((a, b) =>
    b.share > a.share ? b : a,
  );
  return questionBlock({question: QUESTION, answer}, [
    m('.pf-sismo-page__stat-row', cards.map(renderStatCard)),
    // CPU time split by how long each on-CPU burst lasted — a whole divided
    // into length buckets, so one stacked bar reads better than a table.
    m(Meter, {
      label: 'Burst-length mix',
      help:
        'How the threads’ on-CPU time divides by how long each continuous run ' +
        'lasted before going idle.',
      primary: meterReadout(fmtPercent(dominant.share), ` in ${dominant.name} bursts`),
      bar: s.distribution.map((r) => ({
        color: bucketColor(r.name),
        frac: r.share,
      })),
      legend: s.distribution.map((r) => ({
        color: bucketColor(r.name),
        label: r.name,
        value: fmtPercent(r.share),
      })),
    }),
  ]);
}
