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

// L4 — "A few long stalls, or constant churn?" How the off-CPU time is spread
// across individual waits: a handful of long stalls versus death-by-a-thousand-
// cuts. Vertical slice: owns its query, types, and rendering.

import m from 'mithril';
import type {Engine} from '../../../trace_processor/engine';
import {LONG_NULL} from '../../../trace_processor/query_result';
import type {PrivilegedSet} from '../privileged_set';
import {fmtCount, fmtPercent} from '../format';
import {questionBlock} from '../cpu/block';
import {Meter, meterReadout, type MeterColor} from '../../dev.perfetto.SismoWidgets/meter';

export interface ChurnSummary {
  // Number of distinct off-CPU intervals (each a block→wake cycle).
  readonly intervals: number;
  // Total off-CPU nanoseconds.
  readonly totalNs: number;
  // Nanoseconds in the 6 longest waits.
  readonly top6Ns: number;
}

export async function loadChurn(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<ChurnSummary> {
  const scope =
    priv.upids.length > 0 ? `IN (${priv.upids.join(',')})` : 'IS NOT NULL';
  const res = await engine.query(`
    WITH offcpu AS (
      SELECT ts.dur AS dur
      FROM thread_state ts
      JOIN thread th USING (utid)
      WHERE ts.dur > 0
        AND ts.state NOT IN ('Running', 'R', 'R+')
        AND NOT (th.utid IN (SELECT utid FROM thread WHERE is_idle))
        AND th.upid ${scope}
    )
    SELECT
      (SELECT count(*) FROM offcpu) AS intervals,
      (SELECT sum(dur) FROM offcpu) AS total,
      (SELECT sum(dur) FROM (SELECT dur FROM offcpu ORDER BY dur DESC LIMIT 6))
        AS top6
  `);
  const r = res.firstRow({intervals: LONG_NULL, total: LONG_NULL, top6: LONG_NULL});
  return {
    intervals: Number(r.intervals ?? 0n),
    totalNs: Number(r.total ?? 0n),
    top6Ns: Number(r.top6 ?? 0n),
  };
}

export function renderChurnBlock(s: ChurnSummary): m.Children {
  const question = 'A few long stalls, or constant churn?';
  const description =
    'How the off-CPU time is distributed across individual waits — outliers ' +
    'versus death-by-a-thousand-cuts.';

  if (s.intervals === 0 || s.totalNs === 0) {
    return questionBlock({
      question,
      description,
      answer: 'No off-CPU waits were recorded for these threads.',
    });
  }

  const conc = s.top6Ns / s.totalNs;
  const answer =
    conc >= 0.5
      ? `${fmtCount(s.intervals)} distinct waits, but the 6 longest are ` +
        `${fmtPercent(conc, 0)} of the off-CPU time — a few big stalls dominate.`
      : `${fmtCount(s.intervals)} distinct waits; the 6 longest are only ` +
        `${fmtPercent(conc, 0)} of the off-CPU time — the waiting is spread ` +
        'across many small ones.';

  const bar = [
    {color: 'caution' as MeterColor, frac: conc},
    {color: 'idle' as MeterColor, frac: 1 - conc},
  ];

  return questionBlock(
    {
      question,
      description,
      answer,
    },
    [
      m(Meter, {
        label: 'Concentration of the wait',
        help:
          'Share of the off-CPU time that sits in the 6 longest individual ' +
          'waits versus everything else. Colours are roles, not a good/bad ' +
          'scale.',
        primary: meterReadout(fmtPercent(conc, 0), ' is in the 6 longest waits'),
        bar,
        legend: [
          {color: 'caution', label: 'The 6 longest waits', value: fmtPercent(conc, 0)},
          {color: 'idle', label: 'Everything else', value: fmtPercent(1 - conc, 0)},
        ],
      }),
    ],
  );
}
