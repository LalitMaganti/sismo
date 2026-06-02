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

// Block 0 — "Is this even a CPU problem?" The router, and the first thing on the
// landing. It splits the profiled threads' wall time into running /
// runnable-but-not-scheduled / waiting, as a neutral fact, and points at the
// Latency section when waiting dominates. Vertical slice: owns its query, its
// types, and its rendering.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import type {Engine} from '../../../trace_processor/engine';
import {LONG_NULL} from '../../../trace_processor/query_result';
import {Button, ButtonVariant} from '../../../widgets/button';
import {goToSismoDomain} from '../page_common';
import type {PrivilegedSet} from '../privileged_set';
import {fmtPercent} from '../format';
import {questionBlock} from './block';
import {Meter, meterReadout} from '../../dev.perfetto.SismoWidgets/meter';

// Wall-time split of the profiled threads. running = on-CPU; runnable = ready
// but the scheduler didn't give it a core; waiting = blocked/sleeping on
// something. Nanoseconds.
export interface TriageSummary {
  readonly runningNs: number;
  readonly runnableNs: number;
  readonly waitingNs: number;
  readonly totalNs: number;
}

export async function loadTriage(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<TriageSummary> {
  // Scope to the profiled processes when a set is selected; otherwise every real
  // thread, so the block still states what the trace says.
  const scope =
    priv.upids.length > 0 ? `IN (${priv.upids.join(',')})` : 'IS NOT NULL';
  const res = await engine.query(`
    SELECT
      sum(CASE WHEN ts.state = 'Running' THEN ts.dur ELSE 0 END) AS running,
      sum(CASE WHEN ts.state IN ('R', 'R+') THEN ts.dur ELSE 0 END) AS runnable,
      sum(CASE WHEN ts.state NOT IN ('Running', 'R', 'R+')
               THEN ts.dur ELSE 0 END) AS waiting
    FROM thread_state ts
    JOIN thread th USING (utid)
    WHERE ts.dur > 0
      AND NOT (th.utid IN (SELECT utid FROM thread WHERE is_idle))
      AND th.upid ${scope}
  `);
  const r = res.firstRow({
    running: LONG_NULL,
    runnable: LONG_NULL,
    waiting: LONG_NULL,
  });
  const running = Number(r.running ?? 0n);
  const runnable = Number(r.runnable ?? 0n);
  const waiting = Number(r.waiting ?? 0n);
  return {
    runningNs: running,
    runnableNs: runnable,
    waitingNs: waiting,
    totalNs: running + runnable + waiting,
  };
}

export function renderTriageBlock(
  trace: Trace,
  s: TriageSummary,
): m.Children {
  const total = s.totalNs > 0 ? s.totalNs : 1;
  const runFrac = s.runningNs / total;
  const runnableFrac = s.runnableNs / total;
  const waitFrac = s.waitingNs / total;
  const offFrac = runnableFrac + waitFrac;
  const runPct = Math.round(runFrac * 100);
  const offPct = Math.round(offFrac * 100);

  // Plain answer, no verdict: state the split and where the waiting part lives.
  const answer =
    offFrac >= 0.5
      ? `Most of the time was spent off the CPU (${offPct}%) — much of this is ` +
        'likely a Latency question rather than a CPU one.'
      : offFrac <= 0.1
        ? `Almost all of the time was spent running on the CPU (${runPct}%) — ` +
          'this is a CPU story.'
        : `${runPct}% running on the CPU, ${offPct}% waiting off it.`;

  return questionBlock(
    {question: 'Is this even a CPU problem?', answer},
    [
      // Colours are roles, not a good/bad scale; per-state durations live one
      // tab over in Latency.
      m(Meter, {
        label: 'Thread-time split',
        help:
          'How the profiled threads’ tracked time divides between running on a ' +
          'core, ready but not scheduled, and waiting (blocked or asleep).',
        primary: meterReadout(fmtPercent(runFrac), ' running on the CPU'),
        bar: [
          {color: 'primary', frac: runFrac},
          {color: 'secondary', frac: runnableFrac},
          {color: 'idle', frac: waitFrac},
        ],
        legend: [
          {
            color: 'primary',
            label: 'Running on the CPU',
            value: fmtPercent(runFrac),
          },
          {
            color: 'secondary',
            label: 'Ready, not scheduled',
            value: fmtPercent(runnableFrac),
          },
          {
            color: 'idle',
            label: 'Waiting (blocked/sleeping)',
            value: fmtPercent(waitFrac),
          },
        ],
      }),
      offFrac >= 0.2 &&
        m(
          '.pf-sismo-qblock__route',
          m(Button, {
            label: 'Open the Latency section',
            icon: 'open_in_new',
            variant: ButtonVariant.Minimal,
            onclick: () => goToSismoDomain(trace, 'latency'),
          }),
        ),
    ],
  );
}
