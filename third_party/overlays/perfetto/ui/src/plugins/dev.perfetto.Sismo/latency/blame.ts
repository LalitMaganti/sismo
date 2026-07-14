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

// L3 — "Who or what was making you wait?" Of the time your threads were
// runnable but not scheduled, what held the cores instead — led by your OWN
// threads (self-contention: too many hot threads for the cores), the common
// cause, then other processes. Hands off to the full "Who it waited on" tab.

import m from 'mithril';
import type {RunnableSummary} from '../cpu_data';
import {fmtPercent} from '../format';
import {questionBlock} from '../cpu/block';
import {Meter, meterReadout, type MeterColor} from '../../dev.perfetto.SismoWidgets/meter';

const QUESTION = 'Who or what was making you wait?';
const DESCRIPTION =
  'Of the time your threads were runnable but not scheduled, this splits the ' +
  'CPU that ran instead into your own threads (self-contention) versus other ' +
  'processes.';

// Reads the cheap RunnableSummary (a flat sum + a whole-trace CPU-share proxy),
// so the landing pays no interval_intersect on page load. The precise
// per-runnable-window attribution is the "Who it waited on" tab's job.
export function renderBlameBlock(
  r: RunnableSummary,
  onNavigate: (tab: string) => void,
): m.Children {
  if (!r.hasPriv) {
    return questionBlock({
      question: QUESTION,
      description: DESCRIPTION,
      answer:
        'Record with `sismo record` to tag the processes you’re profiling — ' +
        'then this attributes your scheduling delay to whatever ran instead.',
    });
  }

  if (r.totalNs === 0n) {
    return questionBlock({
      question: QUESTION,
      description: DESCRIPTION,
      answer:
        'Nothing kept your threads off a core — they were scheduled as soon as ' +
        'they became runnable.',
    });
  }

  const selfPct = fmtPercent(r.selfFrac, 0);
  const ctxPct = fmtPercent(r.contextFrac, 0);
  const answer =
    r.selfFrac >= r.contextFrac
      ? `Mostly your own threads — ${selfPct} of the CPU used while your ` +
        'threads were ready to run was other threads of the same process ' +
        '(self-contention: more hot threads than cores)' +
        (r.topSelfLabel ? `, led by "${r.topSelfLabel}".` : '.')
      : `Mostly other processes — ${ctxPct} of the CPU used while your ` +
        'threads were ready belonged to other processes on the machine.';

  const colors: [MeterColor, MeterColor] = ['primary', 'info'];
  const bar = [
    {color: colors[0], frac: r.selfFrac},
    {color: colors[1], frac: r.contextFrac},
  ];
  const legend = [
    {color: colors[0], label: 'Your own threads', value: selfPct},
    {color: colors[1], label: 'Other processes', value: ctxPct},
  ];

  return questionBlock(
    {
      question: QUESTION,
      description: DESCRIPTION,
      answer,
      deeper: {
        label: 'Who else competed for the CPU',
        onclick: () => onNavigate('scheduling'),
      },
    },
    [
      m(Meter, {
        label: 'What held the cores while you were runnable',
        help:
          'Share of the CPU that ran during your threads’ runnable-but-not-' +
          'scheduled windows: your own threads versus other processes. Colours ' +
          'are roles, not a good/bad scale.',
        primary: meterReadout(selfPct, ' was your own threads'),
        bar,
        legend,
      }),
    ],
  );
}
