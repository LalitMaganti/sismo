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

// L3 — "Who or what was making you wait?" The privileged-vs-context payoff: of
// the time your threads were runnable but not scheduled, which context process
// held a core instead. Reuses the tested loadLatencyDetail blame query; this is
// a compact summary that hands off to the full "Who it waited on" tab.

import m from 'mithril';
import type {LatencyDetail} from '../cpu_data';
import {fmtPercent} from '../format';
import {questionBlock} from '../cpu/block';
import {Meter, meterReadout, type MeterColor} from '../../dev.perfetto.SismoWidgets/meter';

const QUESTION = 'Who or what was making you wait?';
const DESCRIPTION =
  'Of the time your threads were runnable but not scheduled, this attributes ' +
  'each slice to whatever context process held a core instead.';

export function renderBlameBlock(
  d: LatencyDetail,
  onNavigate: (tab: string) => void,
): m.Children {
  if (!d.hasPriv) {
    return questionBlock({
      question: QUESTION,
      description: DESCRIPTION,
      answer:
        'Record with `sismo record` to tag the processes you’re profiling — ' +
        'then this attributes your scheduling delay to whatever ran instead.',
    });
  }

  const rows = d.blame;
  const total = rows.reduce((a, r) => a + Number(r.blockedNs), 0);
  if (rows.length === 0 || total === 0) {
    return questionBlock({
      question: QUESTION,
      description: DESCRIPTION,
      answer:
        'Nothing held a core while your threads were runnable — they got a CPU ' +
        'as soon as they were ready.',
    });
  }

  const sorted = [...rows].sort((a, b) => Number(b.blockedNs) - Number(a.blockedNs));
  const top = sorted.slice(0, 3);
  const topNs = top.reduce((a, r) => a + Number(r.blockedNs), 0);
  const otherNs = total - topNs;
  const topFrac = Number(top[0].blockedNs) / total;
  const colors: MeterColor[] = ['primary', 'secondary', 'info'];

  const bar = [
    ...top.map((r, i) => ({color: colors[i], frac: Number(r.blockedNs) / total})),
    ...(otherNs > 0 ? [{color: 'idle' as MeterColor, frac: otherNs / total}] : []),
  ];
  const legend = [
    ...top.map((r, i) => ({
      color: colors[i],
      label: r.name,
      value: fmtPercent(Number(r.blockedNs) / total, 0),
    })),
    ...(otherNs > 0
      ? [
          {
            color: 'idle' as MeterColor,
            label: `${rows.length - top.length} other context processes`,
            value: fmtPercent(otherNs / total, 0),
          },
        ]
      : []),
  ];

  return questionBlock(
    {
      question: QUESTION,
      description: DESCRIPTION,
      answer:
        `For ${fmtPercent(topFrac, 0)} of the CPU time you lost while ` +
        `runnable, "${top[0].name}" was running instead — a context process.`,
      deeper: {label: 'Who it waited on', onclick: () => onNavigate('who')},
    },
    [
      m(Meter, {
        label: 'Held a core while you were runnable',
        help:
          'For each context process: its share of the CPU time it held while ' +
          'one of your threads was runnable but waiting. Colours are roles, ' +
          'not a good/bad scale.',
        primary: meterReadout(fmtPercent(topFrac, 0), ` was "${top[0].name}"`),
        bar,
        legend,
      }),
    ],
  );
}
