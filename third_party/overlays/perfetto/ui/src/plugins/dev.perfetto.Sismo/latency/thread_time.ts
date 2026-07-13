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

// The Latency landing's first two blocks — both read the one thread-state
// triage summary (loadCpuTriage), so they share a loader:
//   L1 "Is it busy, or waiting?"  — the on-CPU vs off-CPU split, the router.
//   L2 "What was it waiting for?"  — of the off-CPU time, the kind of wait.
// Rendering only; the loader + meters are the shared triage_meters pieces.

import type m from 'mithril';
import type {Trace} from '../../../public/trace';
import type {CpuTriage} from '../cpu_data';
import {goToSismoDomain} from '../page_common';
import {fmtPercent} from '../format';
import {questionBlock, type DeeperAction} from '../cpu/block';
import {
  renderOffCpuBreakdownMeter,
  renderOnOffCpuMeter,
  triageShares,
} from '../views/triage_meters';

// L1 — the router. States the on/off-CPU split and sends you back to CPU if the
// time was mostly on-core; the deeper link opens the per-thread breakdown.
export function renderLatencyTriageBlock(
  trace: Trace,
  d: CpuTriage,
  scope: string,
  onNavigate: (tab: string) => void,
  // The busiest on-CPU function, so the overview names WHAT was running, not
  // just how much (mirrors the CPU section's function-first framing).
  topFn?: {name: string; share: number},
): m.Children {
  const s = triageShares(d);
  const off = s.offCpu ?? 0;
  const onPct = fmtPercent(s.onCpu, 0);
  const offPct = fmtPercent(s.offCpu, 0);
  const base =
    off >= 0.5
      ? `${offPct} of the wall-clock was spent off-CPU — this is mostly a ` +
        'waiting problem. The blocks below break the wait down.'
      : off <= 0.1
        ? `Almost all the time was on the CPU (${onPct}) — this is really a ` +
          'compute story; the CPU section breaks down where it went.'
        : `${onPct} running on the CPU, ${offPct} waiting off it.`;
  const answer =
    topFn !== undefined && (s.onCpu ?? 0) > 0.05
      ? `${base} Of the running time, ${fmtPercent(topFn.share, 0)} was in ` +
        `"${topFn.name}".`
      : base;

  // Always offer the per-thread breakdown; add the reciprocal CPU hand-off when
  // a meaningful share was on-core (mirrors CPU triage's link over to Latency).
  const deeper: DeeperAction[] = [
    {
      label: 'Where the wait went',
      onclick: () => onNavigate('where'),
    },
    ...(1 - off >= 0.2
      ? [
          {
            label: 'Open the CPU section',
            icon: 'open_in_new',
            onclick: () => goToSismoDomain(trace, 'cpu'),
          },
        ]
      : []),
  ];

  return questionBlock(
    {
      question: 'Is it slow because it’s busy, or because it’s waiting?',
      description:
        'Splits each thread’s wall-clock into time running on a CPU versus ' +
        'off-CPU — waiting.',
      answer,
      deeper,
    },
    [renderOnOffCpuMeter(d, scope)],
  );
}

// L2 — of the off-CPU time, the kind of wait (waiting for a core / blocked on
// I/O / benign sleep / other).
export function renderWaitKindBlock(
  d: CpuTriage,
  scope: string,
  onNavigate: (tab: string) => void,
): m.Children {
  const s = triageShares(d);
  const waitPct = fmtPercent(s.waiting, 0);
  const sleepBlockedFrac = (s.sleeping ?? 0) + (s.blocked ?? 0);
  const answer =
    sleepBlockedFrac >= (s.waiting ?? 0)
      ? 'Most of the wait was blocked or asleep — on I/O, a lock, or an event. ' +
        `Another ${waitPct} was runnable but not scheduled — ready to run, but ` +
        'the machine was busy.'
      : `${waitPct} of the off-CPU time was spent runnable but not scheduled — ` +
        'ready to run, but a core was busy with something else.';

  return questionBlock(
    {
      question: 'What was it waiting for?',
      description:
        'Groups the off-CPU time by scheduler state — the kind of wait, not ' +
        'yet the exact call.',
      answer,
      deeper: {
        label: 'Where the wait went',
        onclick: () => onNavigate('where'),
      },
    },
    [renderOffCpuBreakdownMeter(d, scope)],
  );
}
