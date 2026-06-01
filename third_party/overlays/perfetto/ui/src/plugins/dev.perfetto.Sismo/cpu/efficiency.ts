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

// Block 4 — "How efficiently did the CPU run?" Vital-sign scorecards (IPC, cache
// and branch miss rates) plus the bottom-up per-function table: the hottest
// functions and their work-per-cycle, so you can sort to find what's both hot
// and slow. When no counters were recorded this folds to one honest line. The
// full Top-Down breakdown is the Efficiency tab.

import m from 'mithril';
import type {Engine} from '../../../trace_processor/engine';
import {computeTma, loadMicroarchCounters} from '../cpu_data';
import {renderStatCard, type StatCard} from '../page_common';
import type {PrivilegedSet} from '../privileged_set';
import {questionBlock} from './block';
import {breakdownGrid, type BreakdownGridRow} from './grid';

const TOP_N = 8;

export interface EfficiencySummary {
  readonly hasCounters: boolean;
  readonly ipc: number | null;
  readonly cacheMpki: number | null;
  readonly branchMpki: number | null;
  // Plain-language phrase for where most cycles went, or null.
  readonly dominantPlain: string | null;
  // Hottest functions; value is IPC (-1 when too few samples to derive), share
  // is the function's fraction of sampled on-CPU time.
  readonly byFunction: ReadonlyArray<BreakdownGridRow>;
}

const QUESTION = 'How efficiently did the CPU run?';

// Plain mechanism for each Top-Down bucket — what the cycles were physically
// doing, not whether that is good or bad.
function plainBucket(key: string): string {
  switch (key) {
    case 'retiring':
    case 'not-stalled':
      return 'computing useful work';
    case 'frontend':
      return 'fetching instructions';
    case 'backend':
      return 'waiting on memory or execution units';
    case 'bad-spec':
      return 'on work thrown away after mispredicted branches';
    default:
      return key;
  }
}

export async function loadEfficiencySummary(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<EfficiencySummary> {
  // The loader sorts (by cycles) and limits in SQL, so the rows arrive already
  // ranked and capped — no JS sort/slice.
  const mc = await loadMicroarchCounters(engine, priv, TOP_N);
  if (mc.state !== 'ok') {
    return {
      hasCounters: false,
      ipc: null,
      cacheMpki: null,
      branchMpki: null,
      dominantPlain: null,
      byFunction: [],
    };
  }
  const tma = computeTma(mc.roles);
  const total = mc.totalSamples > 0 ? mc.totalSamples : 1;
  const byFunction = mc.perFunc.map((f) => ({
    name: f.name,
    value: f.tma?.ipc ?? -1,
    share: f.samples / total,
  }));
  return {
    hasCounters: true,
    ipc: tma?.ipc ?? null,
    cacheMpki: tma?.cacheMpki ?? null,
    branchMpki: tma?.branchMpki ?? null,
    dominantPlain: tma?.dominant != null ? plainBucket(tma.dominant.key) : null,
    byFunction,
  };
}

export function renderEfficiencyBlock(s: EfficiencySummary): m.Children {
  if (!s.hasCounters) {
    return questionBlock({
      question: QUESTION,
      answer:
        'No CPU performance counters were recorded, so efficiency can’t be ' +
        'measured here. Re-record with counters enabled to see it.',
    });
  }
  if (s.ipc === null) {
    return questionBlock({
      question: QUESTION,
      answer:
        'Counters were recorded, but there weren’t enough to compute ' +
        'instructions-per-cycle for this scope.',
    });
  }
  const answer =
    `Completed about ${s.ipc.toFixed(1)} instructions per CPU cycle` +
    (s.dominantPlain !== null
      ? `; most cycles went to ${s.dominantPlain}.`
      : '.');
  const cards: StatCard[] = [
    {label: 'IPC', value: s.ipc.toFixed(2), help: 'Instructions per CPU cycle'},
  ];
  if (s.cacheMpki !== null) {
    cards.push({
      label: 'Cache miss/1k',
      value: s.cacheMpki.toFixed(1),
      help: 'Cache misses per 1,000 instructions',
    });
  }
  if (s.branchMpki !== null) {
    cards.push({
      label: 'Branch miss/1k',
      value: s.branchMpki.toFixed(1),
      help: 'Branch mispredictions per 1,000 instructions',
    });
  }
  return questionBlock({question: QUESTION, answer}, [
    m('.pf-sismo-page__stat-row', cards.map(renderStatCard)),
    breakdownGrid({
      nameTitle: 'Function',
      valueTitle: 'IPC',
      formatValue: (n) => (n >= 0 ? n.toFixed(2) : '—'),
      rows: s.byFunction,
    }),
  ]);
}
