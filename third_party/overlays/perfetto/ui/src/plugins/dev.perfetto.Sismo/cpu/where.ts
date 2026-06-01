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

// Block 1 — "How much CPU did you use, and where did it go?" The magnitude, then
// where it went three ways: by function (the bottom-up view), by process and by
// thread. Each as a table where every row carries its absolute AND its share, so
// a percentage is never floating free of its denominator. The full drill is Tab
// A; here we show enough to point.

import m from 'mithril';
import type {Engine} from '../../../trace_processor/engine';
import {LONG} from '../../../trace_processor/query_result';
import type {PrivilegedSet} from '../privileged_set';
import {
  loadCpuTotals,
  loadHeaviestFunctions,
  loadThreadRows,
} from '../cpu_data';
import {fmtDurationNs, fmtPercent} from '../format';
import {renderStatCard, type StatCard} from '../page_common';
import {questionBlock, subSection} from './block';
import {breakdownGrid, type BreakdownGridRow} from './grid';

export interface WhereSummary {
  readonly cpuUsedNs: number;
  readonly wallNs: number;
  // Thread rows carry their process in `group`.
  readonly byThread: ReadonlyArray<BreakdownGridRow>;
  readonly byFunction: ReadonlyArray<BreakdownGridRow>;
}

const QUESTION = 'How much CPU did you use, and where did it go?';
const TOP_N = 6;

export async function loadWhereSummary(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<WhereSummary> {
  const hasPriv = priv.upids.length > 0;
  const kind = hasPriv ? 'privileged' : 'context';
  const totals = await loadCpuTotals(engine, priv);
  const cpuUsedNs = Number(
    hasPriv && totals.privilegedNs !== null
      ? totals.privilegedNs
      : totals.totalNs,
  );
  const denom = cpuUsedNs > 0 ? cpuUsedNs : 1;

  const wb = await engine.query(
    'SELECT (end_ts - start_ts) AS dur FROM trace_bounds',
  );
  const wallNs = Number(wb.firstRow({dur: LONG}).dur);

  const threads = await loadThreadRows(engine, priv, kind, TOP_N);
  const fns = await loadHeaviestFunctions(engine, priv, TOP_N);

  return {
    cpuUsedNs,
    wallNs,
    byThread: threads.map((t) => {
      const ns = Number(t.runtimeNs);
      return {
        name: t.threadName,
        value: ns,
        share: ns / denom,
        group: t.processName ?? '—',
      };
    }),
    // Functions are sampled; turn the sample share into an approximate absolute
    // so the row still anchors its percentage to a time.
    byFunction: fns.map((f) => ({
      name: f.name,
      value: f.share * cpuUsedNs,
      share: f.share,
    })),
  };
}

export function renderWhereBlock(s: WhereSummary): m.Children {
  const cards: StatCard[] = [
    {label: 'CPU used', value: fmtDurationNs(s.cpuUsedNs)},
    {label: 'Wall window', value: fmtDurationNs(s.wallNs)},
  ];
  if (s.byFunction.length > 0) {
    cards.push({
      label: 'Busiest function',
      value: fmtPercent(s.byFunction[0].share),
      help: s.byFunction[0].name,
    });
  }
  return questionBlock({question: QUESTION}, [
    m('.pf-sismo-page__stat-row', cards.map(renderStatCard)),
    subSection(
      'By function',
      breakdownGrid({
        nameTitle: 'Function',
        valueTitle: 'CPU time',
        formatValue: fmtDurationNs,
        rows: s.byFunction,
      }),
    ),
    subSection(
      'By thread',
      breakdownGrid({
        nameTitle: 'Thread',
        groupTitle: 'Process',
        valueTitle: 'CPU time',
        formatValue: fmtDurationNs,
        rows: s.byThread,
      }),
    ),
  ]);
}
