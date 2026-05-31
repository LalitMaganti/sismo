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

// CPU "Cores" tab: per-core breakdown — how busy each core was (your work vs
// the rest) and the frequency it ran at, grouped by cluster on big/little SoCs.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {Section} from '../../../widgets/section';
import {Card} from '../../../widgets/card';
import {Grid, GridCell, GridHeaderCell} from '../../../widgets/grid';
import {EmptyState} from '../../../widgets/empty_state';
import type {CpuCoreRow, CpuSummary} from '../cpu_data';
import {MeterBar} from '../../dev.perfetto.SismoWidgets/meter';
import {fmtDuration, fmtFreqKhz, fmtMegacycles, fmtPercent} from '../format';

export function renderCpuCores(
  trace: Trace,
  summary: CpuSummary,
  rows: CpuCoreRow[],
): m.Children {
  if (rows.length === 0) {
    return m(
      Section,
      {
        title: 'Per-core breakdown',
        subtitle: 'How busy each core was and at what frequency.',
      },
      m(EmptyState, {icon: 'memory', title: 'No per-core data'}),
    );
  }
  const walltime = summary.walltimeNs !== null ? Number(summary.walltimeNs) : 0;
  const hasPriv = rows.some((r) => r.privilegedRuntimeNs !== null);
  const clusters = groupCoresByCluster(rows);
  const subtitle =
    clusters.length > 1
      ? 'Cores grouped by cluster. Per core: how busy it was (your work vs the ' +
        'rest) and the frequency it ran at.'
      : 'Per core: how busy it was (your work vs the rest) and the frequency it ' +
        'ran at.';
  return m(
    Section,
    {title: 'Per-core breakdown', subtitle},
    clusters.map((cl) =>
      m(
        '.pf-sismo-page__tab-pane',
        clusters.length > 1 && m('.pf-sismo-page__tab-pane-label', cl.label),
        renderCoreTable(trace, cl.cores, walltime, hasPriv),
      ),
    ),
  );
}

interface CoreCluster {
  readonly label: string;
  readonly cores: CpuCoreRow[];
}

// Groups cores by cluster_id and labels clusters performance/efficiency when
// they're distinguishable (distinct capacities, or failing that distinct peak
// frequencies). Falls back to a single "All cores" group on uniform SoCs.
function groupCoresByCluster(rows: CpuCoreRow[]): CoreCluster[] {
  const byId = new Map<number, CpuCoreRow[]>();
  for (const r of rows) {
    const id = r.clusterId ?? 0;
    const bucket = byId.get(id);
    if (bucket === undefined) byId.set(id, [r]);
    else bucket.push(r);
  }
  if (byId.size <= 1) {
    return [{label: `All cores (${rows.length})`, cores: rows}];
  }
  const groups = [...byId.values()].map((cores) => ({
    cores,
    cap: Math.max(...cores.map((c) => c.capacity ?? 0)),
    freq: Math.max(
      ...cores.map((c) => (c.maxFreqKhz !== null ? Number(c.maxFreqKhz) : 0)),
    ),
  }));
  const caps = new Set(groups.map((g) => g.cap));
  const freqs = new Set(groups.map((g) => g.freq));
  const byCap = caps.size > 1 && !caps.has(0);
  const byFreq = !byCap && freqs.size > 1 && !freqs.has(0);
  const rankable = byCap || byFreq;
  groups.sort((a, b) => (byCap ? b.cap - a.cap : b.freq - a.freq));
  return groups.map((g, i) => {
    const n = g.cores.length;
    let label: string;
    if (!rankable) label = `Cluster ${g.cores[0].clusterId ?? i} (${n} cores)`;
    else if (i === 0) label = `Performance cores (${n})`;
    else if (i === groups.length - 1) label = `Efficiency cores (${n})`;
    else label = `Cluster ${g.cores[0].clusterId ?? i} (${n} cores)`;
    return {label, cores: g.cores};
  });
}

function renderCoreTable(
  trace: Trace,
  cores: ReadonlyArray<CpuCoreRow>,
  walltime: number,
  hasPriv: boolean,
): m.Children {
  const data = cores.map((r) => {
    const runtime = Number(r.runtimeNs ?? 0n);
    const priv = Number(r.privilegedRuntimeNs ?? 0n);
    const busyFrac = walltime > 0 ? runtime / walltime : 0;
    const privFrac = runtime > 0 ? Math.max(0, Math.min(1, priv / runtime)) : 0;
    return [
      m(GridCell, `CPU ${r.cpu}`),
      m(GridCell, {align: 'right'}, fmtDuration(trace, r.runtimeNs ?? 0n)),
      m(GridCell, {align: 'right'}, fmtPercent(busyFrac)),
      m(GridCell, renderCoreBar(busyFrac, privFrac, hasPriv)),
      m(GridCell, {align: 'right'}, fmtFreqKhz(r.avgFreqKhz)),
      m(GridCell, {align: 'right'}, fmtFreqKhz(r.maxFreqKhz)),
      m(GridCell, {align: 'right'}, fmtMegacycles(r.megacycles)),
    ];
  });
  return m(
    Card,
    {className: 'pf-sismo-page__table-card'},
    m(Grid, {
      columns: [
        {key: 'core', header: m(GridHeaderCell, 'Core')},
        {key: 'busy', header: m(GridHeaderCell, 'Busy')},
        {key: 'pct', header: m(GridHeaderCell, '% busy')},
        {key: 'bar', header: m(GridHeaderCell, '')},
        {key: 'avg', header: m(GridHeaderCell, 'Avg freq')},
        {key: 'peak', header: m(GridHeaderCell, 'Peak freq')},
        {key: 'cyc', header: m(GridHeaderCell, 'Cycles')},
      ],
      rowData: data,
    }),
  );
}

// Busy fraction of the core, split into your work (blue) vs the rest (amber);
// the unfilled remainder reads as idle.
function renderCoreBar(
  busyFrac: number,
  privFrac: number,
  hasPriv: boolean,
): m.Children {
  const busy = Math.max(0, Math.min(1, busyFrac));
  return m(MeterBar, {
    segments: hasPriv
      ? [
          {color: 'primary', frac: busy * privFrac},
          {color: 'secondary', frac: busy * (1 - privFrac)},
        ]
      : [{color: 'primary', frac: busy}],
  });
}
