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
import {Anchor} from '../../../widgets/anchor';
import {Grid, GridCell, GridHeaderCell} from '../../../widgets/grid';
import {EmptyState} from '../../../widgets/empty_state';
import type {CoreSeries, CpuCoreRow, CpuSummary} from '../cpu_data';
import {loadCoreSeries} from '../cpu_data';
import {MeterBar} from '../../dev.perfetto.SismoWidgets/meter';
import {renderStatCard, revealInTimeline, type StatCard} from '../page_common';
import {fmtDuration, fmtPercent} from '../format';

// Class component wrapper: loads the per-core utilisation time-series (for the
// inline sparklines) and re-renders when it lands. The aggregate per-core table
// renders immediately; the sparkline column fills in once the series resolves.
export interface CpuCoresViewAttrs {
  readonly trace: Trace;
  readonly summary: CpuSummary;
  readonly perCore: CpuCoreRow[];
}

export class CpuCoresView implements m.ClassComponent<CpuCoresViewAttrs> {
  private series?: CoreSeries;

  oninit({attrs}: m.CVnode<CpuCoresViewAttrs>): void {
    loadCoreSeries(attrs.trace.engine)
      .then((s) => {
        this.series = s;
        m.redraw();
      })
      .catch(() => {
        this.series = {numBuckets: 0, byCpu: new Map()};
        m.redraw();
      });
  }

  view({attrs}: m.CVnode<CpuCoresViewAttrs>): m.Children {
    return renderCpuCores(attrs.trace, attrs.summary, attrs.perCore, this.series);
  }
}

export function renderCpuCores(
  trace: Trace,
  summary: CpuSummary,
  rows: CpuCoreRow[],
  series?: CoreSeries,
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

  // Headline scorecards above the per-core breakdown.
  let busiest = 0;
  let idle = 0;
  for (const r of rows) {
    const frac = walltime > 0 ? Number(r.runtimeNs ?? 0n) / walltime : 0;
    if (frac > busiest) busiest = frac;
    if (frac < 0.01) idle++;
  }
  const cards: StatCard[] = [
    {
      label: 'Cores',
      value:
        summary.numClusters > 1
          ? `${summary.numCpus} · ${summary.numClusters} clusters`
          : `${summary.numCpus}`,
      help: 'Logical CPUs seen in the trace.',
    },
    {
      label: 'Busiest core',
      value: fmtPercent(busiest),
      help: 'Highest single-core utilisation (busy time ÷ walltime).',
    },
    {
      label: 'Idle cores',
      value: `${idle}`,
      help: 'Cores busy less than 1% of the walltime.',
    },
  ];
  const lead =
    clusters.length > 1
      ? 'Cores grouped by cluster. Per core: how busy it was (your work vs the ' +
        'rest) and the frequency it ran at.'
      : 'Per core: how busy it was (your work vs the rest) and the frequency it ' +
        'ran at.';
  const subtitle = `${lead} Click a core to open its track in the timeline.`;
  return m(
    Section,
    {title: 'Per-core breakdown', subtitle},
    m('.pf-sismo-page__stat-row', cards.map(renderStatCard)),
    clusters.map((cl) =>
      m(
        '.pf-sismo-page__tab-pane',
        clusters.length > 1 && m('.pf-sismo-page__tab-pane-label', cl.label),
        renderCoreTable(trace, cl.cores, walltime, hasPriv, series),
      ),
    ),
  );
}

interface CoreCluster {
  readonly label: string;
  readonly cores: CpuCoreRow[];
}

// Groups cores by cluster_id and labels clusters performance/efficiency when
// their relative capacities distinguish them. Falls back to a single "All
// cores" group on uniform SoCs.
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
  }));
  const caps = new Set(groups.map((g) => g.cap));
  const rankable = caps.size > 1 && !caps.has(0);
  groups.sort((a, b) => b.cap - a.cap);
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
  series?: CoreSeries,
): m.Children {
  const data = cores.map((r) => {
    const runtime = Number(r.runtimeNs ?? 0n);
    const priv = Number(r.privilegedRuntimeNs ?? 0n);
    const busyFrac = walltime > 0 ? runtime / walltime : 0;
    const privFrac = runtime > 0 ? Math.max(0, Math.min(1, priv / runtime)) : 0;
    return [
      m(
        GridCell,
        m(
          Anchor,
          {
            href: '#!/viewer',
            title: `Open CPU ${r.cpu} in the timeline`,
            onclick: (e: Event) => {
              e.preventDefault();
              revealInTimeline(trace, {cpus: [r.cpu]});
            },
          },
          `CPU ${r.cpu}`,
        ),
      ),
      m(GridCell, {align: 'right'}, fmtDuration(trace, r.runtimeNs ?? 0n)),
      m(GridCell, {align: 'right'}, fmtPercent(busyFrac)),
      m(GridCell, renderCoreBar(busyFrac, privFrac, hasPriv)),
      m(GridCell, renderSparkline(series?.byCpu.get(r.cpu))),
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
        {key: 'spark', header: m(GridHeaderCell, 'Utilisation over time')},
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

// Inline utilisation-over-time sparkline: one thin bar per time-bucket, height
// = that bucket's busy fraction. Empty until the series resolves (or when a
// core has no slices). Each bar is at least a sliver so non-zero reads.
function renderSparkline(fracs: number[] | undefined): m.Children {
  if (fracs === undefined || fracs.length === 0) return undefined;
  return m(
    '.pf-sismo-spark',
    fracs.map((f) =>
      m('.pf-sismo-spark__bar', {
        style: {height: `${Math.max(3, Math.min(1, f) * 100)}%`},
      }),
    ),
  );
}
