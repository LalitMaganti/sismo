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
// the rest), how it was spread over time, and the contention on it (threads
// sharing it, migrations onto it), grouped by cluster on big/little SoCs.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {QuerySlot, SerialTaskQueue} from '../../../base/query_slot';
import {Section} from '../../../widgets/section';
import {Card} from '../../../widgets/card';
import {Anchor} from '../../../widgets/anchor';
import {Grid, GridCell, GridHeaderCell} from '../../../widgets/grid';
import {EmptyState} from '../../../widgets/empty_state';
import type {
  CoreContentionRow,
  CoreSeries,
  CoreThreadDetail,
  CpuCoreRow,
  CpuSummary,
  FocusWindow,
} from '../cpu_data';
import {
  loadCoreContention,
  loadCoreSeries,
  loadCoreThreads,
  loadPerCore,
} from '../cpu_data';
import type {PrivilegedSet} from '../privileged_set';
import {MeterBar} from '../../dev.perfetto.SismoWidgets/meter';
import {
  actionHandler,
  renderStatCard,
  renderThreadLink,
  revealInTimeline,
  type StatCard,
} from '../page_common';
import {clamp01, fmtCount, fmtDuration, fmtPercent} from '../format';

// Per-core drill state threaded into the render: which core's "what ran here"
// detail is open, the loaded per-core threads (your set + an "others" total),
// and the toggle callback.
interface CoreDrill {
  readonly threads: Map<number, CoreThreadDetail>;
  readonly expandedCpu: number | null;
  readonly onToggle: (cpu: number) => void;
}

// Class component wrapper: loads the per-core utilisation time-series (for the
// inline sparklines) and the contention signals (threads sharing the core,
// migrations onto it), re-rendering as each lands. The aggregate table renders
// immediately; the extra columns fill in once their queries resolve.
export interface CpuCoresViewAttrs {
  readonly trace: Trace;
  readonly summary: CpuSummary;
  readonly perCore: CpuCoreRow[];
  readonly priv: PrivilegedSet;
  // The shared focus window; when set, per-core busy time, sparklines,
  // contention and the drill are all recomputed for that region.
  readonly focus?: FocusWindow;
}

export class CpuCoresView implements m.ClassComponent<CpuCoresViewAttrs> {
  // Each signal is its own QuerySlot, re-keyed on {upids, focus window}: change
  // the focus and they all re-fetch, with stale results dropped by the slot. The
  // aggregate table renders as soon as perCore lands; the sparkline / contention
  // / drill columns fill in as their slots resolve (each .data is undefined until
  // it does).
  private readonly queue = new SerialTaskQueue();
  private readonly perCoreSlot = new QuerySlot<CpuCoreRow[]>(this.queue);
  private readonly seriesSystemSlot = new QuerySlot<CoreSeries>(this.queue);
  private readonly seriesMineSlot = new QuerySlot<CoreSeries>(this.queue);
  private readonly contentionSlot = new QuerySlot<
    Map<number, CoreContentionRow>
  >(this.queue);
  private readonly coreThreadsSlot = new QuerySlot<
    Map<number, CoreThreadDetail>
  >(this.queue);
  private expandedCpu: number | null = null;
  // Utilisation basis. Defaults to your work when there's a profiled set; set
  // once on first render (there's no in-view toggle).
  private scope?: 'mine' | 'system';

  onremove(): void {
    this.perCoreSlot.dispose();
    this.seriesSystemSlot.dispose();
    this.seriesMineSlot.dispose();
    this.contentionSlot.dispose();
    this.coreThreadsSlot.dispose();
  }

  view({attrs}: m.CVnode<CpuCoresViewAttrs>): m.Children {
    const {trace, priv, focus} = attrs;
    const hasPriv = priv.upids.length > 0;
    this.scope ??= hasPriv ? 'mine' : 'system';
    const upids = [...priv.upids];

    // Per-core runtimes: the preloaded whole-trace rows when unfocused, else a
    // windowed reload keyed on the focus.
    let perCore: CpuCoreRow[] | undefined;
    if (focus === undefined) {
      perCore = attrs.perCore;
    } else {
      try {
        perCore = this.perCoreSlot.use({
          key: {upids, focus},
          queryFn: () => loadPerCore(trace.engine, priv, focus),
        }).data;
      } catch {
        perCore = [];
      }
    }

    let seriesSystem: CoreSeries | undefined;
    try {
      seriesSystem = this.seriesSystemSlot.use({
        key: {focus: focus ?? null},
        queryFn: () => loadCoreSeries(trace.engine, undefined, undefined, focus),
      }).data;
    } catch {
      seriesSystem = {numBuckets: 0, byCpu: new Map()};
    }

    let seriesMine: CoreSeries | undefined;
    if (hasPriv) {
      try {
        seriesMine = this.seriesMineSlot.use({
          key: {upids, focus: focus ?? null},
          queryFn: () => loadCoreSeries(trace.engine, priv, undefined, focus),
        }).data;
      } catch {
        seriesMine = undefined;
      }
    }

    let contention: Map<number, CoreContentionRow> | undefined;
    try {
      contention = this.contentionSlot.use({
        key: {focus: focus ?? null},
        queryFn: () => loadCoreContention(trace.engine, focus),
      }).data;
    } catch {
      contention = undefined;
    }

    let coreThreads: Map<number, CoreThreadDetail> | undefined;
    try {
      coreThreads = this.coreThreadsSlot.use({
        key: {upids, focus: focus ?? null},
        queryFn: () => loadCoreThreads(trace.engine, priv, undefined, focus),
      }).data;
    } catch {
      coreThreads = undefined;
    }

    const drill: CoreDrill = {
      threads: coreThreads ?? new Map(),
      expandedCpu: this.expandedCpu,
      onToggle: (cpu) => {
        this.expandedCpu = this.expandedCpu === cpu ? null : cpu;
        m.redraw();
      },
    };
    const series = this.scope === 'mine' ? seriesMine : seriesSystem;
    if (perCore === undefined) {
      return m(
        Section,
        {title: 'Per-core breakdown', subtitle: 'Loading…'},
        m(EmptyState, {icon: 'hourglass_empty', title: 'Loading cores…'}),
      );
    }
    // When focused, the per-core utilisation denominator is the window span, not
    // the whole-trace walltime.
    const summary =
      attrs.focus === undefined
        ? attrs.summary
        : {...attrs.summary, walltimeNs: attrs.focus.end - attrs.focus.start};
    return renderCpuCores(
      attrs.trace,
      summary,
      perCore,
      series,
      contention,
      drill,
      this.scope === 'mine',
    );
  }
}

export function renderCpuCores(
  trace: Trace,
  summary: CpuSummary,
  rows: CpuCoreRow[],
  series?: CoreSeries,
  contention?: Map<number, CoreContentionRow>,
  drill?: CoreDrill,
  // Utilisation basis: your work only ('mine') vs the whole machine. Fixed per
  // trace (your-work when there's a profiled set, else machine-wide) — there is
  // no in-view toggle.
  mineScope = false,
): m.Children {
  if (rows.length === 0) {
    return m(
      Section,
      {
        title: 'Per-core breakdown',
        subtitle: 'How busy each core was and the contention on it.',
      },
      m(EmptyState, {icon: 'memory', title: 'No per-core data'}),
    );
  }
  const walltime = summary.walltimeNs !== null ? Number(summary.walltimeNs) : 0;
  const hasPriv = rows.some((r) => r.privilegedRuntimeNs !== null);
  const clusters = groupCoresByCluster(rows);
  const coreBusyNs = (r: CpuCoreRow): bigint =>
    (mineScope ? r.privilegedRuntimeNs : r.runtimeNs) ?? 0n;

  // Headline scorecards above the per-core breakdown, on the chosen basis.
  let busiest = 0;
  let idle = 0;
  for (const r of rows) {
    const frac = walltime > 0 ? Number(coreBusyNs(r)) / walltime : 0;
    if (frac > busiest) busiest = frac;
    if (frac < 0.01) idle++;
  }
  const whose = mineScope ? 'your work' : 'the machine';
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
      help: `Highest single-core utilisation by ${whose} (busy ÷ walltime).`,
    },
    {
      label: mineScope ? 'Cores you barely used' : 'Idle cores',
      value: `${idle}`,
      help: `Cores busy (by ${whose}) less than 1% of the walltime.`,
    },
  ];
  const lead =
    `Per core, ${mineScope ? 'how much YOUR work used it' : 'how busy it was'}` +
    ', how that was spread over time, and the contention on it' +
    (clusters.length > 1 ? ', grouped by cluster.' : '.');
  const subtitle =
    `${lead} "Threads"/"Migrations in" are machine-wide contention. The core ` +
    'name opens its timeline track; the ▸ expands what ran on it.';
  const expanded = drill?.expandedCpu ?? null;
  const busyNsOf = (cpu: number): bigint =>
    rows.find((r) => r.cpu === cpu)?.runtimeNs ?? 0n;
  return m(
    Section,
    {title: 'Per-core breakdown', subtitle},
    m('.pf-sismo-page__stat-row', cards.map(renderStatCard)),
    clusters.map((cl) =>
      m(
        '.pf-sismo-page__tab-pane',
        clusters.length > 1 && m('.pf-sismo-page__tab-pane-label', cl.label),
        renderCoreTable(
          trace,
          cl.cores,
          walltime,
          hasPriv,
          mineScope,
          series,
          contention,
          drill,
        ),
      ),
    ),
    expanded !== null &&
      renderCoreDetail(
        trace,
        expanded,
        drill?.threads.get(expanded),
        busyNsOf(expanded),
      ),
  );
}

// "What ran on CPU N" drill: YOUR top threads on the core (the focus), each as a
// share of the core's busy time and linking into the timeline; the time other
// processes spent on the core is summarised on one line, not enumerated.
function renderCoreDetail(
  trace: Trace,
  cpu: number,
  detail: CoreThreadDetail | undefined,
  coreBusyNs: bigint,
): m.Children {
  const busy = Number(coreBusyNs);
  const threads = detail?.threads ?? [];
  const othersNs = detail?.othersNs ?? 0n;
  const table =
    threads.length === 0
      ? m(EmptyState, {
          icon: 'developer_board',
          title: 'None of your threads ran on this core',
        })
      : m(
          Card,
          {className: 'pf-sismo-page__table-card'},
          m(Grid, {
            columns: [
              {key: 'thread', header: m(GridHeaderCell, 'Thread')},
              {key: 'process', header: m(GridHeaderCell, 'Process')},
              {key: 'time', header: m(GridHeaderCell, 'Time on core')},
              {key: 'share', header: m(GridHeaderCell, '% of core')},
            ],
            rowData: threads.map((t) => [
              m(
                GridCell,
                {wrap: true},
                renderThreadLink(trace, t.threadName, t.tid, t.utid),
              ),
              m(GridCell, {wrap: true}, t.processName ?? '—'),
              m(GridCell, {align: 'right'}, fmtDuration(trace, t.runtimeNs)),
              m(
                GridCell,
                {align: 'right'},
                fmtPercent(busy > 0 ? Number(t.runtimeNs) / busy : null),
              ),
            ]),
          }),
        );
  return m(
    '.pf-sismo-page__tab-pane',
    m('.pf-sismo-page__tab-pane-label', `What ran on CPU ${cpu}`),
    table,
    othersNs > 0n &&
      m(
        '.pf-sismo-page__muted',
        `Other processes used ${fmtDuration(trace, othersNs)}` +
          (busy > 0
            ? ` (${fmtPercent(Number(othersNs) / busy)} of the core).`
            : '.'),
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
  mineScope: boolean,
  series?: CoreSeries,
  contention?: Map<number, CoreContentionRow>,
  drill?: CoreDrill,
): m.Children {
  const data = cores.map((r) => {
    const runtime = Number(r.runtimeNs ?? 0n);
    const priv = Number(r.privilegedRuntimeNs ?? 0n);
    // In 'mine' scope the bar is all-yours at your busy fraction; in 'system'
    // it splits the core's total busy into yours vs the rest.
    const busyFrac =
      walltime > 0 ? (mineScope ? priv : runtime) / walltime : 0;
    const privFrac = mineScope
      ? 1
      : runtime > 0
        ? clamp01(priv / runtime)
        : 0;
    const c = contention?.get(r.cpu);
    const detail = drill?.threads.get(r.cpu);
    const canDrill =
      (detail?.threads.length ?? 0) > 0 || (detail?.othersNs ?? 0n) > 0n;
    return [
      m(
        GridCell,
        {
          chevron: canDrill
            ? drill?.expandedCpu === r.cpu
              ? 'expanded'
              : 'collapsed'
            : undefined,
          onChevronClick: canDrill
            ? () => drill?.onToggle(r.cpu)
            : undefined,
        },
        m(
          Anchor,
          {
            href: '#!/viewer',
            title: `Open CPU ${r.cpu} in the timeline`,
            onclick: actionHandler(() => revealInTimeline(trace, {cpus: [r.cpu]})),
          },
          `CPU ${r.cpu}`,
        ),
      ),
      m(GridCell, {align: 'right'}, fmtDuration(trace, r.runtimeNs ?? 0n)),
      m(GridCell, {align: 'right'}, fmtPercent(busyFrac)),
      m(GridCell, renderCoreBar(busyFrac, privFrac, hasPriv)),
      m(GridCell, renderSparkline(series?.byCpu.get(r.cpu))),
      m(GridCell, {align: 'right'}, c !== undefined ? fmtCount(c.threads) : '—'),
      m(
        GridCell,
        {align: 'right'},
        c !== undefined ? fmtCount(c.migrationsIn) : '—',
      ),
    ];
  });
  return m(
    Card,
    {className: 'pf-sismo-page__table-card'},
    m(Grid, {
      columns: [
        // The cell is just a short "CPU N" link, so auto-sizing floors it to the
        // grid minimum — but a chevron is added once the per-core thread slot
        // resolves, after the column width has already locked, and squeezes the
        // link. Floor the width to fit link + chevron up to "CPU NNN".
        {key: 'core', header: m(GridHeaderCell, 'Core'), minWidthPx: 110},
        {key: 'busy', header: m(GridHeaderCell, 'Busy')},
        {key: 'pct', header: m(GridHeaderCell, '% busy')},
        {key: 'bar', header: m(GridHeaderCell, '')},
        {key: 'spark', header: m(GridHeaderCell, 'Utilisation over time')},
        {key: 'threads', header: m(GridHeaderCell, 'Threads')},
        {key: 'mig', header: m(GridHeaderCell, 'Migrations in')},
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
  const busy = clamp01(busyFrac);
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
