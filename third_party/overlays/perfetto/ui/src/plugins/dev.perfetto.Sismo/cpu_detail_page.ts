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

import m from 'mithril';
import type {Trace} from '../../public/trace';
import {Section} from '../../widgets/section';
import {Card} from '../../widgets/card';
import {Grid, GridCell, GridHeaderCell} from '../../widgets/grid';
import {EmptyState} from '../../widgets/empty_state';
import {Callout} from '../../widgets/callout';
import {Intent} from '../../widgets/common';
import {Anchor} from '../../widgets/anchor';
import {Button, ButtonVariant} from '../../widgets/button';
import {Icon} from '../../widgets/icon';
import {Tooltip} from '../../widgets/tooltip';
import {Tabs} from '../../widgets/tabs';
import {
  goToTimeline,
  renderPrivilegedBanner,
  renderProcessLink,
  renderThreadLink,
} from './page_common';
import {
  loadCpuDetail,
  type CpuCoreRow,
  type CpuDetail,
  type CpuProcessRow,
  type CpuSummary,
  type CpuThreadRow,
  type HotMappingRow,
  type HotSymbolRow,
  type MicroarchData,
} from './cpu_data';
import {
  fmtCount,
  fmtDuration,
  fmtFreqKhz,
  fmtMegacycles,
  fmtMegacyclesNum,
  fmtPercent,
} from './format';
import type {PrivilegedSet} from './privileged_set';

export interface CpuDetailPageAttrs {
  readonly trace: Trace;
  readonly privileged: PrivilegedSet;
}

export class CpuDetailPage implements m.ClassComponent<CpuDetailPageAttrs> {
  private data?: CpuDetail;
  private error?: string;
  private consumersTab: 'processes' | 'threads' = 'processes';

  oninit({attrs}: m.CVnode<CpuDetailPageAttrs>) {
    this.load(attrs.trace, attrs.privileged);
  }

  view({attrs}: m.CVnode<CpuDetailPageAttrs>) {
    return m(
      '.pf-sismo-page',
      m(
        '.pf-sismo-page__inner',
        m(
          '.pf-sismo-page__header',
          m(
            '.pf-sismo-page__breadcrumbs',
            m(Anchor, {href: '#!/sismo', startIcon: 'arrow_back'}, 'Overview'),
            ' / CPU',
          ),
          m(
            '.pf-sismo-page__header-row',
            m('h1.pf-sismo-page__title', 'CPU usage'),
            m(Button, {
              label: 'Open timeline',
              icon: 'timeline',
              variant: ButtonVariant.Filled,
              onclick: () => goToTimeline(attrs.trace),
            }),
          ),
          m(
            '.pf-sismo-page__subtitle',
            'Where the cores went: per-CPU breakdown, top consumers, frequencies and idle states. Click any process or thread to jump to it on the timeline.',
          ),
          renderPrivilegedBanner(attrs.privileged),
        ),
        m('.pf-sismo-page__body', this.renderBody(attrs.trace)),
      ),
    );
  }

  private renderBody(trace: Trace): m.Children {
    if (this.error !== undefined) {
      return m(
        Callout,
        {icon: 'error', intent: Intent.Danger},
        this.error,
      );
    }
    if (this.data === undefined) {
      return m(EmptyState, {
        icon: 'hourglass_empty',
        title: 'Loading CPU details…',
      });
    }
    const d = this.data;
    if (!d.summary.hasSched) {
      return m(
        Callout,
        {icon: 'info', intent: Intent.Primary},
        'This trace contains no scheduling data, so there is nothing to break down. Re-record with ftrace + sched data sources to enable CPU analysis.',
      );
    }
    return [
      this.renderHeadline(trace, d.summary),
      this.renderPerCore(trace, d.summary, d.perCore),
      this.renderConsumers(trace, d),
      this.renderMicroarch(d.microarch),
    ];
  }

  private renderHeadline(trace: Trace, s: CpuSummary): m.Children {
    const meters: m.Children[] = [];
    // Cycle budget needs cpufreq data to compute the peak-frequency denominator.
    // Without it we can still show the concurrency and parallelism meters,
    // which only need sched.
    if (s.peakMegacycles !== null && s.megacycles !== null) {
      meters.push(renderCycleBudgetMeter(s));
    }
    meters.push(renderConcurrencyMeter(s));
    if (s.privilegedConcurrency !== null) {
      meters.push(renderParallelismMeter(s));
    }

    // Secondary stat row: orientation facts that don't need a meter.
    const cards: HeadlineCard[] = [
      {
        label: 'Walltime',
        value: fmtDuration(trace, s.walltimeNs),
        help: 'max(ts) − min(ts) across sched rows.',
      },
      {
        label: 'Cores',
        value:
          s.numClusters > 1
            ? `${s.numCpus} (${s.numClusters} clusters)`
            : `${s.numCpus}`,
      },
      {
        label: 'Avg freq',
        value: fmtFreqKhz(s.avgFreqKhz),
        help: 'Runtime-weighted average across (cpu, frequency).',
      },
      {
        label: 'Peak freq',
        value: fmtFreqKhz(s.maxFreqKhz),
        help: 'Highest CPU frequency observed during the trace.',
      },
      {
        label: 'Processes',
        value: fmtCount(s.numProcesses),
      },
      {
        label: 'Threads',
        value: fmtCount(s.numThreads),
      },
    ];

    return m(
      Section,
      {
        title: 'Cycle budget',
        subtitle:
          'What fraction of the SoC’s capacity you spent. The goal isn’t to fill the bars — it’s to understand where the cycles went and whether you got parallelism in return.',
      },
      m('.pf-sismo-page__meters', meters),
      m('.pf-sismo-page__stat-row', cards.map(renderHeadlineCard)),
    );
  }

  private renderPerCore(
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
        ? 'Cores grouped by cluster. Per core: how busy it was (your work vs the rest) and the frequency it ran at.'
        : 'Per core: how busy it was (your work vs the rest) and the frequency it ran at.';
    return m(
      Section,
      {title: 'Per-core breakdown', subtitle},
      clusters.map((cl) =>
        m(
          '.pf-sismo-page__tab-pane',
          clusters.length > 1 &&
            m('.pf-sismo-page__tab-pane-label', cl.label),
          renderCoreTable(trace, cl.cores, walltime, hasPriv),
        ),
      ),
    );
  }

  // "Top consumers" section: one tab pane for processes, one for threads.
  // Each pane stacks the privileged set on top of the top-N context set so
  // your processes/threads are immediately visible above the system noise.
  private renderConsumers(trace: Trace, d: CpuDetail): m.Children {
    const hasPriv =
      d.privilegedProcesses.length > 0 || d.privilegedThreads.length > 0;
    return m(
      Section,
      {
        title: hasPriv ? 'Top CPU consumers' : 'Top consumers by CPU time',
        subtitle: hasPriv
          ? 'Your processes/threads first, then the heaviest other consumers on the system.'
          : 'Heaviest CPU consumers in the trace. No record-time marker found — your processes are not differentiated from the rest.',
      },
      m(Tabs, {
        activeTabKey: this.consumersTab,
        onTabChange: (key) => {
          this.consumersTab = key as 'processes' | 'threads';
        },
        tabs: [
          {
            key: 'processes',
            title: 'Processes',
            content: this.renderConsumerProcessPane(trace, d),
          },
          {
            key: 'threads',
            title: 'Threads',
            content: this.renderConsumerThreadPane(trace, d),
          },
        ],
      }),
    );
  }

  private renderConsumerProcessPane(trace: Trace, d: CpuDetail): m.Children {
    if (
      d.privilegedProcesses.length === 0 &&
      d.topContextProcesses.length === 0
    ) {
      return m(EmptyState, {icon: 'apps', title: 'No process-level CPU data'});
    }
    return m(
      '.pf-sismo-page__tab-panes',
      d.privilegedProcesses.length > 0 &&
        m(
          '.pf-sismo-page__tab-pane',
          m('.pf-sismo-page__tab-pane-label', 'Your processes'),
          renderProcessTable(trace, d.summary, d.privilegedProcesses),
        ),
      d.topContextProcesses.length > 0 &&
        m(
          '.pf-sismo-page__tab-pane',
          m(
            '.pf-sismo-page__tab-pane-label',
            d.privilegedProcesses.length > 0
              ? 'Other processes (top 20)'
              : 'Top processes by CPU time',
          ),
          renderProcessTable(trace, d.summary, d.topContextProcesses),
        ),
    );
  }

  private renderConsumerThreadPane(trace: Trace, d: CpuDetail): m.Children {
    if (
      d.privilegedThreads.length === 0 &&
      d.topContextThreads.length === 0
    ) {
      return m(EmptyState, {
        icon: 'developer_board',
        title: 'No thread-level CPU data',
      });
    }
    return m(
      '.pf-sismo-page__tab-panes',
      d.privilegedThreads.length > 0 &&
        m(
          '.pf-sismo-page__tab-pane',
          m('.pf-sismo-page__tab-pane-label', 'Your threads'),
          renderThreadTable(trace, d.summary, d.privilegedThreads),
        ),
      d.topContextThreads.length > 0 &&
        m(
          '.pf-sismo-page__tab-pane',
          m(
            '.pf-sismo-page__tab-pane-label',
            d.privilegedThreads.length > 0
              ? 'Other threads (top 20)'
              : 'Top threads by CPU time',
          ),
          renderThreadTable(trace, d.summary, d.topContextThreads),
        ),
    );
  }

  private renderMicroarch(m_: MicroarchData): m.Children {
    if (!m_.hasSamples) {
      return m(
        Section,
        {
          title: 'Microarchitecture',
          subtitle:
            'Where the cycles actually went, broken down by symbol and by library. Requires CPU sampling.',
        },
        m(EmptyState, {
          icon: 'science',
          title: 'No CPU samples in this trace',
          description:
            'Re-record with `sismo record` to capture stack samples; ' +
            'they’re what drives the hot-symbol breakdown.',
        }),
      );
    }
    if (!m_.hasSymbols) {
      return m(
        Section,
        {
          title: 'Microarchitecture',
          subtitle:
            'Where the cycles actually went, broken down by symbol and by library.',
        },
        m(
          Callout,
          {icon: 'info', intent: Intent.Primary},
          `${fmtCount(m_.totalSamples)} samples were captured but none ` +
            'were symbolised. Make sure debug info is available — ' +
            'unstripped binaries on Linux, dSYMs on macOS.',
        ),
      );
    }
    return m(
      Section,
      {
        title: 'Microarchitecture',
        subtitle:
          `Where the cycles actually went. Based on ${fmtCount(m_.totalSamples)} ` +
          'sampled stacks (leaf frame = currently-executing function).',
      },
      m(
        '.pf-sismo-page__microarch',
        m(
          '.pf-sismo-page__microarch-col',
          m('.pf-sismo-page__tab-pane-label', 'Hot symbols'),
          renderHotSymbolTable(m_.hotSymbols),
        ),
        m(
          '.pf-sismo-page__microarch-col',
          m('.pf-sismo-page__tab-pane-label', 'Hot libraries / mappings'),
          renderHotMappingTable(m_.hotMappings),
        ),
      ),
      m(
        Callout,
        {icon: 'science', intent: Intent.None},
        'Hardware counters (IPC, branch mispredicts, cache misses) ' +
          'are not yet recorded by `sismo record`. They unlock the ' +
          '“cycles spent but unproductive” drilldown — coming soon.',
      ),
    );
  }

  private async load(trace: Trace, priv: PrivilegedSet): Promise<void> {
    try {
      this.data = await loadCpuDetail(trace.engine, priv);
    } catch (e) {
      this.error = e instanceof Error ? e.message : 'Failed to load CPU detail';
    }
    m.redraw();
  }
}

interface HeadlineCard {
  readonly label: string;
  readonly value: string;
  readonly help?: string;
}

function renderProcessTable(
  trace: Trace,
  summary: CpuSummary,
  rows: ReadonlyArray<CpuProcessRow>,
): m.Children {
  const total = Number(summary.totalRuntimeNs ?? 0n);
  const data = rows.map((r) => {
    const runtime = Number(r.runtimeNs);
    const share = total > 0 ? runtime / total : null;
    return [
      m(
        GridCell,
        {wrap: true},
        renderProcessLink(trace, r.name, r.pid, r.upid),
      ),
      m(GridCell, {align: 'right'}, fmtDuration(trace, r.runtimeNs)),
      m(GridCell, {align: 'right'}, fmtPercent(share)),
      m(GridCell, {align: 'right'}, fmtMegacycles(r.megacycles)),
    ];
  });
  return m(
    Card,
    {className: 'pf-sismo-page__table-card'},
    m(Grid, {
      columns: [
        {key: 'name', header: m(GridHeaderCell, 'Process')},
        {key: 'runtime', header: m(GridHeaderCell, 'Runtime')},
        {key: 'share', header: m(GridHeaderCell, '% of CPU')},
        {key: 'mcyc', header: m(GridHeaderCell, 'Cycles')},
      ],
      rowData: data,
    }),
  );
}

function renderThreadTable(
  trace: Trace,
  summary: CpuSummary,
  rows: ReadonlyArray<CpuThreadRow>,
): m.Children {
  const total = Number(summary.totalRuntimeNs ?? 0n);
  const data = rows.map((r) => {
    const runtime = Number(r.runtimeNs);
    const share = total > 0 ? runtime / total : null;
    return [
      m(
        GridCell,
        {wrap: true},
        renderThreadLink(trace, r.threadName, r.tid, r.utid),
      ),
      m(GridCell, {wrap: true}, r.processName ?? '—'),
      m(GridCell, {align: 'right'}, fmtDuration(trace, r.runtimeNs)),
      m(GridCell, {align: 'right'}, fmtPercent(share)),
      m(GridCell, {align: 'right'}, fmtMegacycles(r.megacycles)),
    ];
  });
  return m(
    Card,
    {className: 'pf-sismo-page__table-card'},
    m(Grid, {
      columns: [
        {key: 'thread', header: m(GridHeaderCell, 'Thread')},
        {key: 'process', header: m(GridHeaderCell, 'Process')},
        {key: 'runtime', header: m(GridHeaderCell, 'Runtime')},
        {key: 'share', header: m(GridHeaderCell, '% of CPU')},
        {key: 'mcyc', header: m(GridHeaderCell, 'Cycles')},
      ],
      rowData: data,
    }),
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

// Busy fraction of the core, split into your work (blue) vs the rest (grey).
function renderCoreBar(
  busyFrac: number,
  privFrac: number,
  hasPriv: boolean,
): m.Children {
  const busyPct = Math.max(0, Math.min(1, busyFrac)) * 100;
  return m(
    '.pf-sismo-page__meter-bar',
    hasPriv &&
      m('.pf-sismo-page__meter-fill.pf-sismo-page__meter-fill--priv', {
        style: {width: `${busyPct * privFrac}%`},
      }),
    m('.pf-sismo-page__meter-fill.pf-sismo-page__meter-fill--ctx', {
      style: {width: `${hasPriv ? busyPct * (1 - privFrac) : busyPct}%`},
    }),
  );
}

function renderCycleBudgetMeter(s: CpuSummary): m.Children {
  const used = fmtMegacycles(s.megacycles);
  const avail = fmtMegacyclesNum(s.peakMegacycles);
  const pct = s.bandwidthUtilization ?? 0;
  const pctClamped = Math.max(0, Math.min(1, pct));
  return m(
    Card,
    {className: 'pf-sismo-page__meter'},
    m(
      '.pf-sismo-page__meter-label',
      'Cycles spent',
      m(
        Tooltip,
        {
          trigger: m(Icon, {
            icon: 'help_outline',
            className: 'pf-sismo-page__help-icon',
          }),
        },
        'Cycles delivered across all cores / cycles that would have been ' +
          'delivered if every core ran at its peak observed frequency for ' +
          'the full walltime. Requires cpufreq data.',
      ),
    ),
    m(
      '.pf-sismo-page__meter-primary',
      m('span.pf-sismo-page__meter-big', used),
      m('span.pf-sismo-page__meter-of', ' of '),
      m('span.pf-sismo-page__meter-big', avail),
    ),
    m(
      '.pf-sismo-page__meter-bar',
      m('.pf-sismo-page__meter-fill.pf-sismo-page__meter-fill--ctx', {
        style: {width: `${pctClamped * 100}%`},
      }),
    ),
    m(
      '.pf-sismo-page__meter-sub',
      `${fmtPercent(pct)} of peak-frequency budget`,
    ),
  );
}

function renderConcurrencyMeter(s: CpuSummary): m.Children {
  const conc = s.effectiveConcurrency;
  const ncpus = s.numCpus;
  const concClamped =
    conc !== null && ncpus > 0 ? Math.min(conc / ncpus, 1) : 0;
  const privFrac =
    s.privilegedConcurrency !== null && conc !== null && conc > 0
      ? Math.max(0, Math.min(1, s.privilegedConcurrency / conc))
      : 0;
  const privWidthPct = concClamped * privFrac * 100;
  const ctxWidthPct = concClamped * (1 - privFrac) * 100;
  const sub =
    s.privilegedConcurrency !== null && conc !== null
      ? `Your processes: ${s.privilegedConcurrency.toFixed(2)} cores avg · ` +
        `others: ${Math.max(0, conc - s.privilegedConcurrency).toFixed(2)}`
      : conc !== null
        ? `${fmtPercent(concClamped)} of available core-time`
        : '—';
  return m(
    Card,
    {className: 'pf-sismo-page__meter'},
    m(
      '.pf-sismo-page__meter-label',
      'Concurrency',
      m(
        Tooltip,
        {
          trigger: m(Icon, {
            icon: 'help_outline',
            className: 'pf-sismo-page__help-icon',
          }),
        },
        'Average number of cores in use at any instant ' +
          '(total non-idle runtime ÷ walltime).',
      ),
    ),
    m(
      '.pf-sismo-page__meter-primary',
      m('span.pf-sismo-page__meter-big', conc !== null ? conc.toFixed(2) : '—'),
      m('span.pf-sismo-page__meter-of', ' of '),
      m('span.pf-sismo-page__meter-big', `${ncpus}`),
      m('span.pf-sismo-page__meter-of', ' cores'),
    ),
    m(
      '.pf-sismo-page__meter-bar',
      m('.pf-sismo-page__meter-fill.pf-sismo-page__meter-fill--priv', {
        style: {width: `${privWidthPct}%`},
      }),
      m('.pf-sismo-page__meter-fill.pf-sismo-page__meter-fill--ctx', {
        style: {width: `${ctxWidthPct}%`},
      }),
    ),
    m('.pf-sismo-page__meter-sub', sub),
  );
}

function renderParallelismMeter(s: CpuSummary): m.Children {
  const priv = s.privilegedConcurrency ?? 0;
  const nthreads = s.numPrivilegedThreads ?? 0;
  const ideal = Math.min(nthreads, s.numCpus);
  const ratio = ideal > 0 ? priv / ideal : null;
  const ratioClamped = ratio !== null ? Math.max(0, Math.min(1, ratio)) : 0;
  return m(
    Card,
    {className: 'pf-sismo-page__meter'},
    m(
      '.pf-sismo-page__meter-label',
      'Parallelism (your processes)',
      m(
        Tooltip,
        {
          trigger: m(Icon, {
            icon: 'help_outline',
            className: 'pf-sismo-page__help-icon',
          }),
        },
        'How close your average core-usage got to the theoretical max ' +
          '(min of #threads-that-ran and #cores). Low values mean your ' +
          'threads spent most of their time waiting or idle.',
      ),
    ),
    m(
      '.pf-sismo-page__meter-primary',
      m('span.pf-sismo-page__meter-big', priv.toFixed(2)),
      m('span.pf-sismo-page__meter-of', ' cores avg / '),
      m('span.pf-sismo-page__meter-big', `${nthreads}`),
      m('span.pf-sismo-page__meter-of', ` thread${nthreads === 1 ? '' : 's'} ran`),
    ),
    m(
      '.pf-sismo-page__meter-bar',
      m('.pf-sismo-page__meter-fill.pf-sismo-page__meter-fill--priv', {
        style: {width: `${ratioClamped * 100}%`},
      }),
    ),
    m(
      '.pf-sismo-page__meter-sub',
      ratio !== null
        ? `${fmtPercent(ratio)} of max parallelism (${ideal} core${ideal === 1 ? '' : 's'})`
        : 'No privileged threads ran in this trace',
    ),
  );
}

function renderHotSymbolTable(rows: ReadonlyArray<HotSymbolRow>): m.Children {
  if (rows.length === 0) {
    return m(EmptyState, {icon: 'code', title: 'No hot symbols'});
  }
  const data = rows.map((r) => [
    m(
      GridCell,
      {wrap: true},
      m('span', r.name),
      r.mappingName !== null &&
        m('span.pf-sismo-page__muted', ` — ${shortMapping(r.mappingName)}`),
    ),
    m(GridCell, {align: 'right'}, fmtCount(r.samples)),
    m(GridCell, {align: 'right'}, fmtPercent(r.share)),
  ]);
  return m(
    Card,
    {className: 'pf-sismo-page__table-card'},
    m(Grid, {
      columns: [
        {key: 'symbol', header: m(GridHeaderCell, 'Symbol')},
        {key: 'samples', header: m(GridHeaderCell, 'Samples')},
        {key: 'share', header: m(GridHeaderCell, '% of samples')},
      ],
      rowData: data,
    }),
  );
}

function renderHotMappingTable(rows: ReadonlyArray<HotMappingRow>): m.Children {
  if (rows.length === 0) {
    return m(EmptyState, {icon: 'inventory_2', title: 'No mapping data'});
  }
  const data = rows.map((r) => [
    m(GridCell, {wrap: true}, shortMapping(r.name)),
    m(GridCell, {align: 'right'}, fmtCount(r.samples)),
    m(GridCell, {align: 'right'}, fmtPercent(r.share)),
  ]);
  return m(
    Card,
    {className: 'pf-sismo-page__table-card'},
    m(Grid, {
      columns: [
        {key: 'mapping', header: m(GridHeaderCell, 'Mapping')},
        {key: 'samples', header: m(GridHeaderCell, 'Samples')},
        {key: 'share', header: m(GridHeaderCell, '% of samples')},
      ],
      rowData: data,
    }),
  );
}

// Mapping names from stack_profile_mapping are full paths; trim to a basename
// so the table column stays readable.
function shortMapping(path: string): string {
  const slash = path.lastIndexOf('/');
  return slash >= 0 ? path.slice(slash + 1) : path;
}

function renderHeadlineCard({label, value, help}: HeadlineCard): m.Children {
  return m(
    Card,
    {className: 'pf-sismo-page__stat-card'},
    m(
      '.pf-sismo-page__stat-label',
      label,
      help &&
        m(
          Tooltip,
          {
            trigger: m(Icon, {
              icon: 'help_outline',
              className: 'pf-sismo-page__help-icon',
            }),
          },
          help,
        ),
    ),
    m('.pf-sismo-page__stat-value', value),
  );
}
