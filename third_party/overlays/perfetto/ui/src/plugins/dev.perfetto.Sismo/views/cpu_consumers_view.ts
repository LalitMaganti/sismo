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

// CPU "Consumers" tab: top CPU consumers, processes and threads. Your processes
// /threads stack on top of the top-N context set so they're visible above the
// system noise.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {Section} from '../../../widgets/section';
import {Card} from '../../../widgets/card';
import {Grid, GridCell, GridHeaderCell} from '../../../widgets/grid';
import {EmptyState} from '../../../widgets/empty_state';
import {Tabs} from '../../../widgets/tabs';
import {
  renderProcessLink,
  renderStatCard,
  renderThreadLink,
  type StatCard,
} from '../page_common';
import type {
  CpuDetail,
  CpuProcessRow,
  CpuSummary,
  CpuThreadRow,
  RealCycles,
  ThreadStateRow,
} from '../cpu_data';
import {loadRealCycles, loadThreadStates} from '../cpu_data';
import {MeterBar, type MeterColor} from '../../dev.perfetto.SismoWidgets/meter';
import type {PrivilegedSet} from '../privileged_set';
import {fmtCount, fmtDuration, fmtMegacycles, fmtPercent} from '../format';

interface CpuConsumersViewAttrs {
  readonly trace: Trace;
  readonly data: CpuDetail;
  readonly priv: PrivilegedSet;
}

// State → meter colour, shared by the per-thread breakdown bars and the legend
// so the two never drift. On-CPU is the in-focus colour; runnable (waiting for
// a core) is the attention amber; blocked I/O is the caution red; benign sleep
// is the neutral teal.
const STATE_SWATCHES: ReadonlyArray<{
  readonly color: MeterColor;
  readonly label: string;
}> = [
  {color: 'primary', label: 'On CPU'},
  {color: 'secondary', label: 'Waiting for a core'},
  {color: 'caution', label: 'Blocked / I/O'},
  {color: 'info', label: 'Sleeping'},
  {color: 'idle', label: 'Other'},
];

export class CpuConsumersView
  implements m.ClassComponent<CpuConsumersViewAttrs>
{
  private consumersTab: 'processes' | 'threads' = 'threads';
  private threadStates?: ThreadStateRow[];
  private cycles?: RealCycles;

  oninit({attrs}: m.CVnode<CpuConsumersViewAttrs>): void {
    loadThreadStates(attrs.trace.engine, attrs.priv, 25)
      .then((rows) => {
        this.threadStates = rows;
        m.redraw();
      })
      .catch(() => {
        this.threadStates = [];
        m.redraw();
      });
    loadRealCycles(attrs.trace.engine)
      .then((c) => {
        this.cycles = c;
        m.redraw();
      })
      .catch(() => {});
  }

  view({attrs}: m.CVnode<CpuConsumersViewAttrs>): m.Children {
    const {trace, data: d} = attrs;
    const hasPriv =
      d.privilegedProcesses.length > 0 || d.privilegedThreads.length > 0;
    return [
      m(
        Section,
        {
          title: hasPriv ? 'Top CPU consumers' : 'Top consumers by CPU time',
          subtitle: hasPriv
            ? 'Your processes/threads first, then the heaviest other consumers ' +
              'on the system.'
            : 'Heaviest CPU consumers in the trace. No record-time marker found ' +
              '— your processes are not differentiated from the rest.',
        },
        m(
          '.pf-sismo-page__stat-row',
          summaryCards(d, hasPriv).map(renderStatCard),
        ),
        m(Tabs, {
          activeTabKey: this.consumersTab,
          onTabChange: (key) => {
            this.consumersTab = key as 'processes' | 'threads';
          },
          tabs: [
            {
              key: 'threads',
              title: 'Threads',
              content: this.renderThreadPane(trace, d),
            },
            {
              key: 'processes',
              title: 'Processes',
              content: this.renderProcessPane(trace, d),
            },
          ],
        }),
      ),
      this.renderStateBreakdown(trace),
    ];
  }

  // Where each thread's wall-time actually went: on-CPU vs waiting for a core
  // (scheduling latency) vs blocked on I/O vs asleep. The bridge from "who used
  // the CPU" to "why a thread wasn't using it" — and on to the Latency tab.
  private renderStateBreakdown(trace: Trace): m.Children {
    const rows = this.threadStates;
    if (rows !== undefined && rows.length === 0) return undefined;
    return m(
      Section,
      {
        title: 'Where threads spent their time',
        subtitle:
          'Per thread, the split of tracked time between running on a core and ' +
          'the off-CPU states (waiting for a core, blocked on I/O, asleep). ' +
          'Click a thread to open it in the timeline.',
      },
      rows === undefined
        ? m(EmptyState, {
            icon: 'hourglass_empty',
            title: 'Loading thread states…',
          })
        : [
            renderStateLegend(),
            renderThreadStateTable(trace, rows, this.cycles?.byUtid),
          ],
    );
  }

  private renderProcessPane(trace: Trace, d: CpuDetail): m.Children {
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

  private renderThreadPane(trace: Trace, d: CpuDetail): m.Children {
    if (d.privilegedThreads.length === 0 && d.topContextThreads.length === 0) {
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
}

// Headline scorecards above the consumer tables: how many threads/processes
// ran, the single busiest thread's share, and (when profiling) your slice.
function summaryCards(d: CpuDetail, hasPriv: boolean): StatCard[] {
  const total = Number(d.summary.totalRuntimeNs ?? 0n);
  let busiest = 0;
  for (const t of [...d.privilegedThreads, ...d.topContextThreads]) {
    const frac = total > 0 ? Number(t.runtimeNs) / total : 0;
    if (frac > busiest) busiest = frac;
  }
  const cards: StatCard[] = [
    {
      label: 'Threads',
      value: fmtCount(d.summary.numThreads),
      help: 'Distinct threads that ran on a CPU during the trace.',
    },
    {
      label: 'Processes',
      value: fmtCount(d.summary.numProcesses),
      help: 'Distinct processes that ran on a CPU during the trace.',
    },
    {
      label: 'Busiest thread',
      value: fmtPercent(busiest),
      help: 'Highest single-thread share of total CPU time.',
    },
  ];
  if (hasPriv && d.summary.privilegedRuntimeNs !== null && total > 0) {
    cards.push({
      label: 'Your CPU share',
      value: fmtPercent(Number(d.summary.privilegedRuntimeNs) / total),
      help: 'Your processes’ share of all CPU time in the trace.',
    });
  }
  return cards;
}

export function renderProcessTable(
  trace: Trace,
  summary: CpuSummary,
  rows: ReadonlyArray<CpuProcessRow>,
): m.Children {
  const total = Number(summary.totalRuntimeNs ?? 0n);
  const data = rows.map((r) => {
    const runtime = Number(r.runtimeNs);
    const share = total > 0 ? runtime / total : null;
    return [
      m(GridCell, {wrap: true}, renderProcessLink(trace, r.name, r.pid, r.upid)),
      m(GridCell, {align: 'right'}, fmtDuration(trace, r.runtimeNs)),
      m(GridCell, {align: 'right'}, fmtPercent(share)),
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
      ],
      rowData: data,
    }),
  );
}

export function renderThreadTable(
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
      ],
      rowData: data,
    }),
  );
}

// Colour key for the per-thread state bars, rendered once above the table.
function renderStateLegend(): m.Children {
  return m(
    '.pf-sismo-meter__legend',
    STATE_SWATCHES.map((sw) =>
      m(
        '.pf-sismo-meter__legend-item',
        m(`.pf-sismo-meter__swatch.pf-sismo-meter__fill--${sw.color}`),
        sw.label,
      ),
    ),
  );
}

// Stacked proportion bar for one thread's tracked time, in STATE_SWATCHES order:
// running | runnable | uninterruptible | sleeping | other.
function renderStateBar(s: ThreadStateRow): m.Children {
  const total =
    Number(
      s.runningNs +
        s.runnableNs +
        s.uninterruptibleNs +
        s.sleepingNs +
        s.otherNs,
    ) || 1;
  const f = (ns: bigint): number => Number(ns) / total;
  return m(MeterBar, {
    segments: [
      {color: 'primary', frac: f(s.runningNs)},
      {color: 'secondary', frac: f(s.runnableNs)},
      {color: 'caution', frac: f(s.uninterruptibleNs)},
      {color: 'info', frac: f(s.sleepingNs)},
      {color: 'idle', frac: f(s.otherNs)},
    ],
  });
}

function renderThreadStateTable(
  trace: Trace,
  rows: ReadonlyArray<ThreadStateRow>,
  cyclesByUtid: Map<number, bigint> | undefined,
): m.Children {
  const data = rows.map((s) => {
    const total = Number(
      s.runningNs +
        s.runnableNs +
        s.uninterruptibleNs +
        s.sleepingNs +
        s.otherNs,
    );
    const onCpu = total > 0 ? Number(s.runningNs) / total : null;
    return [
      m(
        GridCell,
        {wrap: true},
        renderThreadLink(trace, s.threadName, s.tid, s.utid),
      ),
      m(GridCell, {wrap: true}, s.processName ?? '—'),
      m(GridCell, {align: 'right'}, fmtPercent(onCpu)),
      m(GridCell, renderStateBar(s)),
      m(GridCell, {align: 'right'}, fmtMegacycles(cyclesByUtid?.get(s.utid) ?? null)),
      m(GridCell, {align: 'right'}, fmtCount(s.numRunSlices)),
    ];
  });
  return m(
    Card,
    {className: 'pf-sismo-page__table-card'},
    m(Grid, {
      columns: [
        {key: 'thread', header: m(GridHeaderCell, 'Thread')},
        {key: 'process', header: m(GridHeaderCell, 'Process')},
        {key: 'oncpu', header: m(GridHeaderCell, 'On-CPU %')},
        {key: 'split', header: m(GridHeaderCell, 'Time split')},
        {key: 'cyc', header: m(GridHeaderCell, 'Cycles')},
        {key: 'sw', header: m(GridHeaderCell, 'Switches')},
      ],
      rowData: data,
    }),
  );
}
