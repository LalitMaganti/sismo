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
import type {Trace} from '../../../../public/trace';
import {Section} from '../../../../widgets/section';
import {Card} from '../../../../widgets/card';
import {Grid, GridCell, GridHeaderCell} from '../../../../widgets/grid';
import {EmptyState} from '../../../../widgets/empty_state';
import {Tabs} from '../../../../widgets/tabs';
import {Anchor} from '../../../../widgets/anchor';
import {
  goToSismoDomain,
  renderProcessLink,
  renderStatCard,
  renderThreadLink,
  type StatCard,
} from '../../page_common';
import type {
  CpuDetail,
  CpuProcessRow,
  CpuSummary,
  CpuThreadRow,
  FocusWindow,
  RealCycles,
  ThreadStateRow,
} from '../../cpu_data';
import {
  loadCpuTotals,
  loadProcessRows,
  loadRealCycles,
  loadThreadRows,
  loadThreadStates,
} from '../../cpu_data';
import {MeterBar, type MeterColor} from '../../../dev.perfetto.SismoWidgets/meter';
import type {PrivilegedSet} from '../../privileged_set';
import {
  fmtCount,
  fmtDuration,
  fmtIpc,
  fmtMegacycles,
  fmtPercent,
} from '../../format';

interface CpuConsumersViewAttrs {
  readonly trace: Trace;
  readonly data: CpuDetail;
  readonly priv: PrivilegedSet;
  // The shared focus window; when set, the consumer tables, denominators and
  // state breakdown are all recomputed for that region.
  readonly focus?: FocusWindow;
}

// The consumer tables' data source: the whole-trace rows borrowed from
// CpuDetail, or a windowed reload. `summary` carries the matching total so the
// "% of CPU" denominator tracks the window.
interface ConsumerRows {
  privProc: ReadonlyArray<CpuProcessRow>;
  ctxProc: ReadonlyArray<CpuProcessRow>;
  privThread: ReadonlyArray<CpuThreadRow>;
  ctxThread: ReadonlyArray<CpuThreadRow>;
  summary: CpuSummary;
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
  private rows?: ConsumerRows;

  oninit({attrs}: m.CVnode<CpuConsumersViewAttrs>): void {
    const {trace, data: d, priv, focus} = attrs;
    loadThreadStates(trace.engine, priv, 25, focus)
      .then((rows) => {
        this.threadStates = rows;
        m.redraw();
      })
      .catch(() => {
        this.threadStates = [];
        m.redraw();
      });
    loadRealCycles(trace.engine, focus)
      .then((c) => {
        this.cycles = c;
        m.redraw();
      })
      .catch(() => {});
    if (focus === undefined) {
      // Whole-trace: reuse the rows the page already loaded into CpuDetail.
      this.rows = {
        privProc: d.privilegedProcesses,
        ctxProc: d.topContextProcesses,
        privThread: d.privilegedThreads,
        ctxThread: d.topContextThreads,
        summary: d.summary,
      };
    } else {
      Promise.all([
        loadProcessRows(trace.engine, priv, 'privileged', undefined, focus),
        loadProcessRows(trace.engine, priv, 'context', 20, focus),
        loadThreadRows(trace.engine, priv, 'privileged', undefined, focus),
        loadThreadRows(trace.engine, priv, 'context', 20, focus),
        loadCpuTotals(trace.engine, priv, focus),
      ])
        .then(([privProc, ctxProc, privThread, ctxThread, totals]) => {
          this.rows = {
            privProc,
            ctxProc,
            privThread,
            ctxThread,
            // Denominators scoped to the window; counts stay whole-trace (they
            // describe the trace, not the window).
            summary: {
              ...d.summary,
              totalRuntimeNs: totals.totalNs,
              privilegedRuntimeNs: totals.privilegedNs,
            },
          };
          m.redraw();
        })
        .catch(() => {});
    }
  }

  view({attrs}: m.CVnode<CpuConsumersViewAttrs>): m.Children {
    const {trace, data: d} = attrs;
    const hasPriv =
      d.privilegedProcesses.length > 0 || d.privilegedThreads.length > 0;
    const rows = this.rows;
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
        rows === undefined
          ? m(EmptyState, {
              icon: 'hourglass_empty',
              title: 'Loading consumers…',
            })
          : [
              m(
                '.pf-sismo-page__stat-row',
                summaryCards(rows, hasPriv).map(renderStatCard),
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
                    content: this.renderThreadPane(trace, rows),
                  },
                  {
                    key: 'processes',
                    title: 'Processes',
                    content: this.renderProcessPane(trace, rows),
                  },
                ],
              }),
            ],
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
        title: 'Where threads spent their time, and how well',
        subtitle:
          'Per thread: the split of tracked time between running and the ' +
          'off-CPU states (waiting for a core, blocked on I/O, asleep), plus ' +
          'how productive the on-CPU time was — IPC and effective clock from ' +
          'the hardware counters. Click a thread to open it in the timeline.',
      },
      rows === undefined
        ? m(EmptyState, {
            icon: 'hourglass_empty',
            title: 'Loading thread states…',
          })
        : [
            renderStateLegend(),
            renderThreadStateTable(trace, rows, this.cycles),
            offCpuHeavy(rows) &&
              m(
                '.pf-sismo-page__question-footer',
                m(
                  Anchor,
                  {
                    href: '#!/sismo/latency',
                    icon: 'arrow_forward',
                    onclick: (e: Event) => {
                      e.preventDefault();
                      goToSismoDomain(trace, 'latency');
                    },
                  },
                  'Lots of off-CPU time (waiting, blocked, asleep)? The ' +
                    'Latency view explains what they were waiting on',
                ),
              ),
          ],
    );
  }

  private renderProcessPane(trace: Trace, rows: ConsumerRows): m.Children {
    if (rows.privProc.length === 0 && rows.ctxProc.length === 0) {
      return m(EmptyState, {icon: 'apps', title: 'No process-level CPU data'});
    }
    return m(
      '.pf-sismo-page__tab-panes',
      rows.privProc.length > 0 &&
        m(
          '.pf-sismo-page__tab-pane',
          m('.pf-sismo-page__tab-pane-label', 'Your processes'),
          renderProcessTable(trace, rows.summary, rows.privProc),
        ),
      rows.ctxProc.length > 0 &&
        m(
          '.pf-sismo-page__tab-pane',
          m(
            '.pf-sismo-page__tab-pane-label',
            rows.privProc.length > 0
              ? 'Other processes (top 20)'
              : 'Top processes by CPU time',
          ),
          renderProcessTable(trace, rows.summary, rows.ctxProc),
        ),
    );
  }

  private renderThreadPane(trace: Trace, rows: ConsumerRows): m.Children {
    if (rows.privThread.length === 0 && rows.ctxThread.length === 0) {
      return m(EmptyState, {
        icon: 'developer_board',
        title: 'No thread-level CPU data',
      });
    }
    return m(
      '.pf-sismo-page__tab-panes',
      rows.privThread.length > 0 &&
        m(
          '.pf-sismo-page__tab-pane',
          m('.pf-sismo-page__tab-pane-label', 'Your threads'),
          renderThreadTable(trace, rows.summary, rows.privThread),
        ),
      rows.ctxThread.length > 0 &&
        m(
          '.pf-sismo-page__tab-pane',
          m(
            '.pf-sismo-page__tab-pane-label',
            rows.privThread.length > 0
              ? 'Other threads (top 20)'
              : 'Top threads by CPU time',
          ),
          renderThreadTable(trace, rows.summary, rows.ctxThread),
        ),
    );
  }
}

// Headline scorecards above the consumer tables: how many threads/processes
// ran, the single busiest thread's share, and (when profiling) your slice. When
// a focus is set, the rows + denominators come scoped to the window.
function summaryCards(rows: ConsumerRows, hasPriv: boolean): StatCard[] {
  const s = rows.summary;
  const total = Number(s.totalRuntimeNs ?? 0n);
  let busiest = 0;
  for (const t of [...rows.privThread, ...rows.ctxThread]) {
    const frac = total > 0 ? Number(t.runtimeNs) / total : 0;
    if (frac > busiest) busiest = frac;
  }
  const cards: StatCard[] = [
    {
      label: 'Threads',
      value: fmtCount(s.numThreads),
      help: 'Distinct threads that ran on a CPU during the trace.',
    },
    {
      label: 'Processes',
      value: fmtCount(s.numProcesses),
      help: 'Distinct processes that ran on a CPU during the trace.',
    },
    {
      label: 'Busiest thread',
      value: fmtPercent(busiest),
      help: 'Highest single-thread share of total CPU time.',
    },
  ];
  if (hasPriv && s.privilegedRuntimeNs !== null && total > 0) {
    cards.push({
      label: 'Your CPU share',
      value: fmtPercent(Number(s.privilegedRuntimeNs) / total),
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

// Whether the shown threads spent a meaningful share of their tracked time
// off-CPU — the cue to surface the Latency-view hand-off.
function offCpuHeavy(rows: ReadonlyArray<ThreadStateRow>): boolean {
  let on = 0;
  let off = 0;
  for (const s of rows) {
    on += Number(s.runningNs);
    off += Number(
      s.runnableNs + s.uninterruptibleNs + s.sleepingNs + s.otherNs,
    );
  }
  const total = on + off;
  return total > 0 && off / total >= 0.2;
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
  cycles: RealCycles | undefined,
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
    const cyc = cycles?.byUtid.get(s.utid) ?? null;
    const instr = cycles?.instrByUtid.get(s.utid) ?? null;
    // IPC = instructions ÷ cycles; effective clock = cycles ÷ on-CPU time
    // (cycles/ns = GHz) — the cpufreq-free "how fast it actually ran".
    const ipc =
      instr !== null && cyc !== null && cyc > 0n
        ? Number(instr) / Number(cyc)
        : null;
    const ghz =
      cyc !== null && s.runningNs > 0n ? Number(cyc) / Number(s.runningNs) : null;
    return [
      m(
        GridCell,
        {wrap: true},
        renderThreadLink(trace, s.threadName, s.tid, s.utid),
      ),
      m(GridCell, {wrap: true}, s.processName ?? '—'),
      m(GridCell, {align: 'right'}, fmtPercent(onCpu)),
      m(GridCell, renderStateBar(s)),
      m(GridCell, {align: 'right'}, fmtMegacycles(cyc)),
      m(GridCell, {align: 'right'}, fmtIpc(ipc)),
      m(GridCell, {align: 'right'}, ghz !== null ? `${ghz.toFixed(2)} GHz` : '—'),
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
        {key: 'ipc', header: m(GridHeaderCell, 'IPC')},
        {key: 'clock', header: m(GridHeaderCell, 'Eff. clock')},
        {key: 'sw', header: m(GridHeaderCell, 'Switches')},
      ],
      rowData: data,
    }),
  );
}
