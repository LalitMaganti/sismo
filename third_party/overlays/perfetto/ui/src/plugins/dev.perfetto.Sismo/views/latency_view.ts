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

// Latency domain body. Parked while we focus on CPU, but kept wired up: it
// renders the existing scheduling-latency analysis under the shared Sismo
// shell (the shell owns the header / domain selector, so this is body-only).

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {Section} from '../../../widgets/section';
import {Card} from '../../../widgets/card';
import {Grid, GridCell, GridHeaderCell} from '../../../widgets/grid';
import {EmptyState} from '../../../widgets/empty_state';
import {Callout} from '../../../widgets/callout';
import {Intent} from '../../../widgets/common';
import {Tabs} from '../../../widgets/tabs';
import {
  loadCpuTriage,
  loadLatencyDetail,
  type CpuBlameRow,
  type CpuIdleStateRow,
  type CpuThreadBlameRow,
  type CpuTriage,
  type LatencyDetail,
} from '../cpu_data';
import {fmtDuration} from '../format';
import {renderProcessLink, renderThreadLink} from '../page_common';
import type {PrivilegedSet} from '../privileged_set';
import {
  renderOffCpuBreakdownMeter,
  renderOnOffCpuMeter,
  renderTriageRoute,
  triageShares,
} from './triage_meters';

interface LatencyViewAttrs {
  readonly trace: Trace;
  readonly privileged: PrivilegedSet;
}

export class LatencyView implements m.ClassComponent<LatencyViewAttrs> {
  private data?: LatencyDetail;
  private triage?: CpuTriage;
  private error?: string;
  private blameTab: 'processes' | 'threads' = 'processes';
  private scope = 'all threads';

  oninit({attrs}: m.CVnode<LatencyViewAttrs>) {
    this.scope = attrs.privileged.upids.length > 0 ? 'your threads' : 'all threads';
    this.load(attrs.trace, attrs.privileged);
  }

  view({attrs}: m.CVnode<LatencyViewAttrs>): m.Children {
    if (this.error !== undefined) {
      return m(Callout, {icon: 'error', intent: Intent.Danger}, this.error);
    }
    if (this.data === undefined) {
      return m(EmptyState, {
        icon: 'hourglass_empty',
        title: 'Loading latency details…',
      });
    }
    const d = this.data;
    if (!d.hasSched) {
      return m(
        Callout,
        {icon: 'info', intent: Intent.Primary},
        'This trace contains no scheduling data, so scheduling latency can’t ' +
          'be analysed. Re-record with ftrace + sched data sources.',
      );
    }
    return [
      this.renderTriage(attrs.trace),
      this.renderBlame(attrs.trace, d),
      this.renderIdleStates(d.idleStates),
      this.renderComingSoon(),
    ];
  }

  // Mirror of the CPU tab's triage gauge, with the route reversed: on-CPU vs
  // off-CPU, then a breakdown of the off-CPU time by why, plus a standing link
  // back to the CPU views for the on-CPU half.
  private renderTriage(trace: Trace): m.Children {
    const d = this.triage;
    if (d === undefined || !d.hasData) return undefined;
    const scope = this.scope;
    const s = triageShares(d);
    return m(
      Section,
      {
        title: 'Was your time on CPU, or off it?',
        subtitle:
          `Scheduling latency lives in off-CPU time. This splits ${scope}’ ` +
          'tracked thread-time on vs off the CPU, then breaks the off-CPU part ' +
          'down by why.',
      },
      m('.pf-sismo-page__meters', [
        renderOnOffCpuMeter(d, scope),
        s.offCpuNs > 0 && renderOffCpuBreakdownMeter(d, scope),
      ]),
      renderTriageRoute(trace, {
        icon: 'memory',
        message: `On-CPU time is where ${scope} actually ran; the CPU view breaks down where it went.`,
        linkText: 'Open the CPU view',
        domain: 'cpu',
      }),
    );
  }

  private renderIdleStates(rows: CpuIdleStateRow[]): m.Children {
    if (rows.length === 0) {
      return m(
        Section,
        {
          title: 'Idle-state residency',
          subtitle:
            'Time each CPU spent in each cpuidle (C-)state. Deeper states save ' +
            'more power but take longer to wake from — a source of wakeup latency.',
        },
        m(EmptyState, {icon: 'bedtime', title: 'No idle-state data'}),
      );
    }
    // Bucket residency by (cpu, state); deeper states first via the percentage
    // ordering from the loader.
    const byCpu = new Map<number, CpuIdleStateRow[]>();
    for (const r of rows) {
      const b = byCpu.get(r.cpu);
      if (b === undefined) byCpu.set(r.cpu, [r]);
      else b.push(r);
    }
    const cpus = [...byCpu.keys()].sort((a, b) => a - b);
    const data = cpus.map((cpu) => {
      const states = byCpu.get(cpu)!;
      const summary = states
        .map((s) => `${s.state} ${s.percentage.toFixed(0)}%`)
        .join(', ');
      return [m(GridCell, `CPU ${cpu}`), m(GridCell, {wrap: true}, summary)];
    });
    return m(
      Section,
      {
        title: 'Idle-state residency',
        subtitle:
          'Time each CPU spent in each cpuidle (C-)state. Deeper states save ' +
          'more power but take longer to wake from — a source of wakeup latency.',
      },
      m(
        Card,
        {className: 'pf-sismo-page__table-card'},
        m(Grid, {
          columns: [
            {key: 'cpu', header: m(GridHeaderCell, 'Core')},
            {key: 'states', header: m(GridHeaderCell, 'Idle-state residency')},
          ],
          rowData: data,
        }),
      ),
    );
  }

  private renderBlame(trace: Trace, d: LatencyDetail): m.Children {
    if (!d.hasPriv) {
      return m(
        Section,
        {
          title: 'Scheduling latency',
          subtitle:
            'What held the CPU while your threads were runnable but waiting.',
        },
        m(
          Callout,
          {icon: 'info', intent: Intent.Primary},
          'No profiled processes detected — record with `sismo record` to tag ' +
            'the processes you’re profiling, then this attributes your ' +
            'scheduling delay to whoever was running instead of you.',
        ),
      );
    }
    return m(
      Section,
      {
        title: 'What was running while you were runnable',
        subtitle:
          'For each other process/thread on the system: how long it was on the ' +
          'CPU while one of your threads was waiting to run. Higher = more of ' +
          'your scheduling latency this attributes to.',
      },
      m(Tabs, {
        activeTabKey: this.blameTab,
        onTabChange: (key) => {
          this.blameTab = key as 'processes' | 'threads';
        },
        tabs: [
          {
            key: 'processes',
            title: 'Processes',
            content: renderBlameProcessTable(trace, d.blame),
          },
          {
            key: 'threads',
            title: 'Threads',
            content: renderBlameThreadTable(trace, d.threadBlame),
          },
        ],
      }),
    );
  }

  private renderComingSoon(): m.Children {
    return m(
      Section,
      {
        title: 'More latency analysis (coming soon)',
        subtitle:
          'Scheduling-delay distribution, long blocking syscalls, IO waits, ' +
          'wakeup chains and critical paths.',
      },
      m(
        Card,
        {className: 'pf-sismo-page__hero pf-sismo-page__hero--placeholder'},
        m(
          '.pf-sismo-page__hero-head',
          m(
            '.pf-sismo-page__hero-titlewrap',
            m('.pf-sismo-page__hero-tagline', 'Not yet implemented.'),
          ),
        ),
      ),
    );
  }

  private async load(trace: Trace, priv: PrivilegedSet): Promise<void> {
    try {
      const [detail, triage] = await Promise.all([
        loadLatencyDetail(trace.engine, priv),
        loadCpuTriage(trace.engine, priv).catch(() => undefined),
      ]);
      this.data = detail;
      this.triage = triage;
    } catch (e) {
      this.error =
        e instanceof Error ? e.message : 'Failed to load latency detail';
    }
    m.redraw();
  }
}

function renderBlameProcessTable(
  trace: Trace,
  rows: ReadonlyArray<CpuBlameRow>,
): m.Children {
  if (rows.length === 0) {
    return m(EmptyState, {
      icon: 'block',
      title:
        'Nothing was blocking you — your threads got the CPU as soon as they ' +
        'became runnable.',
    });
  }
  const data = rows.map((r) => [
    m(GridCell, {wrap: true}, renderProcessLink(trace, r.name, r.pid, r.upid)),
    m(GridCell, {align: 'right'}, fmtDuration(trace, r.blockedNs)),
  ]);
  return m(
    Card,
    {className: 'pf-sismo-page__table-card'},
    m(Grid, {
      columns: [
        {key: 'name', header: m(GridHeaderCell, 'Process')},
        {
          key: 'blocked',
          header: m(GridHeaderCell, 'Time on CPU while you wanted it'),
        },
      ],
      rowData: data,
    }),
  );
}

function renderBlameThreadTable(
  trace: Trace,
  rows: ReadonlyArray<CpuThreadBlameRow>,
): m.Children {
  if (rows.length === 0) {
    return m(EmptyState, {
      icon: 'block',
      title:
        'No blocking threads — your threads got the CPU as soon as they became ' +
        'runnable.',
    });
  }
  const data = rows.map((r) => [
    m(
      GridCell,
      {wrap: true},
      renderThreadLink(trace, r.threadName, r.tid, r.utid),
    ),
    m(GridCell, {wrap: true}, r.processName ?? '—'),
    m(GridCell, {align: 'right'}, fmtDuration(trace, r.blockedNs)),
  ]);
  return m(
    Card,
    {className: 'pf-sismo-page__table-card'},
    m(Grid, {
      columns: [
        {key: 'thread', header: m(GridHeaderCell, 'Thread')},
        {key: 'process', header: m(GridHeaderCell, 'Process')},
        {
          key: 'blocked',
          header: m(GridHeaderCell, 'Time on CPU while you wanted it'),
        },
      ],
      rowData: data,
    }),
  );
}
