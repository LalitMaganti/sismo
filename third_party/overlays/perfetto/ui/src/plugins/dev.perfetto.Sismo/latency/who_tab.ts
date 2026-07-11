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

// "Who it waited on" — the Latency deep-dive that answers L3 in full: which
// context process/thread held the CPU while your threads were runnable, plus
// idle-state residency (a wakeup-latency source). The wakeup-causality graph
// ("who WOKE you") lands here later, once wakeup edges are captured.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {QuerySlot, SerialTaskQueue} from '../../../base/query_slot';
import {Section} from '../../../widgets/section';
import {Card} from '../../../widgets/card';
import {Grid, GridCell, GridHeaderCell} from '../../../widgets/grid';
import {EmptyState} from '../../../widgets/empty_state';
import {Callout} from '../../../widgets/callout';
import {Intent} from '../../../widgets/common';
import {Tabs} from '../../../widgets/tabs';
import {
  loadLatencyDetail,
  type CpuBlameRow,
  type CpuIdleStateRow,
  type CpuThreadBlameRow,
  type LatencyDetail,
} from '../cpu_data';
import {fmtDuration} from '../format';
import {loadingBody, renderProcessLink, renderThreadLink} from '../page_common';
import type {PrivilegedSet} from '../privileged_set';

interface WhoTabAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
}

export class LatencyWhoTab implements m.ClassComponent<WhoTabAttrs> {
  private readonly queue = new SerialTaskQueue();
  private readonly detailSlot = new QuerySlot<LatencyDetail>(this.queue);
  private blameTab: 'processes' | 'threads' = 'processes';

  onremove(): void {
    this.detailSlot.dispose();
  }

  view({attrs}: m.CVnode<WhoTabAttrs>): m.Children {
    const {trace, priv} = attrs;
    let data: LatencyDetail | undefined;
    try {
      data = this.detailSlot.use({
        key: {upids: [...priv.upids]},
        queryFn: () => loadLatencyDetail(trace.engine, priv),
      }).data;
    } catch (e) {
      return m(
        Callout,
        {icon: 'error', intent: Intent.Danger},
        e instanceof Error ? e.message : 'Failed to load blame detail',
      );
    }
    if (data === undefined) return loadingBody('Reading the trace…');
    if (!data.hasSched) {
      return m(
        Callout,
        {icon: 'info', intent: Intent.Primary},
        'This trace has no scheduling data, so there is nothing to attribute ' +
          'the waiting to. Re-record with the sched data source.',
      );
    }
    return m('.pf-sismo-tab__body', [
      this.renderBlame(trace, data),
      this.renderIdleStates(data.idleStates),
    ]);
  }

  private renderBlame(trace: Trace, d: LatencyDetail): m.Children {
    if (!d.hasPriv) {
      return m(
        Section,
        {
          title: 'What was running while you were runnable',
          subtitle: 'Attributes your scheduling delay to whatever ran instead.',
        },
        m(
          Callout,
          {icon: 'info', intent: Intent.Primary},
          'No profiled processes detected — record with `sismo record` to tag ' +
            'the processes you’re profiling.',
        ),
      );
    }
    return m(
      Section,
      {
        title: 'What was running while you were runnable',
        subtitle:
          'For each context process/thread: how long it held the CPU while one ' +
          'of your threads was waiting to run. Higher = more of your scheduling ' +
          'delay this attributes to.',
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

  private renderIdleStates(rows: ReadonlyArray<CpuIdleStateRow>): m.Children {
    const subtitle =
      'Time each CPU spent in each cpuidle (C-)state. Deeper states save more ' +
      'power but take longer to wake from — a source of wakeup latency.';
    if (rows.length === 0) {
      return m(
        Section,
        {title: 'Idle-state residency', subtitle},
        m(EmptyState, {icon: 'bedtime', title: 'No idle-state data'}),
      );
    }
    const byCpu = new Map<number, CpuIdleStateRow[]>();
    for (const r of rows) {
      const b = byCpu.get(r.cpu);
      if (b === undefined) byCpu.set(r.cpu, [r]);
      else b.push(r);
    }
    const cpus = [...byCpu.keys()].sort((a, b) => a - b);
    const data = cpus.map((cpu) => {
      const summary = byCpu
        .get(cpu)!
        .map((s) => `${s.state} ${s.percentage.toFixed(0)}%`)
        .join(', ');
      return [m(GridCell, `CPU ${cpu}`), m(GridCell, {wrap: true}, summary)];
    });
    return m(
      Section,
      {title: 'Idle-state residency', subtitle},
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
