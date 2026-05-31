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
import {renderProcessLink, renderThreadLink} from '../page_common';
import type {
  CpuDetail,
  CpuProcessRow,
  CpuSummary,
  CpuThreadRow,
} from '../cpu_data';
import {fmtDuration, fmtMegacycles, fmtPercent} from '../format';

export interface CpuConsumersViewAttrs {
  readonly trace: Trace;
  readonly data: CpuDetail;
}

export class CpuConsumersView
  implements m.ClassComponent<CpuConsumersViewAttrs>
{
  private consumersTab: 'processes' | 'threads' = 'processes';

  view({attrs}: m.CVnode<CpuConsumersViewAttrs>): m.Children {
    const {trace, data: d} = attrs;
    const hasPriv =
      d.privilegedProcesses.length > 0 || d.privilegedThreads.length > 0;
    return m(
      Section,
      {
        title: hasPriv ? 'Top CPU consumers' : 'Top consumers by CPU time',
        subtitle: hasPriv
          ? 'Your processes/threads first, then the heaviest other consumers ' +
            'on the system.'
          : 'Heaviest CPU consumers in the trace. No record-time marker found ' +
            '— your processes are not differentiated from the rest.',
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
            content: this.renderProcessPane(trace, d),
          },
          {
            key: 'threads',
            title: 'Threads',
            content: this.renderThreadPane(trace, d),
          },
        ],
      }),
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
      m(GridCell, {wrap: true}, renderProcessLink(trace, r.name, r.pid, r.upid)),
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
