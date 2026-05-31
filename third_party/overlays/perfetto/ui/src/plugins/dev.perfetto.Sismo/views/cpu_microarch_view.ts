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

// CPU "Microarchitecture" tab: were the cycles productive? Built from per-sample
// PMU follower counters (instructions, cycles, stalls, misses) — overall IPC and
// stall breakdown, then per-function IPC so you can see which hot functions are
// efficient vs stalled.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {Section} from '../../../widgets/section';
import {Card} from '../../../widgets/card';
import {Grid, GridCell, GridHeaderCell} from '../../../widgets/grid';
import {EmptyState} from '../../../widgets/empty_state';
import {Callout} from '../../../widgets/callout';
import {Intent} from '../../../widgets/common';
import {Icon} from '../../../widgets/icon';
import {Tooltip} from '../../../widgets/tooltip';
import {
  loadMicroarchCounters,
  type MicroarchCounters,
  type MicroarchFuncRow,
  type MicroarchTotals,
} from '../cpu_data';
import {fmtCount, fmtIpc, fmtMetric, fmtPercent} from '../format';
import type {PrivilegedSet} from '../privileged_set';

export interface CpuMicroarchViewAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
}

export class CpuMicroarchView
  implements m.ClassComponent<CpuMicroarchViewAttrs>
{
  private data?: MicroarchCounters;
  private error?: string;

  oninit({attrs}: m.CVnode<CpuMicroarchViewAttrs>) {
    this.load(attrs.trace, attrs.priv);
  }

  view(): m.Children {
    if (this.error !== undefined) {
      return m(Callout, {icon: 'error', intent: Intent.Danger}, this.error);
    }
    if (this.data === undefined) {
      return m(EmptyState, {
        icon: 'hourglass_empty',
        title: 'Loading hardware counters…',
      });
    }
    switch (this.data.state) {
      case 'no-counters':
        return renderNoCounters();
      case 'all-zero':
        return renderAllZero(this.data.totalSamples);
      case 'ok':
        return this.renderCounters(this.data);
    }
  }

  private renderCounters(d: MicroarchCounters): m.Children {
    const hasStalls =
      d.totals.feStallCycles !== null || d.totals.beStallCycles !== null;
    return m(
      Section,
      {
        title: 'Microarchitecture',
        subtitle:
          'Whether the cycles were productive. IPC near the core’s width means ' +
          'you’re retiring instructions; low IPC with high stalls means the ' +
          'core was busy but waiting (memory, branches, frontend).',
      },
      m('.pf-sismo-page__stat-row', renderHeadline(d.totals)),
      m(
        '.pf-sismo-page__tab-pane',
        m('.pf-sismo-page__tab-pane-label', 'Per-function efficiency'),
        renderFuncTable(d.perFunc, hasStalls),
      ),
    );
  }

  private async load(trace: Trace, priv: PrivilegedSet): Promise<void> {
    try {
      this.data = await loadMicroarchCounters(trace.engine, priv);
    } catch (e) {
      this.error =
        e instanceof Error ? e.message : 'Failed to load hardware counters';
    }
    m.redraw();
  }
}

function renderHeadline(t: MicroarchTotals): m.Children {
  const cards: StatCard[] = [
    {
      label: 'IPC',
      value: fmtIpc(t.ipc),
      help: 'Instructions retired per cycle, summed over all in-scope samples. ' +
        'Higher is better; the ceiling is the core’s issue width.',
    },
    {label: 'Instructions', value: fmtMetric(t.instructions)},
    {label: 'Cycles', value: fmtMetric(t.cycles)},
  ];
  if (t.feStallCycles !== null) {
    cards.push({
      label: 'Frontend stalls',
      value: fmtPercent(stallFrac(t.feStallCycles, t.cycles)),
      help: 'Cycles stalled waiting for instructions to issue (frontend-bound: ' +
        'i-cache misses, branch resteers), as a share of all cycles.',
    });
  }
  if (t.beStallCycles !== null) {
    cards.push({
      label: 'Backend stalls',
      value: fmtPercent(stallFrac(t.beStallCycles, t.cycles)),
      help: 'Cycles stalled with instructions unable to retire (backend-bound: ' +
        'data-cache/memory latency, execution-port contention).',
    });
  }
  if (t.cacheMisses !== null) {
    cards.push({label: 'Cache misses', value: fmtMetric(t.cacheMisses)});
  }
  if (t.branchMisses !== null) {
    cards.push({label: 'Branch misses', value: fmtMetric(t.branchMisses)});
  }
  return cards.map(renderStatCard);
}

function renderFuncTable(
  rows: ReadonlyArray<MicroarchFuncRow>,
  hasStalls: boolean,
): m.Children {
  if (rows.length === 0) {
    return m(EmptyState, {icon: 'code', title: 'No symbolised samples'});
  }
  const columns = [
    {key: 'fn', header: m(GridHeaderCell, 'Function')},
    {key: 'samples', header: m(GridHeaderCell, 'Samples')},
    {key: 'instr', header: m(GridHeaderCell, 'Instructions')},
    {key: 'cycles', header: m(GridHeaderCell, 'Cycles')},
    {key: 'ipc', header: m(GridHeaderCell, 'IPC')},
  ];
  if (hasStalls) {
    columns.push(
      {key: 'fe', header: m(GridHeaderCell, 'FE stall')},
      {key: 'be', header: m(GridHeaderCell, 'BE stall')},
    );
  }
  const data = rows.map((r) => {
    const cells = [
      m(
        GridCell,
        {wrap: true},
        m('span', r.name),
        r.mappingName !== null &&
          m('span.pf-sismo-page__muted', ` — ${shortMapping(r.mappingName)}`),
      ),
      m(GridCell, {align: 'right'}, fmtCount(r.samples)),
      m(GridCell, {align: 'right'}, fmtMetric(r.instructions)),
      m(GridCell, {align: 'right'}, fmtMetric(r.cycles)),
      m(GridCell, {align: 'right'}, fmtIpc(r.ipc)),
    ];
    if (hasStalls) {
      cells.push(
        m(GridCell, {align: 'right'}, fmtPercent(r.feStallPct)),
        m(GridCell, {align: 'right'}, fmtPercent(r.beStallPct)),
      );
    }
    return cells;
  });
  return m(
    Card,
    {className: 'pf-sismo-page__table-card'},
    m(Grid, {columns, rowData: data}),
  );
}

function renderNoCounters(): m.Children {
  return m(
    Section,
    {
      title: 'Microarchitecture',
      subtitle: 'Were the cycles productive? Requires PMU hardware counters.',
    },
    m(
      Callout,
      {icon: 'science', intent: Intent.Primary},
      m('strong', 'No hardware counters in this trace.'),
      m(
        'p',
        'This trace was recorded with only the sampling timebase. To break ' +
          'down IPC and frontend/backend stalls per function, re-record with ' +
          'PMU follower counters enabled (instructions, cpu-cycles, ' +
          'stalled-cycles-frontend/backend, cache-misses, branch-misses). Each ' +
          'sample then carries the counter vector this view attributes down to ' +
          'each function.',
      ),
    ),
  );
}

function renderAllZero(samples: number): m.Children {
  return m(
    Section,
    {
      title: 'Microarchitecture',
      subtitle: 'Were the cycles productive? Requires a working PMU.',
    },
    m(
      Callout,
      {icon: 'warning', intent: Intent.Warning},
      m('strong', 'Hardware counters were recorded but read zero.'),
      m(
        'p',
        `${fmtCount(samples)} samples carry counter slots, but every ` +
          'instructions/cycles value is zero — the CPU’s PMU isn’t actually ' +
          'counting. This is typical inside a VM whose hypervisor doesn’t ' +
          'expose a working virtual PMU. Record on bare metal (or a host with ' +
          'vPMU passthrough) to get real IPC and stall data.',
      ),
    ),
  );
}

interface StatCard {
  readonly label: string;
  readonly value: string;
  readonly help?: string;
}

function renderStatCard({label, value, help}: StatCard): m.Children {
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

function stallFrac(stallCycles: number | null, cycles: number | null): number | null {
  if (stallCycles === null || cycles === null || cycles === 0) return null;
  return stallCycles / cycles;
}

function shortMapping(path: string): string {
  const slash = path.lastIndexOf('/');
  return slash >= 0 ? path.slice(slash + 1) : path;
}
