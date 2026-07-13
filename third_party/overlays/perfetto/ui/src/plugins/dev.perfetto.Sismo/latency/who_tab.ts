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
import {
  loadLatencyDetail,
  type CpuIdleStateRow,
  type LatencyDetail,
  type OccupantShare,
  type WakerRow,
} from '../cpu_data';
import {fmtDuration, fmtPercent} from '../format';
import {loadingBody, renderProcessLink, renderThreadLink} from '../page_common';
import {
  Meter,
  meterReadout,
  type MeterColor,
} from '../../dev.perfetto.SismoWidgets/meter';
import type {PrivilegedSet} from '../privileged_set';

interface WhoTabAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
}

export class LatencyWhoTab implements m.ClassComponent<WhoTabAttrs> {
  private readonly queue = new SerialTaskQueue();
  private readonly detailSlot = new QuerySlot<LatencyDetail>(this.queue);

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
      this.renderRunnableDelay(trace, data),
      this.renderWakers(trace, data),
      this.renderIdleStates(data.idleStates),
    ]);
  }

  // "Why your threads waited for a core" — the runnable-but-not-scheduled delay,
  // attributed intra-process-first. The common cause of a multithreaded app
  // sitting runnable is its OWN other threads holding the cores (self-contention
  // / oversubscription), not another process. So this leads with your threads,
  // then other processes, then notes whether a core was even free (a placement
  // problem, not contention).
  private renderRunnableDelay(trace: Trace, d: LatencyDetail): m.Children {
    const title = 'Why your threads waited for a core';
    const subtitle =
      'When a thread was ready to run but not scheduled — what held the cores ' +
      'instead. Your own threads (self-contention) are the usual cause; shares ' +
      'are of the CPU that ran while you waited.';
    if (!d.hasPriv) {
      return m(
        Section,
        {title, subtitle},
        m(
          Callout,
          {icon: 'info', intent: Intent.Primary},
          'No profiled processes detected — record with `sismo record` to tag ' +
            'the processes you’re profiling.',
        ),
      );
    }
    const r = d.runnable;
    if (r.totalNs === 0n) {
      return m(
        Section,
        {title, subtitle},
        m(EmptyState, {
          icon: 'check_circle',
          title:
            'Your threads never waited for a core — they were scheduled as soon ' +
            'as they became runnable.',
        }),
      );
    }
    const selfPct = fmtPercent(r.selfFrac, 0);
    const ctxPct = fmtPercent(r.contextFrac, 0);
    const lead =
      r.selfFrac >= r.contextFrac
        ? `Your threads spent ${fmtDuration(trace, r.totalNs)} runnable but not ` +
          `scheduled. ${selfPct} of the CPU that ran instead was your OWN ` +
          'threads — self-contention: more hot threads than cores.'
        : `Your threads spent ${fmtDuration(trace, r.totalNs)} runnable but not ` +
          `scheduled. ${ctxPct} of the CPU that ran instead belonged to other ` +
          'processes on the machine.';
    const placement =
      r.idleAvailFrac >= 0.1
        ? ` A core was actually free for ${fmtPercent(r.idleAvailFrac, 0)} of ` +
          'that wait — the scheduler left you unplaced (affinity, cgroup caps, ' +
          'or wakeup latency), which is not contention.'
        : ' Cores were busy essentially the whole time, so this is contention, ' +
          'not scheduler placement.';

    const colors: [MeterColor, MeterColor] = ['primary', 'info'];
    const bar = [
      {color: colors[0], frac: r.selfFrac},
      {color: colors[1], frac: r.contextFrac},
    ];
    const legend = [
      {color: colors[0], label: 'Your own threads', value: selfPct},
      {color: colors[1], label: 'Other processes', value: ctxPct},
    ];
    return m(
      Section,
      {title, subtitle},
      m(Callout, {icon: 'insights', intent: Intent.Primary}, lead + placement),
      m(Meter, {
        label: 'What held the cores while you were runnable',
        help:
          'Share of the CPU time that ran during your threads’ runnable-but-' +
          'not-scheduled windows: your own threads versus other processes. ' +
          'Colours are roles, not a good/bad scale.',
        primary: meterReadout(selfPct, ' was your own threads'),
        bar,
        legend,
      }),
      r.selfThreads.length > 0 &&
        m(
          'div',
          m('.pf-sismo-page__tab-pane-label', 'Your threads that held the cores'),
          renderShareTable(trace, r.selfThreads, 'thread'),
        ),
      r.contextProcs.length > 0 &&
        m(
          'div',
          m('.pf-sismo-page__tab-pane-label', 'Other processes'),
          renderShareTable(trace, r.contextProcs, 'process'),
        ),
    );
  }

  // "Who woke you" — the causal side of a voluntary block. When one of your
  // threads was blocked (on a lock, a condvar, a pipe, …), the wakeup that ended
  // the block names the thread that did it. Timer/IRQ wakeups (a sleep or
  // timeout expiring) have no meaningful waker, so they're summarised, not
  // blamed on whatever happened to run.
  private renderWakers(trace: Trace, d: LatencyDetail): m.Children {
    const subtitle =
      'When a thread blocked and later woke, this names who woke it and sums ' +
      'the time it was blocked first. Locks, condvars and pipes show up as the ' +
      'thread that released them.';
    if (!d.hasPriv) {
      return m(
        Section,
        {title: 'Who woke you', subtitle},
        m(
          Callout,
          {icon: 'info', intent: Intent.Primary},
          'No profiled processes detected — record with `sismo record` to tag ' +
            'the processes you’re profiling.',
        ),
      );
    }
    const w = d.wakers;
    const total = Number(w.threadNs) + Number(w.timerIrqNs);
    if (total === 0) {
      return m(
        Section,
        {title: 'Who woke you', subtitle},
        m(EmptyState, {
          icon: 'notifications_off',
          title:
            'No wakeup data — the trace has no sched_wakeup events to attribute ' +
            'blocks to a waker.',
        }),
      );
    }
    const irqFrac = Number(w.timerIrqNs) / total;
    const note =
      `Of the blocked time with a recorded wakeup, ${fmtPercent(1 - irqFrac, 0)} ` +
      `ended when another thread woke you; ${fmtPercent(irqFrac, 0)} ended on a ` +
      'timer or device IRQ — a sleep or timeout expiring, with no thread to ' +
      'blame.';
    return m(
      Section,
      {title: 'Who woke you', subtitle},
      m(Callout, {icon: 'insights', intent: Intent.Primary}, note),
      renderWakerTable(trace, w.threadWakers),
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

function renderWakerTable(
  trace: Trace,
  rows: ReadonlyArray<WakerRow>,
): m.Children {
  if (rows.length === 0) {
    return m(EmptyState, {
      icon: 'notifications_off',
      title:
        'Nothing woke you from a block — every wait ended on its own (a timer ' +
        'or timeout), not because another thread signalled you.',
    });
  }
  const data = rows.map((r) => [
    m(
      GridCell,
      {wrap: true},
      renderThreadLink(trace, r.threadName, r.tid, r.utid),
    ),
    m(GridCell, {wrap: true}, r.processName ?? '—'),
    m(GridCell, {align: 'right'}, fmtDuration(trace, r.wokeNs)),
    m(GridCell, {align: 'right'}, `${r.wakeups}`),
  ]);
  return m(
    Card,
    {className: 'pf-sismo-page__table-card'},
    m(Grid, {
      columns: [
        {key: 'thread', header: m(GridHeaderCell, 'Woke you')},
        {key: 'process', header: m(GridHeaderCell, 'Process')},
        {
          key: 'blocked',
          header: m(GridHeaderCell, 'Time you were blocked first'),
        },
        {key: 'wakeups', header: m(GridHeaderCell, 'Wakeups')},
      ],
      rowData: data,
    }),
  );
}

// A ranked list of occupants (your threads, or other processes) by their share
// of the CPU that ran while your threads were runnable. Share, not seconds — the
// intersect over-counts across cores, so only the relative split is meaningful.
function renderShareTable(
  trace: Trace,
  rows: ReadonlyArray<OccupantShare>,
  kind: 'thread' | 'process',
): m.Children {
  const isThread = kind === 'thread';
  const data = rows.map((r) => {
    // Self threads roll up by name: a pool of N shows the bare name (linking to
    // one of N would be misleading); a lone thread keeps its link.
    const nameCell =
      isThread && r.count > 1
        ? m(GridCell, {wrap: true}, r.label)
        : isThread
          ? m(GridCell, {wrap: true}, renderThreadLink(trace, r.label, r.tid, r.id))
          : m(GridCell, {wrap: true}, renderProcessLink(trace, r.label, r.pid, r.id));
    const cells = [nameCell];
    if (isThread) cells.push(m(GridCell, {align: 'right'}, `${r.count}`));
    cells.push(m(GridCell, {align: 'right'}, fmtPercent(r.frac, 1)));
    return cells;
  });
  return m(
    Card,
    {className: 'pf-sismo-page__table-card'},
    m(Grid, {
      columns: [
        {
          key: 'name',
          header: m(GridHeaderCell, isThread ? 'Thread name' : 'Process'),
        },
        ...(isThread
          ? [{key: 'count', header: m(GridHeaderCell, 'Threads')}]
          : []),
        {
          key: 'share',
          header: m(GridHeaderCell, 'Share of CPU that ran instead'),
        },
      ],
      rowData: data,
    }),
  );
}
