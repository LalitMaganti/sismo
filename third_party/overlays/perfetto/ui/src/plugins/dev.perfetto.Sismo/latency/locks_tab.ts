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

// "Locks" — the lock-contention slice of the wait-type axis. Every contended
// futex the BPF collector saw is one row, clustered by its uaddr (the lock's
// identity), so two locks taken at the same code site stay distinct. Ranked by
// the wall-clock the profiled threads lost blocked on each; clicking a lock
// drills into its acquisition sites and the threads that blocked on it.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {QuerySlot, SerialTaskQueue} from '../../../base/query_slot';
import {Section} from '../../../widgets/section';
import {Card} from '../../../widgets/card';
import {Anchor} from '../../../widgets/anchor';
import {Grid, GridCell, GridHeaderCell} from '../../../widgets/grid';
import {EmptyState} from '../../../widgets/empty_state';
import {Callout} from '../../../widgets/callout';
import {Intent} from '../../../widgets/common';
import {
  loadLockContention,
  loadLockDetail,
  type LockContention,
  type LockDetail,
  type LockRow,
} from '../cpu_data';
import {fmtDuration, fmtCount} from '../format';
import {loadingBody, renderBar, actionLink} from '../page_common';
import type {PrivilegedSet} from '../privileged_set';

interface LocksTabAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
  readonly onNavigate: (tab: string) => void;
}

export class LatencyLocksTab implements m.ClassComponent<LocksTabAttrs> {
  private readonly queue = new SerialTaskQueue();
  private readonly slot = new QuerySlot<LockContention>(this.queue);
  private readonly detailSlot = new QuerySlot<LockDetail>(this.queue);

  // The lock the user drilled into, or undefined for the ranked list.
  private selected?: LockRow;

  onremove(): void {
    this.slot.dispose();
    this.detailSlot.dispose();
  }

  view({attrs}: m.CVnode<LocksTabAttrs>): m.Children {
    const {trace, priv} = attrs;
    const data = this.slot.use({
      key: {upids: [...priv.upids]},
      queryFn: () => loadLockContention(trace.engine, priv),
    }).data;
    if (data === undefined) return loadingBody('Clustering lock waits…');
    const body =
      this.selected !== undefined
        ? this.renderDetail(attrs, this.selected)
        : this.renderList(attrs, data);
    return m('.pf-sismo-tab__body', body);
  }

  private renderList(attrs: LocksTabAttrs, d: LockContention): m.Children {
    const title = 'Locks';
    const subtitle =
      'Every contended lock your threads blocked on, clustered by the lock ' +
      'itself (its futex address) — so two locks taken from the same code stay ' +
      'apart. Ranked by the wall-clock lost waiting. Click a lock to drill in.';
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
    if (d.locks.length === 0) {
      return m(
        Section,
        {title, subtitle},
        m(EmptyState, {
          icon: 'lock_open',
          title:
            'Your threads never blocked on a lock — no contended futex waits in ' +
            'this trace.',
        }),
      );
    }
    return m(
      Section,
      {title, subtitle},
      this.renderLead(attrs.trace, d),
      this.renderTable(attrs.trace, d),
      m(
        Callout,
        {icon: 'lightbulb', intent: Intent.Primary},
        m(
          'span',
          'For who released each lock (the thread that woke your blocked ' +
            'thread), see ',
          actionLink('Who it waited on', 'open_in_new', () =>
            attrs.onNavigate('who'),
          ),
          '.',
        ),
      ),
    );
  }

  // The one-line read: how much was lost, on the hottest lock, and — the point
  // of clustering by instance — whether any single site hides several locks.
  private renderLead(trace: Trace, d: LockContention): m.Children {
    const top = d.locks[0];
    const lead =
      `Your threads lost ${fmtDuration(trace, d.totalWaitNs)} blocked on ` +
      `${fmtCount(d.locks.length)} lock${d.locks.length === 1 ? '' : 's'}. The ` +
      `hottest is contended in ${top.site} — ${fmtDuration(trace, top.waitNs)} ` +
      `across ${fmtCount(top.waits)} waits (${avgLabel(top)}).`;

    // Sites that take more than one distinct lock: exactly what a stack-only
    // view would merge and instance-clustering keeps apart.
    const perSite = new Map<string, number>();
    for (const l of d.locks) perSite.set(l.site, (perSite.get(l.site) ?? 0) + 1);
    const shared = [...perSite.entries()].filter(([, n]) => n > 1);
    const sharedNote =
      shared.length === 0
        ? undefined
        : shared
            .map(
              ([site, n]) =>
                `${n} distinct locks are contended in ${site} — same code, ` +
                'different objects.',
            )
            .join(' ');

    return [
      m(Callout, {icon: 'insights', intent: Intent.Primary}, lead),
      sharedNote !== undefined &&
        m(Callout, {icon: 'call_split', intent: Intent.Primary}, sharedNote),
    ];
  }

  private renderTable(trace: Trace, d: LockContention): m.Children {
    const maxWait = Number(d.locks[0].waitNs) || 1;
    const rows = d.locks.map((l) => [
      m(
        GridCell,
        {wrap: true},
        m(
          Anchor,
          {
            onclick: (e: Event) => {
              e.preventDefault();
              this.selected = l;
            },
          },
          l.site,
        ),
      ),
      m(GridCell, fmtAddr(l.addr)),
      m(
        GridCell,
        renderBar(Number(l.waitNs) / maxWait, fmtDuration(trace, l.waitNs)),
      ),
      m(GridCell, {align: 'right'}, fmtCount(l.waits)),
      m(GridCell, {align: 'right'}, avgUsLabel(l)),
      m(GridCell, {align: 'right'}, fmtCount(l.threads)),
    ]);
    return m(
      Card,
      {className: 'pf-sismo-page__table-card'},
      m(Grid, {
        columns: [
          {key: 'site', header: m(GridHeaderCell, 'Contended in')},
          {key: 'lock', header: m(GridHeaderCell, 'Lock')},
          {key: 'wait', header: m(GridHeaderCell, 'Wait total')},
          {key: 'waits', header: m(GridHeaderCell, 'Waits')},
          {key: 'avg', header: m(GridHeaderCell, 'Avg wait')},
          {key: 'threads', header: m(GridHeaderCell, 'Threads')},
        ],
        rowData: rows,
      }),
    );
  }

  private renderDetail(attrs: LocksTabAttrs, lock: LockRow): m.Children {
    const detail = this.detailSlot.use({
      key: {addr: lock.addr.toString()},
      queryFn: () => loadLockDetail(attrs.trace.engine, lock.addr),
    }).data;
    const back = m(
      '.pf-sismo-tab__back',
      m(
        Anchor,
        {
          icon: 'arrow_back',
          onclick: (e: Event) => {
            e.preventDefault();
            this.selected = undefined;
          },
        },
        'All locks',
      ),
    );
    const title = `Lock ${fmtAddr(lock.addr)}`;
    const subtitle = `Contended in ${lock.site}`;
    if (detail === undefined) {
      return [back, m(Section, {title, subtitle}, loadingBody('Reading lock…'))];
    }
    return [
      back,
      m(
        Section,
        {title, subtitle},
        this.renderDetailLead(attrs.trace, detail),
        detail.sites.length > 1 &&
          m(
            'div',
            m('.pf-sismo-page__tab-pane-label', 'Where it’s taken'),
            renderSites(attrs.trace, detail),
          ),
        m('.pf-sismo-page__tab-pane-label', 'Threads that blocked on it'),
        renderWaiters(attrs.trace, detail),
        m(
          Callout,
          {icon: 'lightbulb', intent: Intent.Primary},
          m(
            'span',
            'The thread that released this lock is the one that woke each ' +
              'blocked waiter — see ',
            actionLink('Who it waited on', 'open_in_new', () =>
              attrs.onNavigate('who'),
            ),
            '.',
          ),
        ),
      ),
    ];
  }

  private renderDetailLead(trace: Trace, d: LockDetail): m.Children {
    const lead =
      `${fmtCount(d.threads)} thread${d.threads === 1 ? '' : 's'} blocked on ` +
      `this lock ${fmtCount(d.waits)} times for ${fmtDuration(trace, d.waitNs)} ` +
      `total — ${avgDetailLabel(d)}.` +
      (d.sites.length > 1
        ? ` It’s taken from ${fmtCount(d.sites.length)} different sites.`
        : '');
    return m(Callout, {icon: 'insights', intent: Intent.Primary}, lead);
  }
}

function renderSites(trace: Trace, d: LockDetail): m.Children {
  const max = Number(d.sites[0].waitNs) || 1;
  const rows = d.sites.map((s) => [
    m(GridCell, {wrap: true}, s.site),
    m(GridCell, renderBar(Number(s.waitNs) / max, fmtDuration(trace, s.waitNs))),
    m(GridCell, {align: 'right'}, fmtCount(s.waits)),
  ]);
  return m(
    Card,
    {className: 'pf-sismo-page__table-card'},
    m(Grid, {
      columns: [
        {key: 'site', header: m(GridHeaderCell, 'Acquisition site')},
        {key: 'wait', header: m(GridHeaderCell, 'Wait total')},
        {key: 'waits', header: m(GridHeaderCell, 'Waits')},
      ],
      rowData: rows,
    }),
  );
}

function renderWaiters(trace: Trace, d: LockDetail): m.Children {
  const max = Number(d.waiters[0]?.waitNs ?? 0n) || 1;
  const rows = d.waiters.map((w) => [
    m(GridCell, {wrap: true}, w.threadName),
    m(GridCell, {align: 'right'}, fmtCount(w.threads)),
    m(GridCell, renderBar(Number(w.waitNs) / max, fmtDuration(trace, w.waitNs))),
    m(GridCell, {align: 'right'}, fmtCount(w.waits)),
  ]);
  return m(
    Card,
    {className: 'pf-sismo-page__table-card'},
    m(Grid, {
      columns: [
        {key: 'thread', header: m(GridHeaderCell, 'Thread name')},
        {key: 'count', header: m(GridHeaderCell, 'Threads')},
        {key: 'wait', header: m(GridHeaderCell, 'Wait total')},
        {key: 'waits', header: m(GridHeaderCell, 'Waits')},
      ],
      rowData: rows,
    }),
  );
}

// A compact, stable label for a lock's identity: the low bytes of its futex
// address. Not human-meaningful on its own, but distinguishes instances and is
// stable across the trace.
function fmtAddr(addr: bigint): string {
  const hex = addr.toString(16);
  return hex.length > 6 ? `0x…${hex.slice(-6)}` : `0x${hex}`;
}

function avgUsLabel(l: LockRow): string {
  return avgUs(l.waitNs, l.waits);
}

function avgUs(waitNs: bigint, waits: number): string {
  const us = Number(waitNs) / Math.max(1, waits) / 1000;
  if (us >= 1000) return `${(us / 1000).toFixed(1)} ms`;
  return `${us.toFixed(0)} µs`;
}

// "held too long" vs "acquired too often" — read straight off the wait
// distribution, no hold-time instrumentation. Many short waits = frequency
// contention; few long waits = long critical sections.
function personality(waitNs: bigint, waits: number): string {
  const us = Number(waitNs) / Math.max(1, waits) / 1000;
  if (waits > 10000 && us < 100) return 'acquired too often';
  if (us >= 200) return 'held too long';
  return 'contended';
}

function avgLabel(l: LockRow): string {
  return `${avgUs(l.waitNs, l.waits)}/wait, ${personality(l.waitNs, l.waits)}`;
}

function avgDetailLabel(d: LockDetail): string {
  return `${avgUs(d.waitNs, d.waits)}/wait, ${personality(d.waitNs, d.waits)}`;
}
