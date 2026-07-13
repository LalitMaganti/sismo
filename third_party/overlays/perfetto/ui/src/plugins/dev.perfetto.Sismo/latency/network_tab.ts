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

// "Network" — the network slice of the wait-type axis. When a recv parks off-CPU
// waiting for data, the tcp_recvmsg kprobe tags it with the remote it's waiting
// on, so this clusters blocking recvs by peer (the network analog of the Locks
// tab): which remote is your code stuck waiting on. Click a peer to see the
// threads blocked on it.

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
  loadNetworkPeers,
  loadNetPeerDetail,
  type NetworkPeers,
  type NetPeerRow,
  type NetPeerDetail,
} from '../cpu_data';
import {fmtDuration, fmtCount} from '../format';
import {loadingBody, renderBar} from '../page_common';
import type {PrivilegedSet} from '../privileged_set';

interface NetworkTabAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
}

export class LatencyNetworkTab implements m.ClassComponent<NetworkTabAttrs> {
  private readonly queue = new SerialTaskQueue();
  private readonly slot = new QuerySlot<NetworkPeers>(this.queue);
  private readonly detailSlot = new QuerySlot<NetPeerDetail>(this.queue);

  private selected?: NetPeerRow;

  onremove(): void {
    this.slot.dispose();
    this.detailSlot.dispose();
  }

  view({attrs}: m.CVnode<NetworkTabAttrs>): m.Children {
    const {trace, priv} = attrs;
    const data = this.slot.use({
      key: {upids: [...priv.upids]},
      queryFn: () => loadNetworkPeers(trace.engine, priv),
    }).data;
    if (data === undefined) return loadingBody('Clustering network waits…');
    const body =
      this.selected !== undefined
        ? this.renderDetail(attrs, this.selected)
        : this.renderList(attrs, data);
    return m('.pf-sismo-tab__body', body);
  }

  private renderList(attrs: NetworkTabAttrs, d: NetworkPeers): m.Children {
    const title = 'Network';
    const subtitle =
      'Every remote your threads blocked on in recv, waiting for data to ' +
      'arrive. Ranked by the wall-clock lost waiting. Click a peer to drill in.';
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
    if (d.peers.length === 0) {
      return m(
        Section,
        {title, subtitle},
        m(EmptyState, {
          icon: 'lan',
          title:
            'Your threads never blocked on a TCP recv — no network waits in ' +
            'this trace (or the peers were IPv6, not yet captured).',
        }),
      );
    }
    return m(
      Section,
      {title, subtitle},
      this.renderLead(attrs.trace, d),
      this.renderTable(attrs.trace, d),
    );
  }

  private renderLead(trace: Trace, d: NetworkPeers): m.Children {
    const top = d.peers[0];
    const lead =
      `Your threads lost ${fmtDuration(trace, d.totalWaitNs)} blocked on ` +
      `network recv across ${fmtCount(d.peers.length)} peer` +
      `${d.peers.length === 1 ? '' : 's'}. The most-waited-on is ` +
      `${top.addr}:${top.port} — ${fmtDuration(trace, top.waitNs)} across ` +
      `${fmtCount(top.blocks)} blocks (${avgLabel(top.waitNs, top.blocks)}).`;
    return m(Callout, {icon: 'insights', intent: Intent.Primary}, lead);
  }

  private renderTable(trace: Trace, d: NetworkPeers): m.Children {
    const maxWait = Number(d.peers[0].waitNs) || 1;
    const rows = d.peers.map((p) => [
      m(
        GridCell,
        {wrap: true},
        m(
          Anchor,
          {
            onclick: (e: Event) => {
              e.preventDefault();
              this.selected = p;
            },
          },
          `${p.addr}:${p.port}`,
        ),
      ),
      m(
        GridCell,
        renderBar(Number(p.waitNs) / maxWait, fmtDuration(trace, p.waitNs)),
      ),
      m(GridCell, {align: 'right'}, fmtCount(p.blocks)),
      m(GridCell, {align: 'right'}, avgLabel(p.waitNs, p.blocks)),
      m(GridCell, {align: 'right'}, fmtCount(p.threads)),
    ]);
    return m(
      Card,
      {className: 'pf-sismo-page__table-card'},
      m(Grid, {
        columns: [
          {key: 'peer', header: m(GridHeaderCell, 'Peer')},
          {key: 'wait', header: m(GridHeaderCell, 'Wait total')},
          {key: 'blocks', header: m(GridHeaderCell, 'Blocks')},
          {key: 'avg', header: m(GridHeaderCell, 'Avg wait')},
          {key: 'threads', header: m(GridHeaderCell, 'Threads')},
        ],
        rowData: rows,
      }),
    );
  }

  private renderDetail(attrs: NetworkTabAttrs, peer: NetPeerRow): m.Children {
    const detail = this.detailSlot.use({
      key: {peer: peer.peerId.toString()},
      queryFn: () => loadNetPeerDetail(attrs.trace.engine, peer.peerId),
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
        'All peers',
      ),
    );
    const title = `${peer.addr}:${peer.port}`;
    if (detail === undefined) {
      return [back, m(Section, {title}, loadingBody('Reading peer…'))];
    }
    const lead =
      `${fmtCount(detail.threads)} thread${detail.threads === 1 ? '' : 's'} ` +
      `blocked on this peer ${fmtCount(detail.blocks)} times for ` +
      `${fmtDuration(attrs.trace, detail.waitNs)} total — ` +
      `${avgLabel(detail.waitNs, detail.blocks)}.`;
    return [
      back,
      m(
        Section,
        {title, subtitle: 'Blocked in recv, waiting for this remote to send.'},
        m(Callout, {icon: 'insights', intent: Intent.Primary}, lead),
        m('.pf-sismo-page__tab-pane-label', 'Threads that blocked on it'),
        renderWaiters(attrs.trace, detail),
      ),
    ];
  }
}

function renderWaiters(trace: Trace, d: NetPeerDetail): m.Children {
  const max = Number(d.waiters[0]?.waitNs ?? 0n) || 1;
  const rows = d.waiters.map((w) => [
    m(GridCell, {wrap: true}, w.threadName),
    m(GridCell, {align: 'right'}, fmtCount(w.threads)),
    m(GridCell, renderBar(Number(w.waitNs) / max, fmtDuration(trace, w.waitNs))),
    m(GridCell, {align: 'right'}, fmtCount(w.blocks)),
  ]);
  return m(
    Card,
    {className: 'pf-sismo-page__table-card'},
    m(Grid, {
      columns: [
        {key: 'thread', header: m(GridHeaderCell, 'Thread name')},
        {key: 'count', header: m(GridHeaderCell, 'Threads')},
        {key: 'wait', header: m(GridHeaderCell, 'Wait total')},
        {key: 'blocks', header: m(GridHeaderCell, 'Blocks')},
      ],
      rowData: rows,
    }),
  );
}

function avgLabel(waitNs: bigint, blocks: number): string {
  const us = Number(waitNs) / Math.max(1, blocks) / 1000;
  if (us >= 1000) return `${(us / 1000).toFixed(1)} ms/wait`;
  return `${us.toFixed(0)} µs/wait`;
}
