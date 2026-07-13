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

// The Latency Summary's kind-of-wait block: of the blocked (voluntary) time,
// what was the thread waiting FOR — the wait-type axis (locks, signaling, disk,
// network, sleep, …). Read straight from the off-CPU stacks, ranked by
// wall-clock. Each type links to its facet (Locks today; others open the
// cross-type flamegraph filtered later).

import m from 'mithril';
import type {WaitBreakdown} from '../cpu_data';
import {fmtPercent, fmtDurationNs} from '../format';
import {questionBlock, type DeeperAction} from '../cpu/block';
import {breakdownGrid} from '../cpu/grid';
import {EmptyState} from '../../../widgets/empty_state';

// Display label + the deep-dive tab each wait type drills into. Order here is
// only for the label map; rows are ranked by wall-clock.
const TYPE_META: Record<string, {label: string; tab: string}> = {
  lock: {label: 'Locks', tab: 'locks'},
  signaling: {label: 'Signaling / queues', tab: 'where'},
  network: {label: 'Network I/O', tab: 'network'},
  disk: {label: 'Disk I/O', tab: 'disk'},
  pipe: {label: 'Pipes / IPC', tab: 'where'},
  sleep: {label: 'Sleep / timers', tab: 'where'},
  poll: {label: 'Poll / epoll', tab: 'where'},
  memory: {label: 'Memory / faults', tab: 'where'},
  other: {label: 'Other', tab: 'where'},
};

function meta(type: string): {label: string; tab: string} {
  return TYPE_META[type] ?? {label: type, tab: 'where'};
}

export function waitTypeLabel(type: string): string {
  return meta(type).label;
}

export function renderWaitTypeBlock(
  d: WaitBreakdown,
  onNavigate: (tab: string) => void,
): m.Children {
  const question = 'What kind of wait was it?';
  const description =
    'Splits the blocked (voluntary) time by what the thread was waiting on — ' +
    'a lock, a signal, I/O, a sleep — read from the off-CPU stacks.';
  if (!d.hasPriv || d.totalNs === 0n || d.types.length === 0) {
    return questionBlock({question, description, answer: ''}, [
      m(EmptyState, {
        icon: 'do_not_disturb',
        title: 'No blocked time to classify in this trace.',
      }),
    ]);
  }
  const total = Number(d.totalNs);
  const top = d.types.slice(0, 3).map((t) => {
    const frac = Number(t.waitNs) / (total || 1);
    return `${fmtPercent(frac, 0)} ${meta(t.type).label.toLowerCase()}`;
  });
  const answer =
    top.length === 1
      ? `Essentially all of the blocked time was ${top[0]}.`
      : `Of the blocked time: ${top.join(', ')}` +
        (d.types.length > top.length ? ', and a tail of smaller types.' : '.');

  const byLabel = new Map<string, string>();
  for (const t of d.types) byLabel.set(meta(t.type).label, meta(t.type).tab);

  const rows = d.types.map((t) => ({
    name: meta(t.type).label,
    value: Number(t.waitNs),
    share: Number(t.waitNs) / (total || 1),
  }));

  const deeper: DeeperAction[] = [
    {label: 'Where the wait went', onclick: () => onNavigate('where')},
    ...(d.types[0]?.type === 'lock'
      ? [{label: 'Locks', icon: 'lock', onclick: () => onNavigate('locks')}]
      : []),
  ];

  return questionBlock({question, description, answer, deeper}, [
    breakdownGrid({
      nameTitle: 'Wait type',
      valueTitle: 'Blocked time',
      formatValue: (n) => fmtDurationNs(n),
      rows,
      onNameClick: (name) => onNavigate(byLabel.get(name) ?? 'where'),
    }),
  ]);
}
