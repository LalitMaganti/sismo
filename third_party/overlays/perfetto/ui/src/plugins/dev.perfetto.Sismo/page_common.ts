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

// Shared chrome + linking helpers for the Sismo detail pages (CPU, Latency, …).

import m from 'mithril';
import type {Trace} from '../../public/trace';
import {Anchor} from '../../widgets/anchor';
import {Icon} from '../../widgets/icon';
import {getThreadOrProcUri} from '../../public/utils';
import type {PrivilegedSet} from './privileged_set';

export function goToTimeline(
  trace: Trace,
  target?: {upid?: number; utid?: number},
): void {
  trace.navigate('#!/viewer');
  if (target === undefined) return;
  const uri =
    target.upid !== undefined
      ? getThreadOrProcUri(target.upid, null)
      : target.utid !== undefined
        ? getThreadOrProcUri(null, target.utid)
        : undefined;
  if (uri === undefined) return;
  trace.scrollTo({track: {uri, expandGroup: true}});
}

export function renderPrivilegedBanner(priv: PrivilegedSet): m.Children {
  if (priv.pids.length === 0) {
    return m(
      '.pf-sismo-page__priv-banner.pf-sismo-page__priv-banner--empty',
      m(Icon, {icon: 'info'}),
      " No profiled processes detected — sections below show the system undifferentiated. Record with `sismo record` to tag the processes you're profiling.",
    );
  }
  const pidList = priv.pids.map((p) => `pid ${p}`).join(', ');
  return m(
    '.pf-sismo-page__priv-banner',
    m(Icon, {icon: 'star', filled: true}),
    ` Profiling ${pidList}`,
    priv.upids.length < priv.pids.length &&
      m(
        'span.pf-sismo-page__muted',
        ` (${priv.pids.length - priv.upids.length} not found in this trace)`,
      ),
  );
}

export function renderProcessLink(
  trace: Trace,
  name: string,
  pid: number | null,
  upid: number,
): m.Children {
  return m(
    Anchor,
    {
      href: '#!/viewer',
      onclick: (e: Event) => {
        e.preventDefault();
        goToTimeline(trace, {upid});
      },
    },
    name,
    pid !== null && m('span.pf-sismo-page__muted', ` (pid ${pid})`),
  );
}

export function renderThreadLink(
  trace: Trace,
  threadName: string,
  tid: number | null,
  utid: number,
): m.Children {
  return m(
    Anchor,
    {
      href: '#!/viewer',
      onclick: (e: Event) => {
        e.preventDefault();
        goToTimeline(trace, {utid});
      },
    },
    threadName,
    tid !== null && m('span.pf-sismo-page__muted', ` (tid ${tid})`),
  );
}
