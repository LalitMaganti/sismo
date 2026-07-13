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

// The Latency domain's tabbed shell, modeled on CpuTabsView: the Summary feed
// of question-blocks, then fixed deep-dive tabs each block links into. "Who it
// waited on" is built (the scheduling blame); "Where the wall-clock went" and
// "Why it waited" are stubs — the next slices — so the ordering and hand-offs
// are wired before their bodies land.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {EmptyState} from '../../../widgets/empty_state';
import {Tabs, type TabsTab} from '../../../widgets/tabs';
import type {PrivilegedSet} from '../privileged_set';
import {LatencyLandingPage} from './landing';
import {LatencyWhoTab} from './who_tab';
import {LatencyWhereTab} from './where_tab';
import {LatencyLocksTab} from './locks_tab';
import {LatencyNetworkTab} from './network_tab';

interface LatencyTabsAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
}

const OVERVIEW_TAB = 'overview';

interface FixedTab {
  readonly key: string;
  readonly title: string;
  readonly icon: string;
}

const FIXED_TABS: ReadonlyArray<FixedTab> = [
  {key: OVERVIEW_TAB, title: 'Summary', icon: 'dashboard'},
  {key: 'where', title: 'Where the wait went', icon: 'donut_large'},
  {key: 'locks', title: 'Locks', icon: 'lock'},
  {key: 'network', title: 'Network', icon: 'lan'},
  {key: 'who', title: 'Who it waited on', icon: 'groups'},
];

export class LatencyTabsView implements m.ClassComponent<LatencyTabsAttrs> {
  private active: string = OVERVIEW_TAB;
  // Tabs opened at least once; the Tabs widget keeps opened content mounted, so
  // an unopened tab never queries but a visited one keeps its state.
  private readonly visited = new Set<string>([OVERVIEW_TAB]);

  view({attrs}: m.CVnode<LatencyTabsAttrs>): m.Children {
    this.visited.add(this.active);
    const tabs: TabsTab[] = FIXED_TABS.map((t) => ({
      key: t.key,
      title: t.title,
      leftIcon: t.icon,
      content: this.visited.has(t.key) ? this.content(attrs, t) : undefined,
    }));
    return m(Tabs, {
      className: 'pf-sismo-cpu-tabs',
      tabs,
      activeTabKey: this.active,
      onTabChange: (key) => {
        this.active = key;
      },
    });
  }

  private content(attrs: LatencyTabsAttrs, tab: FixedTab): m.Children {
    if (tab.key === OVERVIEW_TAB) {
      return m(LatencyLandingPage, {
        trace: attrs.trace,
        priv: attrs.priv,
        onNavigate: (k) => {
          this.active = k;
        },
      });
    }
    if (tab.key === 'where') {
      return m(LatencyWhereTab, {
        trace: attrs.trace,
        priv: attrs.priv,
        onNavigate: (k) => {
          this.active = k;
        },
      });
    }
    if (tab.key === 'locks') {
      return m(LatencyLocksTab, {
        trace: attrs.trace,
        priv: attrs.priv,
        onNavigate: (k) => {
          this.active = k;
        },
      });
    }
    if (tab.key === 'network') {
      return m(LatencyNetworkTab, {trace: attrs.trace, priv: attrs.priv});
    }
    if (tab.key === 'who') {
      return m(LatencyWhoTab, {trace: attrs.trace, priv: attrs.priv});
    }
    return m(EmptyState, {
      icon: 'construction',
      title: tab.title,
      description: 'This deep-dive is coming next.',
    });
  }
}
