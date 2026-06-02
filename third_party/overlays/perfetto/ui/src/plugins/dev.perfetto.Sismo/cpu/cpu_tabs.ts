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

// The CPU domain's tabbed shell: always-present fixed lens tabs (Overview ·
// Where the cycles went · How were cycles spent · Where it ran) plus dynamic,
// closeable function detail tabs opened by drilling into a function.
// Modeled on com.android.HeapDumpExplorer. Where-it-ran is a stub for now; the
// rest are built.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {EmptyState} from '../../../widgets/empty_state';
import {Tabs, type TabsTab} from '../../../widgets/tabs';
import type {PrivilegedSet} from '../privileged_set';
import {CpuLandingPage} from './landing';
import {CpuWhereTab} from './where_tab';
import {CpuEfficiencyTab} from './efficiency_tab';
import {CpuScheduledTab} from './scheduled_tab';
import {CpuDetailTab} from './detail_tab';
import {
  CpuSession,
  OVERVIEW_TAB,
  type EntityKind,
  type EntityTab,
} from './session';

// Opens (or re-focuses) a function detail tab. Passed down into the views so a
// click on a function anywhere spawns its tab.
export type Drill = (kind: EntityKind, id: string, label: string) => void;

interface CpuTabsAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
}

interface FixedTab {
  readonly key: string;
  readonly title: string;
  readonly icon: string;
}

const FIXED_TABS: ReadonlyArray<FixedTab> = [
  {key: OVERVIEW_TAB, title: 'Summary', icon: 'dashboard'},
  {key: 'where', title: 'Where the cycles went', icon: 'donut_large'},
  {key: 'efficiency', title: 'How were cycles spent', icon: 'speed'},
  {key: 'whereran', title: 'How cycles were scheduled', icon: 'developer_board'},
];

const ENTITY_ICON: Record<EntityKind, string> = {
  function: 'code',
};

export class CpuTabsView implements m.ClassComponent<CpuTabsAttrs> {
  private readonly session = new CpuSession();
  // Tabs that have been opened at least once. The Tabs widget keeps content
  // mounted (gated), so building only visited tabs is lazy AND state-preserving:
  // an unopened tab never queries, but once opened its flamegraph/scroll survive
  // switching away and back.
  private readonly visited = new Set<string>([OVERVIEW_TAB]);

  view({attrs}: m.CVnode<CpuTabsAttrs>): m.Children {
    const active = this.session.active;
    this.visited.add(active);
    const drill: Drill = (kind, id, label) =>
      this.session.openEntityTab(kind, id, label);

    const fixed: TabsTab[] = FIXED_TABS.map((t) => ({
      key: t.key,
      title: t.title,
      leftIcon: t.icon,
      content: this.visited.has(t.key)
        ? this.fixedContent(attrs, t, drill)
        : undefined,
    }));

    const entity: TabsTab[] = this.session.tabs.map((t) => ({
      key: t.key,
      title: t.label,
      leftIcon: ENTITY_ICON[t.kind],
      closeButton: true,
      content: this.visited.has(t.key)
        ? this.entityContent(attrs, t, drill)
        : undefined,
    }));

    return m(Tabs, {
      className: 'pf-sismo-cpu-tabs',
      tabs: [...fixed, ...entity],
      activeTabKey: active,
      onTabChange: (key) => this.session.setActive(key),
      onTabClose: (key) => this.session.closeTab(key),
    });
  }

  private fixedContent(
    attrs: CpuTabsAttrs,
    tab: FixedTab,
    drill: Drill,
  ): m.Children {
    if (tab.key === OVERVIEW_TAB) {
      return m(CpuLandingPage, {
        trace: attrs.trace,
        priv: attrs.priv,
        onNavigate: (k) => this.session.setActive(k),
        onDrill: drill,
      });
    }
    if (tab.key === 'where') {
      return m(CpuWhereTab, {
        trace: attrs.trace,
        priv: attrs.priv,
        onDrill: drill,
      });
    }
    if (tab.key === 'efficiency') {
      return m(CpuEfficiencyTab, {trace: attrs.trace, priv: attrs.priv});
    }
    if (tab.key === 'whereran') {
      return m(CpuScheduledTab, {trace: attrs.trace, priv: attrs.priv});
    }
    return m(EmptyState, {
      icon: 'construction',
      title: tab.title,
      description: 'This deep-dive is coming next.',
    });
  }

  private entityContent(
    attrs: CpuTabsAttrs,
    tab: EntityTab,
    drill: Drill,
  ): m.Children {
    return m(CpuDetailTab, {
      trace: attrs.trace,
      priv: attrs.priv,
      kind: tab.kind,
      id: tab.id,
      label: tab.label,
      onDrill: drill,
    });
  }
}
