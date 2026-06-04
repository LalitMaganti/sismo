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

// The cache focus's tabbed shell: the home "Where the misses are" lens plus
// dynamic, closeable function-detail tabs opened by drilling into a function.
// Structurally like the CPU domain's tabs, but a wholly separate tree — every
// tab's content is a cache-domain view; nothing here routes to a CPU view.
// Shares only the Tabs widget.

import m from 'mithril';
import type {Trace} from '../../../../public/trace';
import {Tabs, type TabsTab} from '../../../../widgets/tabs';
import type {PrivilegedSet} from '../../privileged_set';
import {CacheWhereView} from './where';
import {CacheDetailView} from './detail';

const HOME_TAB = 'where';

interface CacheTabsAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
}

interface FixedTab {
  readonly key: string;
  readonly title: string;
  readonly icon: string;
}

const FIXED_TABS: ReadonlyArray<FixedTab> = [
  {key: HOME_TAB, title: 'Where the misses are', icon: 'donut_large'},
];

export class CacheTabsView implements m.ClassComponent<CacheTabsAttrs> {
  private active: string = HOME_TAB;
  // Open function-detail tabs, by function name (dedup identity). Insertion
  // order = tab order.
  private readonly open: string[] = [];
  // Tabs opened at least once; the Tabs widget keeps content mounted, so this
  // makes building lazy AND state-preserving (an unopened tab never queries).
  private readonly visited = new Set<string>([HOME_TAB]);

  private drill(name: string): void {
    if (name === '') return;
    if (!this.open.includes(name)) this.open.push(name);
    this.active = `fn:${name}`;
  }

  private closeDetail(name: string): void {
    const i = this.open.indexOf(name);
    if (i < 0) return;
    this.open.splice(i, 1);
    if (this.active === `fn:${name}`) this.active = HOME_TAB;
  }

  view({attrs}: m.CVnode<CacheTabsAttrs>): m.Children {
    this.visited.add(this.active);
    const onDrill = (name: string) => this.drill(name);

    const fixed: TabsTab[] = FIXED_TABS.map((t) => ({
      key: t.key,
      title: t.title,
      leftIcon: t.icon,
      content: this.visited.has(t.key)
        ? this.fixedContent(attrs, t.key, onDrill)
        : undefined,
    }));

    const detail: TabsTab[] = this.open.map((name) => {
      const key = `fn:${name}`;
      return {
        key,
        title: shortName(name),
        leftIcon: 'code',
        closeButton: true,
        content: this.visited.has(key)
          ? m(CacheDetailView, {trace: attrs.trace, priv: attrs.priv, name})
          : undefined,
      };
    });

    return m(Tabs, {
      className: 'pf-sismo-cpu-tabs',
      tabs: [...fixed, ...detail],
      activeTabKey: this.active,
      onTabChange: (key) => (this.active = key),
      onTabClose: (key) => this.closeDetail(key.replace(/^fn:/, '')),
    });
  }

  private fixedContent(
    attrs: CacheTabsAttrs,
    _key: string,
    onDrill: (name: string) => void,
  ): m.Children {
    return m(CacheWhereView, {trace: attrs.trace, priv: attrs.priv, onDrill});
  }
}

// A long demangled C++ symbol makes an unreadable tab; keep the leaf-ish tail.
function shortName(name: string): string {
  const paren = name.indexOf('(');
  const base = paren > 0 ? name.slice(0, paren) : name;
  const seg = base.split('::');
  const tail = seg.length > 1 ? seg.slice(-2).join('::') : base;
  return tail.length > 32 ? tail.slice(0, 31) + '…' : tail;
}
