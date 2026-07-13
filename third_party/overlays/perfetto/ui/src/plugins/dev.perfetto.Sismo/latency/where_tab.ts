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

// "Where the wait went" — the off-CPU (waiting) analogue of the CPU section's
// "Where the cycles went": one tab, three views over the SAME wait-time-weighted
// data — a Flamegraph, an expandable Call tree, and a flat Functions ranking.
// Every off-CPU stack is re-rooted at the call that entered the scheduler (the
// sismo.offcpu trim), so the leaf is the real blocking call and the scheduler
// tail is gone from all three views. The wait-kind switch keeps genuine blocks
// (voluntary) apart from involuntary preemption.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {QuerySlot, SerialTaskQueue} from '../../../base/query_slot';
import {Section} from '../../../widgets/section';
import {EmptyState} from '../../../widgets/empty_state';
import {Callout} from '../../../widgets/callout';
import {Intent} from '../../../widgets/common';
import {Grid, GridCell, GridHeaderCell} from '../../../widgets/grid';
import {FlamegraphPanel} from '../../../components/flamegraph_panel';
import {computeFlamegraphTree} from '../../../components/query_flamegraph';
import {
  Flamegraph,
  FlamegraphFilterBar,
  type FlamegraphState,
} from '../../../widgets/flamegraph';
import {
  ROOT,
  buildCalltree,
  flattenFunctions,
  type BuiltTree,
  type CtNode,
} from '../cpu/flamegraph_tree';
import {breakdownGrid, type BreakdownGridRow} from '../cpu/grid';
import {segmentedSwitcher} from '../cpu/segmented';
import {buildBlockedFunctionMetric, sampleScopePredicates} from '../stack_timeline';
import {Setting, oneOf} from '../settings';
import {fmtDurationNs, fmtPercent} from '../format';
import {loadingBody, actionLink} from '../page_common';
import type {PrivilegedSet} from '../privileged_set';

interface WhereAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
  readonly onNavigate: (tab: string) => void;
}

const KINDS = ['blocked', 'all'] as const;
type Kind = (typeof KINDS)[number];

const VIEWS = ['flamegraph', 'calltree', 'functions'] as const;
type View = (typeof VIEWS)[number];

const kindSetting = new Setting<Kind>('latency.where.kind', 'blocked', oneOf(KINDS));
const viewSetting = new Setting<View>(
  'latency.where.view',
  'flamegraph',
  oneOf(VIEWS),
);

const KIND_CAPTION: Record<Kind, string> = {
  blocked:
    'Where your threads spent time genuinely blocked — waiting on a lock, a ' +
    'condvar, I/O, a pipe or a sleep. Wider = more wall-clock waited there.',
  all: 'All off-CPU time, including involuntary preemption (runnable but knocked off a busy core).',
};

const VIEW_TITLE: Record<View, string> = {
  flamegraph: 'Flamegraph',
  calltree: 'Call tree',
  functions: 'Functions',
};

export class LatencyWhereTab implements m.ClassComponent<WhereAttrs> {
  private readonly queue = new SerialTaskQueue();
  private readonly treeSlot = new QuerySlot<BuiltTree>(this.queue);
  private readonly fnSlot = new QuerySlot<ReadonlyArray<BreakdownGridRow>>(
    this.queue,
  );

  private kind: Kind = kindSetting.get();
  private activeView: View = viewSetting.get();

  private fgState?: FlamegraphState;
  private fgMetrics = [buildBlockedFunctionMetric([])];
  private scopeKey = '';

  onremove(): void {
    this.treeSlot.dispose();
    this.fnSlot.dispose();
  }

  // Rebuild the (single) metric + reset flamegraph state when the scope (priv +
  // kind) changes, so a kind switch re-runs against the new predicate set.
  private ensureScope(priv: PrivilegedSet): void {
    const key = `${priv.upids.join(',')}|${this.kind}`;
    if (key === this.scopeKey && this.fgState !== undefined) return;
    this.scopeKey = key;
    this.fgMetrics = [buildBlockedFunctionMetric(this.scopePredicates(priv))];
    this.fgState = Flamegraph.updateState(undefined, this.fgMetrics);
  }

  private scopePredicates(priv: PrivilegedSet): string[] {
    const preds = [...sampleScopePredicates(priv)];
    if (this.kind === 'blocked') preds.push(`t.kind = 'voluntary'`);
    return preds;
  }

  view({attrs}: m.CVnode<WhereAttrs>): m.Children {
    this.ensureScope(attrs.priv);
    return m(
      '.pf-sismo-tab',
      this.renderBars(),
      m(
        '.pf-sismo-tab__body',
        m(
          Section,
          {title: VIEW_TITLE[this.activeView], subtitle: KIND_CAPTION[this.kind]},
          // One filter bar shared by the flamegraph and call tree (Top Down /
          // Bottom Up drives both); the flat Functions ranking has no direction.
          m(FlamegraphFilterBar, {
            metrics: this.fgMetrics,
            state: this.fgState!,
            onStateChange: (s: FlamegraphState) => this.onFgStateChange(s),
            hideMetricSelector: true,
            showViewControls:
              this.activeView === 'flamegraph' || this.activeView === 'calltree',
            showDisplayOptions: false,
            showBreakdown: false,
          }),
          this.renderActive(attrs),
          m(
            Callout,
            {icon: 'lightbulb', intent: Intent.Primary},
            m(
              'span',
              'For who released the lock / woke you and who held the cores, see ',
              actionLink('Who it waited on', 'open_in_new', () =>
                attrs.onNavigate('who'),
              ),
              '.',
            ),
          ),
        ),
      ),
    );
  }

  private renderBars(): m.Children {
    return m(
      '.pf-sismo-tab__modebar',
      segmentedSwitcher<Kind>(
        [
          {key: 'blocked', label: 'What’s blocked', icon: 'bedtime'},
          {key: 'all', label: 'All off-CPU', icon: 'select_all'},
        ],
        this.kind,
        (k) => {
          this.kind = k;
          kindSetting.set(k);
        },
      ),
      segmentedSwitcher<View>(
        [
          {key: 'flamegraph', label: 'Flamegraph', icon: 'local_fire_department'},
          {key: 'calltree', label: 'Call tree', icon: 'account_tree'},
          {key: 'functions', label: 'Functions', icon: 'list'},
        ],
        this.activeView,
        (v) => {
          this.activeView = v;
          viewSetting.set(v);
        },
      ),
    );
  }

  private onFgStateChange(s: FlamegraphState): void {
    this.fgState = s;
  }

  private renderActive(attrs: WhereAttrs): m.Children {
    switch (this.activeView) {
      case 'flamegraph':
        return m(
          '.pf-sismo-tab__flamegraph',
          m(FlamegraphPanel, {
            trace: attrs.trace,
            metrics: this.fgMetrics,
            state: this.fgState!,
            hideFilterBar: true,
            onStateChange: (s: FlamegraphState) => this.onFgStateChange(s),
          }),
        );
      case 'calltree':
        return m('.pf-sismo-tab__view', this.renderCalltree(attrs));
      case 'functions':
        return m('.pf-sismo-tab__view', this.renderFunctions(attrs));
    }
  }

  private renderCalltree(attrs: WhereAttrs): m.Children {
    const view = this.fgState!.view;
    const built = this.treeSlot.use({
      key: {scope: this.scopeKey, view, filters: this.fgState!.filters},
      queryFn: async () => {
        const data = await computeFlamegraphTree(
          attrs.trace.engine,
          this.fgMetrics[0],
          {
            selectedMetricName: this.fgMetrics[0].name,
            filters: this.fgState!.filters,
            view,
          },
        );
        return buildCalltree(data, view.kind === 'PIVOT');
      },
    }).data;
    if (built === undefined) return loadingBody('Reading blocking stacks…');
    if (!built.hasRows) return this.emptyState();
    const total = built.totalValue;
    const rows: m.Children[][] = [];
    const visit = (node: CtNode, indent: number): void => {
      const kids = built.childrenOf.get(node.id) ?? [];
      const isExpanded = built.expanded.has(node.id);
      const chevron =
        kids.length === 0 ? 'leaf' : isExpanded ? 'expanded' : 'collapsed';
      rows.push([
        m(
          GridCell,
          {
            wrap: true,
            indent,
            chevron,
            onChevronClick:
              kids.length > 0 ? () => this.toggle(built, node.id) : undefined,
          },
          node.name,
        ),
        m(GridCell, {align: 'right'}, fmtDurationNs(node.total)),
        m(GridCell, {align: 'right'}, fmtPercent(node.total / total)),
      ]);
      if (isExpanded) for (const k of kids) visit(k, indent + 1);
    };
    for (const root of built.childrenOf.get(ROOT) ?? []) visit(root, 0);
    return m(Grid, {
      columns: [
        {key: 'fn', header: m(GridHeaderCell, 'Function')},
        {key: 'wait', header: m(GridHeaderCell, 'Wait time')},
        {key: 'pct', header: m(GridHeaderCell, 'Share')},
      ],
      rowData: rows,
    });
  }

  private toggle(built: BuiltTree, id: number): void {
    if (built.expanded.has(id)) built.expanded.delete(id);
    else built.expanded.add(id);
  }

  private renderFunctions(attrs: WhereAttrs): m.Children {
    const rows = this.fnSlot.use({
      key: {scope: this.scopeKey, filters: this.fgState!.filters},
      queryFn: async () => {
        const data = await computeFlamegraphTree(
          attrs.trace.engine,
          this.fgMetrics[0],
          {
            selectedMetricName: this.fgMetrics[0].name,
            filters: this.fgState!.filters,
            view: {kind: 'BOTTOM_UP'},
          },
        );
        return flattenFunctions(data);
      },
    }).data;
    if (rows === undefined) return loadingBody('Reading blocking stacks…');
    if (rows.length === 0) return this.emptyState();
    return breakdownGrid({
      nameTitle: 'Blocking function',
      valueTitle: 'Wait time',
      formatValue: (n) => fmtDurationNs(n),
      rows,
    });
  }

  private emptyState(): m.Children {
    return m(EmptyState, {
      icon: 'do_not_disturb',
      title:
        this.kind === 'blocked'
          ? 'Your threads never blocked voluntarily in this region.'
          : 'No off-CPU stacks — record with the CPU data source.',
    });
  }
}
