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

// "Where the misses are" — the cache deep-dive's flamegraph + call tree +
// functions, all weighted by L3 misses (one sample = one miss). Built from
// scratch for the cache domain (not the CPU "where the cycles went" tab): the
// only weighting is misses, and the flamegraph can "Break down by → Data region"
// to regroup the tree by the memory each part missed on. The Functions view is
// the bespoke misses-and-memory table, not a self-cycles list. Shares only
// widget-level pieces (the flamegraph panel, the tree builder, the grid).

import m from 'mithril';
import type {Trace} from '../../../../public/trace';
import {QuerySlot, SerialTaskQueue} from '../../../../base/query_slot';
import {EmptyState} from '../../../../widgets/empty_state';
import {Grid, GridCell, GridHeaderCell} from '../../../../widgets/grid';
import {FlamegraphPanel} from '../../../../components/flamegraph_panel';
import {
  computeFlamegraphTree,
  type QueryFlamegraphMetric,
} from '../../../../components/query_flamegraph';
import {
  Flamegraph,
  FlamegraphFilterBar,
  type FlamegraphOptionalAction,
  type FlamegraphState,
} from '../../../../widgets/flamegraph';
import {
  buildSampleFlamegraphMetrics,
  sampleScopePredicates,
  type BreakdownKind,
} from '../../stack_timeline';
import {
  ROOT,
  buildCalltree,
  EMPTY_BUILT_TREE,
  type BuiltTree,
  type CtNode,
} from '../../cpu/flamegraph_tree';
import {segmentedSwitcher} from '../../cpu/segmented';
import {fmtCount, fmtPercent} from '../../format';
import {actionLink} from '../../page_common';
import type {PrivilegedSet} from '../../privileged_set';
import {CacheFunctionsView} from './functions';

type Mode = 'flamegraph' | 'calltree' | 'functions';

// The single cache weighting: every sample is one L3 miss, so the sample-count
// metric IS the miss histogram. buildSampleFlamegraphMetrics with no counters
// (empty set) yields just that metric — none of the CPU cycle/Top-Down
// weightings — and offerDataRegion adds the "Break down by → Data region" option.
const MISS_METRIC = 'Sample count';

interface CacheWhereAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
  readonly onDrill: (name: string) => void;
}

export class CacheWhereView implements m.ClassComponent<CacheWhereAttrs> {
  private mode: Mode = 'functions';
  private readonly scope: string[];
  private readonly funcActions: ReadonlyArray<FlamegraphOptionalAction>;
  private fgMetrics: QueryFlamegraphMetric[];
  private fgState: FlamegraphState;
  private fgBreakdown: BreakdownKind = 'none';
  // Default the bottom axis to the data region — the cache view's whole point is
  // drilling code → line → the data it touched.
  private fgBottom: BreakdownKind = 'data_region';

  private readonly queue = new SerialTaskQueue();
  private readonly ctSlot = new QuerySlot<BuiltTree>(this.queue);

  constructor({attrs}: m.CVnode<CacheWhereAttrs>) {
    this.scope = sampleScopePredicates(attrs.priv);
    this.funcActions = [
      {
        name: 'Inspect this function’s lines + data',
        icon: 'open_in_new',
        category: 'DRILL',
        description: 'Open the function detail (source/asm + data touched).',
        execute: (ctx) => {
          const n = ctx.node?.name;
          if (n !== undefined && n !== '') attrs.onDrill(n);
        },
      },
    ];
    this.fgMetrics = this.buildMetrics();
    this.fgState = {
      ...Flamegraph.updateState(undefined, this.fgMetrics),
      breakdownBottom: this.fgBottom,
    };
  }

  onremove(): void {
    this.ctSlot.dispose();
  }

  private buildMetrics(): QueryFlamegraphMetric[] {
    return buildSampleFlamegraphMetrics(
      this.scope,
      this.fgBreakdown,
      new Set(), // no counter weightings — cache cares only about misses
      this.funcActions,
      true, // offer "Data region" as a breakdown dimension
      this.fgBottom,
    );
  }

  view({attrs}: m.CVnode<CacheWhereAttrs>): m.Children {
    return m(
      '.pf-sismo-tab',
      this.renderModeBar(),
      // The shared filter bar drives the flamegraph and call tree (filters,
      // top-down/bottom-up, the data-region break-down). The bespoke Functions
      // view runs its own query, so the bar is hidden there.
      this.mode !== 'functions' &&
        m(FlamegraphFilterBar, {
          metrics: this.fgMetrics,
          state: this.fgState,
          onStateChange: (s) => this.onFgStateChange(s),
          hideMetricSelector: true,
          showViewControls: true,
          // Colour-by is flamegraph-only; the data-region break-down shows on
          // both the flamegraph and the call tree (it reshapes both).
          showDisplayOptions: this.mode === 'flamegraph',
          showBreakdown: true,
        }),
      m('.pf-sismo-tab__body', this.renderActive(attrs)),
    );
  }

  private renderModeBar(): m.Children {
    return m(
      '.pf-sismo-tab__modebar',
      segmentedSwitcher<Mode>(
        [
          {key: 'functions', label: 'Functions', icon: 'list'},
          {key: 'flamegraph', label: 'Flamegraph', icon: 'local_fire_department'},
          {key: 'calltree', label: 'Call tree', icon: 'account_tree'},
        ],
        this.mode,
        (mode) => {
          this.mode = mode;
        },
      ),
    );
  }

  private renderActive(attrs: CacheWhereAttrs): m.Children {
    if (this.mode === 'flamegraph') {
      return m(
        '.pf-sismo-tab__flamegraph',
        m(FlamegraphPanel, {
          trace: attrs.trace,
          metrics: this.fgMetrics,
          state: this.fgState,
          hideFilterBar: true,
          onStateChange: (s: FlamegraphState) => this.onFgStateChange(s),
        }),
      );
    }
    if (this.mode === 'calltree') return this.renderCalltree(attrs);
    return m(CacheFunctionsView, {
      trace: attrs.trace,
      priv: attrs.priv,
      onDrill: attrs.onDrill,
    });
  }

  private onFgStateChange(s: FlamegraphState): void {
    this.fgState = s;
    const top = (s.breakdownBy ?? 'none') as BreakdownKind;
    const bottom = (s.breakdownBottom ?? 'none') as BreakdownKind;
    if (top !== this.fgBreakdown || bottom !== this.fgBottom) {
      this.fgBreakdown = top;
      this.fgBottom = bottom;
      this.fgMetrics = this.buildMetrics();
    }
  }

  private renderCalltree(attrs: CacheWhereAttrs): m.Children {
    const view = this.fgState.view;
    const built = this.ctSlot.use({
      // Keyed on the break-down too, so switching "Break down by → Data region"
      // re-runs the tree — the call tree mirrors the flamegraph's grouping.
      key: {
        view,
        filters: this.fgState.filters,
        breakdown: this.fgBreakdown,
        bottom: this.fgBottom,
      },
      queryFn: async () => {
        // Use the same (break-down-applied) metric the flamegraph is showing, so
        // the call tree groups by data region exactly as the flamegraph does.
        const metric =
          this.fgMetrics.find((mt) => mt.name === MISS_METRIC) ?? this.fgMetrics[0];
        if (metric === undefined) return EMPTY_BUILT_TREE;
        const data = await computeFlamegraphTree(attrs.trace.engine, metric, {
          selectedMetricName: metric.name,
          filters: this.fgState.filters,
          view,
        });
        return buildCalltree(data, view.kind === 'PIVOT');
      },
    }).data;
    return m('.pf-sismo-tab__view', this.renderCalltreeGrid(attrs, built));
  }

  private renderCalltreeGrid(
    attrs: CacheWhereAttrs,
    built: BuiltTree | undefined,
  ): m.Children {
    if (built === undefined) {
      return m(EmptyState, {icon: 'hourglass_empty', title: 'Building call tree…'});
    }
    if (!built.hasRows) {
      return m(EmptyState, {
        icon: 'science',
        title: 'No miss-attributed stacks for this scope',
      });
    }
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
          actionLink(node.name, 'open_in_new', () => attrs.onDrill(node.name)),
        ),
        m(GridCell, {align: 'right'}, fmtCount(node.total)),
        m(GridCell, {align: 'right'}, fmtPercent(node.total / total)),
        m(GridCell, {align: 'right'}, fmtCount(node.self)),
      ]);
      if (isExpanded) for (const k of kids) visit(k, indent + 1);
    };
    for (const root of built.childrenOf.get(ROOT) ?? []) visit(root, 0);
    return m(Grid, {
      columns: [
        {key: 'fn', header: m(GridHeaderCell, 'Function')},
        {key: 'total', header: m(GridHeaderCell, 'Total misses')},
        {key: 'totalpct', header: m(GridHeaderCell, 'Total %')},
        {key: 'self', header: m(GridHeaderCell, 'Self misses')},
      ],
      rowData: rows,
    });
  }

  private toggle(built: BuiltTree, id: number): void {
    if (built.expanded.has(id)) built.expanded.delete(id);
    else built.expanded.add(id);
  }
}
