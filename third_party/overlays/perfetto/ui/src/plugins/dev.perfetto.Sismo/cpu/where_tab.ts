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

// "Where the cycles went" deep-dive. Three views over the SAME cycle-weighted
// data, sharing one filter bar: a flamegraph, a call tree (an expandable
// tree-table) and a flat functions table. All three run on the flamegraph's
// pipeline (computeFlamegraphTree), so the same metric and the same filters —
// show/hide stack, hide/show-from frame, pivot — apply consistently.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {QuerySlot, SerialTaskQueue} from '../../../base/query_slot';
import {Callout} from '../../../widgets/callout';
import {EmptyState} from '../../../widgets/empty_state';
import {Grid, GridCell, GridHeaderCell} from '../../../widgets/grid';
import {FlamegraphPanel} from '../../../components/flamegraph_panel';
import {
  computeFlamegraphTree,
  type QueryFlamegraphMetric,
} from '../../../components/query_flamegraph';
import {
  Flamegraph,
  FlamegraphFilterBar,
  type FlamegraphQueryData,
  type FlamegraphState,
} from '../../../widgets/flamegraph';
import {
  buildSampleFlamegraphMetrics,
  loadPerfCounterNames,
  sampleScopePredicates,
  type BreakdownKind,
} from '../stack_timeline';
import {fmtCount, fmtPercent} from '../format';
import type {PrivilegedSet} from '../privileged_set';
import {breakdownGrid, type BreakdownGridRow} from './grid';
import {segmentedSwitcher} from './segmented';
import {
  applyPrefs,
  loadFlamegraphPrefs,
  prefsFromState,
  saveFlamegraphPrefs,
  type FlamegraphPrefs,
} from './prefs';
import {Setting, oneOf} from '../settings';

const MODES = ['flamegraph', 'calltree', 'functions'] as const;
type Mode = (typeof MODES)[number];

// Which sub-view was last used, carried across traces. The call-tree direction
// is shared with the flamegraph (state.view), so it persists via the flamegraph
// prefs rather than its own setting.
const modeSetting = new Setting<Mode>(
  'cpu.where.mode',
  'flamegraph',
  oneOf(MODES),
);

// All three views are cycle-weighted: the metric is fixed to the CPU-cycles
// timebase rather than raw sample count, independent of the flamegraph's (hidden)
// metric picker. Matches the label in buildSampleFlamegraphMetrics
// (COUNTER_WEIGHTS); a trace with no cpu-cycles counter just yields an empty tree.
const CYCLES_METRIC = 'CPU cycles (approx)';

// One-line orientation per mode, so you're never dropped into a view cold.
const CAPTION: Record<Mode, string> = {
  flamegraph:
    'Top-down: where CPU cycles went, by call stack. Each block is a function; ' +
    'wider = more cycles. Click a block to zoom in.',
  calltree:
    'The same cycles as an expandable tree, sharing the flamegraph’s metric and ' +
    'filters. Top-down lists callees under each caller; bottom-up starts from hot ' +
    'leaves and shows who called them. Total % is share of the displayed cycles; ' +
    'Self is cycles in the function itself.',
  functions:
    'A flattened table (no call structure): every function with its self cycles ' +
    'summed across every place it was called from, ranked — the flat ' +
    '“where did the cycles go”. Stack filters still apply (Show-from-frame narrows ' +
    'it; pivot, which only re-roots the tree, does not).',
};

interface CpuWhereAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
}

export class CpuWhereTab implements m.ClassComponent<CpuWhereAttrs> {
  private mode: Mode = modeSetting.get();
  private readonly scope: string[];

  // Flamegraph state.
  private fgMetrics;
  private fgState: FlamegraphState;
  private fgCounters?: ReadonlySet<string>;
  private fgBreakdown: BreakdownKind = 'none';
  // Cross-trace view preferences, restored on construction (see ./prefs).
  private readonly prefs: FlamegraphPrefs;

  // The call tree and functions both run a flamegraph query keyed on the current
  // view/filters; the slots own the caching, cancellation and pending state, so
  // a slot reruns automatically whenever its key changes. They share one queue
  // so the two never compute concurrently (only one is visible at a time).
  private readonly queue = new SerialTaskQueue();
  private readonly ctSlot = new QuerySlot<BuiltTree>(this.queue);
  private readonly fnSlot = new QuerySlot<ReadonlyArray<BreakdownGridRow>>(
    this.queue,
  );

  constructor({attrs}: m.CVnode<CpuWhereAttrs>) {
    this.scope = sampleScopePredicates(attrs.priv);
    this.prefs = loadFlamegraphPrefs();
    // A persisted breakdown reshapes which metrics exist, so honour it before
    // building them.
    if (this.prefs.breakdownBy !== undefined) {
      this.fgBreakdown = this.prefs.breakdownBy as BreakdownKind;
    }
    this.fgMetrics = buildSampleFlamegraphMetrics(this.scope, this.fgBreakdown);
    this.fgState = applyPrefs(
      Flamegraph.updateState(undefined, this.fgMetrics),
      this.prefs,
      new Set(this.fgMetrics.map((mt) => mt.name)),
      CYCLES_METRIC,
    );
    loadPerfCounterNames(attrs.trace.engine, this.scope)
      .then((counters) => {
        this.fgCounters = counters;
        this.fgMetrics = buildSampleFlamegraphMetrics(
          this.scope,
          this.fgBreakdown,
          counters,
        );
        // "Backend-bound slots" only appears once counters are confirmed; if the
        // saved metric was that and we fell back, restore it now (unless the user
        // has since changed the selection away from the default).
        const saved = this.prefs.selectedMetricName;
        const names = new Set(this.fgMetrics.map((mt) => mt.name));
        if (
          saved !== undefined &&
          saved !== this.fgState.selectedMetricName &&
          this.fgState.selectedMetricName === CYCLES_METRIC &&
          names.has(saved)
        ) {
          this.fgState = {...this.fgState, selectedMetricName: saved};
        }
        m.redraw();
      })
      .catch(() => {});
  }

  onremove(): void {
    this.ctSlot.dispose();
    this.fnSlot.dispose();
  }

  view({attrs}: m.CVnode<CpuWhereAttrs>): m.Children {
    return m(
      '.pf-sismo-tab',
      this.renderModeBar(),
      m(Callout, {icon: 'help_outline'}, CAPTION[this.mode]),
      // One filter bar shared by all three sub-views: the same filters apply to
      // the flamegraph, the call tree and the functions table. The flamegraph's
      // own bar is hidden (hideFilterBar, in renderFlamegraph) so it isn't shown
      // twice. The Top Down / Bottom Up toggle drives both the flamegraph and
      // the call tree, so it shows for both but not the flat functions table;
      // the metric picker and the colour / break-down display options are
      // flamegraph-only.
      m(FlamegraphFilterBar, {
        metrics: this.fgMetrics,
        state: this.fgState,
        onStateChange: (s) => this.onFgStateChange(s),
        hideMetricSelector: true,
        showViewControls: this.mode === 'flamegraph' || this.mode === 'calltree',
        showDisplayOptions: this.mode === 'flamegraph',
      }),
      m('.pf-sismo-tab__body', this.renderActive(attrs)),
    );
  }

  private renderModeBar(): m.Children {
    return m(
      '.pf-sismo-tab__modebar',
      segmentedSwitcher<Mode>(
        [
          {key: 'flamegraph', label: 'Flamegraph', icon: 'local_fire_department'},
          {key: 'calltree', label: 'Call tree', icon: 'account_tree'},
          {key: 'functions', label: 'Functions', icon: 'list'},
        ],
        this.mode,
        (mode) => {
          this.mode = mode;
          modeSetting.set(mode);
        },
      ),
    );
  }

  private renderActive(attrs: CpuWhereAttrs): m.Children {
    switch (this.mode) {
      case 'flamegraph':
        return this.renderFlamegraph(attrs);
      case 'calltree':
        return this.renderCalltree(attrs);
      case 'functions':
        return this.renderFunctions(attrs);
    }
  }

  // ---- Flamegraph ----------------------------------------------------------

  private renderFlamegraph(attrs: CpuWhereAttrs): m.Children {
    return m(
      '.pf-sismo-tab__flamegraph',
      m(FlamegraphPanel, {
        trace: attrs.trace,
        metrics: this.fgMetrics,
        state: this.fgState,
        // The shared bar (rendered by view()) provides the filters and the
        // metric / display controls, so suppress the panel's built-in bar.
        hideFilterBar: true,
        onStateChange: (s: FlamegraphState) => this.onFgStateChange(s),
      }),
    );
  }

  // Apply a new flamegraph state, whether it came from the shared filter bar or
  // from interacting with the flamegraph itself (pivoting, zooming): persist the
  // cross-trace prefs and, if the breakdown changed, rebuild the metrics whose
  // shape depends on it.
  private onFgStateChange(s: FlamegraphState): void {
    this.fgState = s;
    saveFlamegraphPrefs(prefsFromState(s));
    const next = (s.breakdownBy ?? 'none') as BreakdownKind;
    if (next !== this.fgBreakdown) {
      this.fgBreakdown = next;
      this.fgMetrics = buildSampleFlamegraphMetrics(
        this.scope,
        next,
        this.fgCounters,
      );
    }
  }

  // The cycle-weighted metric the call tree and functions run on. Built without
  // a breakdown so those views are stable regardless of the flamegraph's
  // break-down setting (which only reshapes the flamegraph itself).
  private cycleMetric(): QueryFlamegraphMetric | undefined {
    return buildSampleFlamegraphMetrics(this.scope, 'none', this.fgCounters).find(
      (mt) => mt.name === CYCLES_METRIC,
    );
  }

  // ---- Call tree -----------------------------------------------------------

  private renderCalltree(attrs: CpuWhereAttrs): m.Children {
    const view = this.fgState.view;
    const built = this.ctSlot.use({
      key: {view, filters: this.fgState.filters},
      queryFn: async () => {
        const metric = this.cycleMetric();
        if (metric === undefined) return EMPTY_BUILT_TREE;
        const data = await computeFlamegraphTree(attrs.trace.engine, metric, {
          selectedMetricName: metric.name,
          filters: this.fgState.filters,
          view,
        });
        return buildCalltree(data, view.kind === 'PIVOT');
      },
    }).data;
    // A pivot in the flamegraph shows callers above the pivot and callees below.
    // A tree-table can only grow one way, so the call tree shows the callee half
    // and points at the flamegraph for the callers.
    const pivotLabel =
      view.kind === 'PIVOT' ? (view.displayLabel ?? view.pivot) : undefined;
    return m(
      '.pf-sismo-tab__view',
      pivotLabel !== undefined &&
        m(
          Callout,
          {icon: 'info'},
          `Pivoted on “${pivotLabel}”: showing the pivot and its callees. ` +
            `Its callers (the upper half of the pivot) can only be shown in the ` +
            `flamegraph, not as a tree.`,
        ),
      this.renderCalltreeGrid(built),
    );
  }

  private renderCalltreeGrid(built: BuiltTree | undefined): m.Children {
    if (built === undefined) {
      return m(EmptyState, {
        icon: 'hourglass_empty',
        title: 'Building call tree…',
      });
    }
    if (!built.hasRows) {
      return m(EmptyState, {
        icon: 'science',
        title: 'No cycle-attributed stacks for this scope',
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
          node.name,
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
        {key: 'total', header: m(GridHeaderCell, 'Total cycles')},
        {key: 'totalpct', header: m(GridHeaderCell, 'Total %')},
        {key: 'self', header: m(GridHeaderCell, 'Self cycles')},
      ],
      rowData: rows,
    });
  }

  private toggle(built: BuiltTree, id: number): void {
    if (built.expanded.has(id)) built.expanded.delete(id);
    else built.expanded.add(id);
  }

  // ---- Flat functions ------------------------------------------------------

  private renderFunctions(attrs: CpuWhereAttrs): m.Children {
    const rows = this.fnSlot.use({
      key: {filters: this.fgState.filters},
      queryFn: async () => {
        const metric = this.cycleMetric();
        if (metric === undefined) return [];
        // A bottom-up tree merges every sampled leaf by function name at its
        // roots, so the roots ARE the flat self-cycles-per-function ranking —
        // aggregated (GROUP BY name) and ordered (heaviest first) entirely in
        // SQL. The stack filters, including Show-from-frame, still narrow what's
        // counted; pivot only re-roots the tree, so it's irrelevant here.
        const data = await computeFlamegraphTree(attrs.trace.engine, metric, {
          selectedMetricName: metric.name,
          filters: this.fgState.filters,
          view: {kind: 'BOTTOM_UP'},
        });
        return flattenFunctions(data);
      },
    }).data;
    const body =
      rows === undefined
        ? m(EmptyState, {icon: 'hourglass_empty', title: 'Loading functions…'})
        : breakdownGrid({
            nameTitle: 'Function',
            valueTitle: 'Self cycles',
            formatValue: (n) => fmtCount(n),
            rows,
          });
    return m('.pf-sismo-tab__view', body);
  }
}

// Synthetic parent id of the displayed roots (computeFlamegraphTree emits -1 for
// a node with no parent).
const ROOT = -1;

interface CtNode {
  readonly id: number;
  readonly parentId: number; // ROOT at the top of the displayed tree
  readonly name: string;
  readonly self: number; // self cycles
  readonly total: number; // cumulative cycles
}

interface BuiltTree {
  readonly childrenOf: Map<number, CtNode[]>; // keyed by parentId (ROOT = roots)
  readonly expanded: Set<number>;
  readonly totalValue: number; // denominator for Total %
  readonly hasRows: boolean;
}

const EMPTY_BUILT_TREE: BuiltTree = {
  childrenOf: new Map(),
  expanded: new Set(),
  totalValue: 1,
  hasRows: false,
};

// Turn the flamegraph's laid-out nodes into an expandable call-tree model. For a
// pivot we keep only the callee half (depth >= 1): the pivot frame and what it
// called. (computeFlamegraphTree puts callees at positive depth and callers at
// negative depth; a tree-table can't show the callers above the root.)
function buildCalltree(
  data: FlamegraphQueryData,
  isPivot: boolean,
): BuiltTree {
  const childrenOf = new Map<number, CtNode[]>();
  for (const n of data.nodes) {
    if (isPivot && n.depth < 1) continue;
    const node: CtNode = {
      id: n.id,
      parentId: n.parentId,
      name: n.name,
      self: n.selfValue,
      total: n.cumulativeValue,
    };
    const arr = childrenOf.get(node.parentId);
    if (arr) arr.push(node);
    else childrenOf.set(node.parentId, [node]);
  }
  // No JS sort: computeFlamegraphTree already lays the nodes out heaviest-first
  // within each parent (the SQL layout orders siblings by cumulative value), so
  // appending in node order preserves that ranking per parent.
  const roots = childrenOf.get(ROOT) ?? [];
  const totalValue = roots.reduce((a, r) => a + r.total, 0) || 1;
  const expanded = new Set<number>();
  expandToFill(childrenOf, expanded, 20);
  return {childrenOf, expanded, totalValue, hasRows: roots.length > 0};
}

// The roots of the bottom-up tree are the sampled leaf functions, already merged
// by name and laid out heaviest-first by SQL. So the flat self-cycles-per-function
// ranking is just those roots, read in order — no JS aggregation or sorting. Share
// is each function's self over the total self across all roots.
function flattenFunctions(
  data: FlamegraphQueryData,
): ReadonlyArray<BreakdownGridRow> {
  const total = data.allRootsCumulativeValue || 1;
  const rows: BreakdownGridRow[] = [];
  for (const n of data.nodes) {
    if (n.parentId !== ROOT) continue; // bottom-up roots = leaf functions
    rows.push({
      name: n.name,
      value: n.cumulativeValue,
      share: n.cumulativeValue / total,
    });
  }
  return rows;
}

// Depth-first: open the heaviest path until at least `target` rows are visible.
function expandToFill(
  childrenOf: ReadonlyMap<number, CtNode[]>,
  expanded: Set<number>,
  target: number,
): void {
  let visible = 0;
  const dfs = (node: CtNode): void => {
    visible++;
    const kids = childrenOf.get(node.id) ?? [];
    if (kids.length > 0 && visible < target) {
      expanded.add(node.id);
      for (const k of kids) dfs(k);
    }
  };
  for (const root of childrenOf.get(ROOT) ?? []) dfs(root);
}
