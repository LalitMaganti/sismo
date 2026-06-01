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

// "Where the time went" deep-dive. Navigate where CPU time went three ways: a
// flamegraph (top-down), a call tree (top-down OR bottom-up — find who calls a
// hot leaf), and a flat function table. Flamegraph and call tree reuse the
// shared widgets; the flat table is a DataGrid.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {Callout} from '../../../widgets/callout';
import {EmptyState} from '../../../widgets/empty_state';
import {Grid, GridCell, GridHeaderCell} from '../../../widgets/grid';
import {FlamegraphPanel} from '../../../components/flamegraph_panel';
import {Flamegraph, type FlamegraphState} from '../../../widgets/flamegraph';
import {
  buildSampleFlamegraphMetrics,
  loadPerfCounterNames,
  type BreakdownKind,
} from '../stack_timeline';
import {
  loadCallTree,
  loadHeaviestFunctions,
  type CallTree,
  type CallTreeNode,
  type CallTreeDirection,
} from '../cpu_data';
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

type Mode = 'flamegraph' | 'calltree' | 'functions';

// Default the flamegraph to cycle-weighted attribution (the sampling timebase)
// rather than raw sample count. Matches the label in buildSampleFlamegraphMetrics
// (COUNTER_WEIGHTS); falls back to an empty tree if the trace has no cpu-cycles.
const CYCLES_METRIC = 'CPU cycles (approx)';

// One-line orientation per mode, so you're never dropped into a view cold.
const CAPTION: Record<Mode, string> = {
  flamegraph:
    'Top-down: where CPU time went, by call stack. Each block is a function; ' +
    'wider = more sampled CPU time. Click a block to zoom in.',
  calltree:
    'The same calls as a tree. Top-down lists callees under each function; ' +
    'bottom-up starts from hot leaves and shows who called them. Total % is ' +
    'share of sampled CPU; Self is time in the function itself.',
  functions:
    'Every sampled function, flat — ranked by how much CPU it used, ignoring ' +
    'the call structure.',
};

interface CpuWhereAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
}

// perf_sample predicates (alias `p`) scoping the views to the profiled set.
function sampleScope(priv: PrivilegedSet): string[] {
  if (priv.upids.length === 0) return [];
  return [
    `p.utid in (SELECT utid FROM thread WHERE upid IN ` +
      `(${priv.upids.join(',')}))`,
  ];
}

export class CpuWhereTab implements m.ClassComponent<CpuWhereAttrs> {
  private mode: Mode = 'flamegraph';
  private readonly scope: string[];

  // Flamegraph state.
  private fgMetrics;
  private fgState: FlamegraphState;
  private fgCounters?: ReadonlySet<string>;
  private fgBreakdown: BreakdownKind = 'none';
  // Cross-trace view preferences, restored on construction (see ./prefs).
  private readonly prefs: FlamegraphPrefs;

  // Call tree state.
  private ctDirection: CallTreeDirection = 'top-down';
  private ctBuilt?: BuiltTree;
  private ctLoadedFor?: CallTreeDirection;

  // Flat functions.
  private fnRows?: ReadonlyArray<BreakdownGridRow>;

  constructor({attrs}: m.CVnode<CpuWhereAttrs>) {
    this.scope = sampleScope(attrs.priv);
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

  view({attrs}: m.CVnode<CpuWhereAttrs>): m.Children {
    return m(
      '.pf-sismo-tab',
      this.renderModeBar(),
      m(Callout, {icon: 'help_outline'}, CAPTION[this.mode]),
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

  // ---- Flamegraph (top-down) ----------------------------------------------

  private renderFlamegraph(attrs: CpuWhereAttrs): m.Children {
    return m(
      '.pf-sismo-tab__flamegraph',
      m(FlamegraphPanel, {
        trace: attrs.trace,
        metrics: this.fgMetrics,
        state: this.fgState,
        onStateChange: (s: FlamegraphState) => {
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
        },
      }),
    );
  }

  // ---- Call tree (top-down / bottom-up) -----------------------------------

  private renderCalltree(attrs: CpuWhereAttrs): m.Children {
    if (this.ctLoadedFor !== this.ctDirection) {
      this.ctLoadedFor = this.ctDirection;
      this.ctBuilt = undefined;
      this.loadCalltree(attrs, this.ctDirection);
    }
    const dirBar = m(
      '.pf-sismo-tab__modebar',
      segmentedSwitcher<CallTreeDirection>(
        [
          {key: 'top-down', label: 'Top-down', icon: 'arrow_downward'},
          {key: 'bottom-up', label: 'Bottom-up', icon: 'arrow_upward'},
        ],
        this.ctDirection,
        (dir) => {
          this.ctDirection = dir;
        },
      ),
    );
    return m('', dirBar, m('.pf-sismo-tab__view', this.renderCalltreeGrid()));
  }

  private renderCalltreeGrid(): m.Children {
    const built = this.ctBuilt;
    if (built === undefined) {
      return m(EmptyState, {
        icon: 'hourglass_empty',
        title: 'Building call tree…',
      });
    }
    if (!built.tree.hasSamples) {
      return m(EmptyState, {
        icon: 'science',
        title: 'No symbolised stacks for this scope',
      });
    }
    const total = built.tree.totalSamples || 1;
    const rows: m.Children[][] = [];
    const visit = (node: CallTreeNode): void => {
      const kids = built.childrenOf.get(node.id) ?? [];
      const isExpanded = built.expanded.has(node.id);
      const chevron =
        kids.length === 0 ? 'leaf' : isExpanded ? 'expanded' : 'collapsed';
      rows.push([
        m(
          GridCell,
          {
            wrap: true,
            indent: node.depth,
            chevron,
            onChevronClick:
              kids.length > 0 ? () => this.toggle(built, node.id) : undefined,
          },
          node.name,
        ),
        m(GridCell, {align: 'right'}, fmtCount(node.totalSamples)),
        m(GridCell, {align: 'right'}, fmtPercent(node.totalSamples / total)),
        m(GridCell, {align: 'right'}, fmtCount(node.selfSamples)),
      ]);
      if (isExpanded) for (const k of kids) visit(k);
    };
    for (const root of built.childrenOf.get(null) ?? []) visit(root);
    return m(Grid, {
      columns: [
        {key: 'fn', header: m(GridHeaderCell, 'Function')},
        {key: 'total', header: m(GridHeaderCell, 'Total')},
        {key: 'totalpct', header: m(GridHeaderCell, 'Total %')},
        {key: 'self', header: m(GridHeaderCell, 'Self')},
      ],
      rowData: rows,
    });
  }

  private loadCalltree(attrs: CpuWhereAttrs, dir: CallTreeDirection): void {
    loadCallTree(attrs.trace.engine, attrs.priv, dir)
      .then((tree) => {
        if (this.ctDirection !== dir) return;
        const childrenOf = new Map<number | null, CallTreeNode[]>();
        for (const n of tree.nodes) {
          const arr = childrenOf.get(n.parentId);
          if (arr) arr.push(n);
          else childrenOf.set(n.parentId, [n]);
        }
        const expanded = new Set<number>();
        expandToFill(childrenOf, expanded, 20);
        this.ctBuilt = {tree, childrenOf, expanded};
        m.redraw();
      })
      .catch(() => {});
  }

  private toggle(built: BuiltTree, id: number): void {
    if (built.expanded.has(id)) built.expanded.delete(id);
    else built.expanded.add(id);
  }

  // ---- Flat functions ------------------------------------------------------

  private renderFunctions(attrs: CpuWhereAttrs): m.Children {
    let body: m.Children;
    if (this.fnRows === undefined) {
      this.loadFunctions(attrs);
      body = m(EmptyState, {
        icon: 'hourglass_empty',
        title: 'Loading functions…',
      });
    } else {
      body = breakdownGrid({
        nameTitle: 'Function',
        valueTitle: 'Samples',
        formatValue: (n) => fmtCount(n),
        rows: this.fnRows,
      });
    }
    return m('.pf-sismo-tab__view', body);
  }

  private loadFunctions(attrs: CpuWhereAttrs): void {
    loadHeaviestFunctions(attrs.trace.engine, attrs.priv, 100)
      .then((fns) => {
        this.fnRows = fns.map((f) => ({
          name: f.name,
          value: f.samples,
          share: f.share,
        }));
        m.redraw();
      })
      .catch(() => {
        this.fnRows = [];
        m.redraw();
      });
  }
}

interface BuiltTree {
  readonly tree: CallTree;
  readonly childrenOf: Map<number | null, CallTreeNode[]>;
  readonly expanded: Set<number>;
}

// Depth-first: open the heaviest path until at least `target` rows are visible.
function expandToFill(
  childrenOf: ReadonlyMap<number | null, CallTreeNode[]>,
  expanded: Set<number>,
  target: number,
): void {
  let visible = 0;
  const dfs = (node: CallTreeNode): void => {
    visible++;
    const kids = childrenOf.get(node.id) ?? [];
    if (kids.length > 0 && visible < target) {
      expanded.add(node.id);
      for (const k of kids) dfs(k);
    }
  };
  for (const root of childrenOf.get(null) ?? []) dfs(root);
}
