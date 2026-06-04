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

// Shared call-tree / flat-functions models derived from the flamegraph's
// laid-out nodes (computeFlamegraphTree output). Helper level — no view state —
// so any deep-dive (the CPU "where" tab, the bespoke cache views) can render an
// expandable call tree or a flat functions ranking over its own weighting
// without depending on another view component.

import type {FlamegraphQueryData} from '../../../widgets/flamegraph';
import type {BreakdownGridRow} from './grid';

// Synthetic parent id of the displayed roots (computeFlamegraphTree emits -1 for
// a node with no parent).
export const ROOT = -1;

export interface CtNode {
  readonly id: number;
  readonly parentId: number; // ROOT at the top of the displayed tree
  readonly name: string;
  readonly self: number; // self weight (cycles / misses / …)
  readonly total: number; // cumulative weight
}

export interface BuiltTree {
  readonly childrenOf: Map<number, CtNode[]>; // keyed by parentId (ROOT = roots)
  readonly expanded: Set<number>;
  readonly totalValue: number; // denominator for Total %
  readonly hasRows: boolean;
}

export const EMPTY_BUILT_TREE: BuiltTree = {
  childrenOf: new Map(),
  expanded: new Set(),
  totalValue: 1,
  hasRows: false,
};

// Turn the flamegraph's laid-out nodes into an expandable call-tree model. For a
// pivot we keep only the callee half (depth >= 1): the pivot frame and what it
// called. (computeFlamegraphTree puts callees at positive depth and callers at
// negative depth; a tree-table can't show the callers above the root.)
export function buildCalltree(
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
// by name and laid out heaviest-first by SQL. So the flat self-per-function
// ranking is just those roots, read in order — no JS aggregation or sorting.
// Share is each function's self over the total self across all roots.
export function flattenFunctions(
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
export function expandToFill(
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
