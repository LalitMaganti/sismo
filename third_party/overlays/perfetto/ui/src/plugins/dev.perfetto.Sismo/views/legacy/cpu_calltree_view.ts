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

// CPU "Calltree" lens: the sampled call tree as an expandable tree-table — the
// textual companion to the Flamegraph tab over the same perf_sample data. A
// Top-down / Bottom-up toggle mirrors the flamegraph's two readings: top-down
// walks from callers into callees, bottom-up inverts it so the sampled
// functions are the roots and you expand into who called them.

import m from 'mithril';
import type {Trace} from '../../../../public/trace';
import {Section} from '../../../../widgets/section';
import {Card} from '../../../../widgets/card';
import {Grid, GridCell, GridHeaderCell} from '../../../../widgets/grid';
import {EmptyState} from '../../../../widgets/empty_state';
import {Callout} from '../../../../widgets/callout';
import {Intent} from '../../../../widgets/common';
import {
  loadCallTree,
  type CallTree,
  type CallTreeNode,
  type CallTreeDirection,
  type FocusWindow,
} from '../../cpu_data';
import {fmtCount, fmtPercent} from '../../format';
import type {PrivilegedSet} from '../../privileged_set';

interface CpuCalltreeViewAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
  // From microarch: lets us tell "no sampler ran" from "samples but no stacks".
  readonly hasSamples: boolean;
  // The shared focus window; scopes the call tree to that region when set.
  readonly focus?: FocusWindow;
}

// Depth-first, expand the heaviest path until at least this many rows are
// visible — opens the tree onto something substantial rather than a handful of
// collapsed roots.
const MIN_VISIBLE_ROWS = 25;

const TITLE = 'Call tree';

const SUBTITLE: Record<CallTreeDirection, string> = {
  'top-down':
    'Your code as an expandable top-down call tree from CPU samples. Total = ' +
    'the leaf landed somewhere in this frame’s subtree; Self = the leaf landed ' +
    'on this frame exactly. Click a row to expand or collapse it.',
  'bottom-up':
    'The call tree inverted: each root is a function the samples landed on; ' +
    'expand to see who called it. Total = samples flowing up through this ' +
    'function; Self = samples where it was the leaf. Click a row to expand it.',
};

// The expandable state for one direction, built once and cached so flipping the
// toggle doesn't re-query or lose what you'd opened.
interface Built {
  readonly tree: CallTree;
  readonly childrenOf: Map<number | null, CallTreeNode[]>;
  readonly expanded: Set<number>;
}

export class CpuCalltreeView
  implements m.ClassComponent<CpuCalltreeViewAttrs>
{
  private direction: CallTreeDirection = 'top-down';
  private readonly built = new Map<CallTreeDirection, Built>();
  private focus?: FocusWindow;

  constructor({attrs}: m.CVnode<CpuCalltreeViewAttrs>) {
    this.focus = attrs.focus;
    this.load(attrs.trace, attrs.priv, this.direction);
  }

  view({attrs}: m.CVnode<CpuCalltreeViewAttrs>): m.Children {
    const subtitle = SUBTITLE[this.direction];
    const built = this.built.get(this.direction);
    const body = (): m.Children => {
      if (built === undefined) {
        return m(EmptyState, {
          icon: 'hourglass_empty',
          title: 'Building call tree…',
        });
      }
      if (!built.tree.hasSamples) {
        const msg = attrs.hasSamples
          ? 'CPU samples were captured but none carry symbolised stacks, so no ' +
            'call tree can be built. Make sure debug info is available — ' +
            'unstripped binaries on Linux, dSYMs on macOS.'
          : 'No CPU samples in this trace. Re-record with `sismo record` to ' +
            'capture the stack samples the call tree is built from.';
        return m(Callout, {icon: 'science', intent: Intent.Primary}, msg);
      }
      return this.renderGrid(built);
    };
    return m(
      Section,
      {title: TITLE, subtitle},
      this.renderDirectionToggle(attrs),
      body(),
    );
  }

  // Top-down | Bottom-up segmented control, matching the scope toggle on the
  // Cores tab. Switching builds the other direction lazily on first use.
  private renderDirectionToggle(attrs: CpuCalltreeViewAttrs): m.Children {
    const seg = (dir: CallTreeDirection, label: string) =>
      m(
        'button.pf-sismo-page__seg',
        {
          className:
            this.direction === dir ? 'pf-sismo-page__seg--active' : undefined,
          onclick: () => {
            if (this.direction === dir) return;
            this.direction = dir;
            if (!this.built.has(dir)) this.load(attrs.trace, attrs.priv, dir);
          },
        },
        label,
      );
    return m(
      '.pf-sismo-page__seg-row',
      seg('top-down', 'Top-down'),
      seg('bottom-up', 'Bottom-up'),
    );
  }

  private renderGrid(built: Built): m.Children {
    const total = built.tree.totalSamples || 1;
    const rows: m.Children[][] = [];
    // DFS over the currently-expanded nodes; siblings keep the query's
    // total-descending order (a globally-sorted list buckets into sorted
    // per-parent runs).
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
          m('span', node.name),
          node.mappingName !== null &&
            m(
              'span.pf-sismo-page__muted',
              ` — ${shortMapping(node.mappingName)}`,
            ),
        ),
        m(GridCell, {align: 'right'}, fmtCount(node.totalSamples)),
        m(GridCell, {align: 'right'}, fmtPercent(node.totalSamples / total)),
        m(GridCell, {align: 'right'}, fmtCount(node.selfSamples)),
        m(GridCell, {align: 'right'}, fmtPercent(node.selfSamples / total)),
      ]);
      if (isExpanded) {
        for (const k of kids) visit(k);
      }
    };
    for (const root of built.childrenOf.get(null) ?? []) {
      visit(root);
    }
    return m(
      Card,
      {className: 'pf-sismo-page__table-card'},
      m(Grid, {
        columns: [
          {key: 'fn', header: m(GridHeaderCell, 'Function')},
          {key: 'total', header: m(GridHeaderCell, 'Total')},
          {key: 'totalpct', header: m(GridHeaderCell, 'Total %')},
          {key: 'self', header: m(GridHeaderCell, 'Self')},
          {key: 'selfpct', header: m(GridHeaderCell, 'Self %')},
        ],
        rowData: rows,
      }),
    );
  }

  private toggle(built: Built, id: number): void {
    if (built.expanded.has(id)) built.expanded.delete(id);
    else built.expanded.add(id);
  }

  private async load(
    trace: Trace,
    priv: PrivilegedSet,
    direction: CallTreeDirection,
  ): Promise<void> {
    const tree = await loadCallTree(trace.engine, priv, direction, this.focus);
    const childrenOf = new Map<number | null, CallTreeNode[]>();
    for (const n of tree.nodes) {
      const arr = childrenOf.get(n.parentId);
      if (arr) arr.push(n);
      else childrenOf.set(n.parentId, [n]);
    }
    const expanded = new Set<number>();
    expandToFill(childrenOf, expanded, MIN_VISIBLE_ROWS);
    this.built.set(direction, {tree, childrenOf, expanded});
    m.redraw();
  }
}

// Depth-first, expand the heaviest path first, marking nodes expanded until at
// least `target` rows would be visible. Children are already total-descending,
// so this opens the dominant stack rather than an arbitrary one.
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

// Mapping names are full paths; trim to a basename for the inline annotation.
function shortMapping(path: string): string {
  const slash = path.lastIndexOf('/');
  return slash >= 0 ? path.slice(slash + 1) : path;
}
