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
// textual companion to the Flamegraph tab over the same perf_sample data. Total
// = the leaf landed anywhere in this frame's subtree; Self = the leaf landed on
// this frame exactly. Built on the Grid widget's native indent/chevron support.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {Section} from '../../../widgets/section';
import {Card} from '../../../widgets/card';
import {Grid, GridCell, GridHeaderCell} from '../../../widgets/grid';
import {EmptyState} from '../../../widgets/empty_state';
import {Callout} from '../../../widgets/callout';
import {Intent} from '../../../widgets/common';
import {loadCallTree, type CallTree, type CallTreeNode} from '../cpu_data';
import {fmtCount, fmtPercent} from '../format';
import type {PrivilegedSet} from '../privileged_set';

interface CpuCalltreeViewAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
  // From microarch: lets us tell "no sampler ran" from "samples but no stacks".
  readonly hasSamples: boolean;
}

const TITLE = 'Call tree';
const SUBTITLE =
  'Your code as an expandable top-down call tree from CPU samples. Total = the ' +
  'leaf landed somewhere in this frame’s subtree; Self = the leaf landed on ' +
  'this frame exactly. Click a row to expand or collapse it.';

export class CpuCalltreeView
  implements m.ClassComponent<CpuCalltreeViewAttrs>
{
  private tree?: CallTree;
  private readonly childrenOf = new Map<number | null, CallTreeNode[]>();
  private readonly expanded = new Set<number>();

  constructor({attrs}: m.CVnode<CpuCalltreeViewAttrs>) {
    this.load(attrs.trace, attrs.priv);
  }

  view({attrs}: m.CVnode<CpuCalltreeViewAttrs>): m.Children {
    const t = this.tree;
    if (t === undefined) {
      return m(
        Section,
        {title: TITLE, subtitle: SUBTITLE},
        m(EmptyState, {icon: 'hourglass_empty', title: 'Building call tree…'}),
      );
    }
    if (!t.hasSamples) {
      const msg = attrs.hasSamples
        ? 'CPU samples were captured but none carry symbolised stacks, so no ' +
          'call tree can be built. Make sure debug info is available — ' +
          'unstripped binaries on Linux, dSYMs on macOS.'
        : 'No CPU samples in this trace. Re-record with `sismo record` to ' +
          'capture the stack samples the call tree is built from.';
      return m(
        Section,
        {title: TITLE, subtitle: SUBTITLE},
        m(Callout, {icon: 'science', intent: Intent.Primary}, msg),
      );
    }
    return m(Section, {title: TITLE, subtitle: SUBTITLE}, this.renderGrid(t));
  }

  private renderGrid(t: CallTree): m.Children {
    const total = t.totalSamples || 1;
    const rows: m.Children[][] = [];
    // DFS over the currently-expanded nodes; siblings keep the query's
    // total-descending order (a globally-sorted list buckets into sorted
    // per-parent runs).
    const visit = (node: CallTreeNode): void => {
      const kids = this.childrenOf.get(node.id) ?? [];
      const isExpanded = this.expanded.has(node.id);
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
              kids.length > 0 ? () => this.toggle(node.id) : undefined,
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
    for (const root of this.childrenOf.get(null) ?? []) {
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

  private toggle(id: number): void {
    if (this.expanded.has(id)) this.expanded.delete(id);
    else this.expanded.add(id);
  }

  private async load(trace: Trace, priv: PrivilegedSet): Promise<void> {
    this.tree = await loadCallTree(trace.engine, priv);
    for (const n of this.tree.nodes) {
      const arr = this.childrenOf.get(n.parentId);
      if (arr) arr.push(n);
      else this.childrenOf.set(n.parentId, [n]);
    }
    // Expand the root frames by default so the tree opens on something useful
    // rather than a wall of collapsed rows.
    for (const r of this.childrenOf.get(null) ?? []) this.expanded.add(r.id);
    m.redraw();
  }
}

// Mapping names are full paths; trim to a basename for the inline annotation.
function shortMapping(path: string): string {
  const slash = path.lastIndexOf('/');
  return slash >= 0 ? path.slice(slash + 1) : path;
}
