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

// Cache Functions view: functions ranked by the L3 misses sampled in them, each
// row carrying a stacked bar of WHICH MEMORY those misses hit (heap / an arena /
// a stack / an object / kernel). The cache-hyperfocused replacement for the CPU
// "self cycles per function" table — the question is "which code misses, and on
// what data". Built on the shared DataGrid (sort/filter/export for free); the
// memory bar is a custom cellRenderer reading its row's per-region split.

import m from 'mithril';
import type {Trace} from '../../../../public/trace';
import {QuerySlot, SerialTaskQueue} from '../../../../base/query_slot';
import {Callout} from '../../../../widgets/callout';
import {EmptyState} from '../../../../widgets/empty_state';
import {Tooltip} from '../../../../widgets/tooltip';
import {Intent} from '../../../../widgets/common';
import {DataGrid} from '../../../../components/widgets/datagrid/datagrid';
import type {SchemaRegistry} from '../../../../components/widgets/datagrid/datagrid_schema';
import type {Row, SqlValue} from '../../../../trace_processor/query_result';
import {fmtCount, fmtPercent} from '../../format';
import type {PrivilegedSet} from '../../privileged_set';
import {actionLink} from '../../page_common';
import {
  loadCacheFunctions,
  type CacheFunction,
  type RegionMisses,
} from './queries';
import {regionColor, regionLabel} from './region_color';

interface CacheFunctionsAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
  readonly onDrill: (name: string) => void;
}

export class CacheFunctionsView implements m.ClassComponent<CacheFunctionsAttrs> {
  private readonly queue = new SerialTaskQueue();
  private readonly slot = new QuerySlot<ReadonlyArray<CacheFunction>>(this.queue);

  onremove(): void {
    this.slot.dispose();
  }

  view({attrs}: m.CVnode<CacheFunctionsAttrs>): m.Children {
    let fns: ReadonlyArray<CacheFunction> | undefined;
    try {
      fns = this.slot.use({
        key: {upids: [...attrs.priv.upids]},
        queryFn: () => loadCacheFunctions(attrs.trace.engine, attrs.priv),
      }).data;
    } catch {
      fns = undefined;
    }
    if (fns === undefined) {
      return m(EmptyState, {icon: 'hourglass_empty', title: 'Loading misses…'});
    }
    if (fns.length === 0) {
      return m(EmptyState, {
        icon: 'science',
        title: 'No data-attributed misses',
        description:
          'No sampled L3 miss resolved to a data region. This needs a ' +
          'PEBS-precise cache focus (sismo record --focus cache); without PEBS ' +
          'the loads carry no data address.',
      });
    }

    const total = fns.reduce((a, f) => a + f.misses, 0) || 1;
    // DataGrid rows are flat SqlValue records; the per-region split rides as a
    // JSON string the memory-bar cellRenderer parses back out (alongside the
    // row's own miss count, so segment widths are within-function shares).
    const rows: Row[] = fns.map((f) => ({
      fn: f.name,
      misses: f.misses,
      share: f.misses / total,
      regions: JSON.stringify(f.regions),
    }));

    return m(
      '.pf-sismo-cachefn',
      m(
        Callout,
        {icon: 'info', intent: Intent.Primary},
        'Functions ranked by the L3 misses sampled in them; the bar shows which ' +
          'memory each function’s misses hit. Counts are misses, not time — a ' +
          'miss whose latency is hidden by out-of-order execution costs less. ' +
          'Click a function to see its lines and the data each touched.',
      ),
      this.renderLegend(fns),
      m(DataGrid, {
        schema: this.schema(attrs.onDrill),
        rootSchema: 'fns',
        data: rows,
        initialColumns: [
          {id: 'fn', field: 'fn'},
          {id: 'misses', field: 'misses', sort: 'DESC' as const},
          {id: 'share', field: 'share'},
          {id: 'regions', field: 'regions'},
        ],
      }),
    );
  }

  private schema(onDrill: (name: string) => void): SchemaRegistry {
    return {
      fns: {
        fn: {
          title: 'Function',
          columnType: 'text',
          cellRenderer: (v: SqlValue) =>
            actionLink(String(v), 'open_in_new', () => onDrill(String(v))),
        },
        misses: {
          title: 'Misses',
          columnType: 'quantitative',
          cellRenderer: (v: SqlValue) => fmtCount(Number(v)),
        },
        share: {
          title: '% of misses',
          columnType: 'quantitative',
          cellRenderer: (v: SqlValue) => fmtPercent(Number(v)),
        },
        regions: {
          title: 'Memory missed',
          columnType: 'text',
          cellRenderer: (_v: SqlValue, row: Row) => renderMemoryBar(row),
        },
      },
    };
  }

  private renderLegend(fns: ReadonlyArray<CacheFunction>): m.Children {
    // Collapse by table label, so every file/object region folds into one
    // "file" entry (its exact name lives in the bar tooltips).
    const byLabel = new Map<string, number>();
    for (const f of fns) {
      for (const r of f.regions) {
        const l = regionLabel(r.region);
        byLabel.set(l, (byLabel.get(l) ?? 0) + r.misses);
      }
    }
    const legend = [...byLabel.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([label]) => label);
    return m(
      '.pf-sismo-cachefn__legend',
      legend.map((label) =>
        m(
          '.pf-sismo-cachefn__legend-item',
          m('span.pf-sismo-cachefn__swatch', {style: {background: regionColor(label)}}),
          label,
        ),
      ),
    );
  }
}

// The "Memory missed" cell: a stacked bar of the function's per-region split
// (sums to 100%), decoded from the JSON the row carries, annotated with the
// dominant region + its share (as the flat table showed before).
function renderMemoryBar(row: Row): m.Children {
  const fnMisses = Number(row.misses) || 1;
  let regions: RegionMisses[] = [];
  try {
    regions = JSON.parse(String(row.regions)) as RegionMisses[];
  } catch {
    regions = [];
  }
  const top = regions[0];
  return m(
    '.pf-sismo-cachefn__memcell',
    m(
      '.pf-sismo-cachefn__bar',
      regions.map((r) =>
        // Each segment is its own hover popup naming the region and its share of
        // this function's misses.
        m(
          Tooltip,
          {
            trigger: m('.pf-sismo-cachefn__seg', {
              style: {
                width: `${(r.misses / fnMisses) * 100}%`,
                background: regionColor(r.region),
              },
            }),
          },
          m(
            '.pf-sismo-cachefn__segtip',
            m('span.pf-sismo-cachefn__swatch', {
              style: {background: regionColor(r.region)},
            }),
            m('span.pf-sismo-cachefn__segtip-name', r.region),
            m(
              'span.pf-sismo-cachefn__segtip-val',
              `${fmtCount(r.misses)} · ${fmtPercent(r.misses / fnMisses)}`,
            ),
          ),
        ),
      ),
    ),
    top !== undefined &&
      m(
        'span.pf-sismo-cachefn__topregion',
        `${regionLabel(top.region)} ${fmtPercent(top.misses / fnMisses)}`,
      ),
  );
}
