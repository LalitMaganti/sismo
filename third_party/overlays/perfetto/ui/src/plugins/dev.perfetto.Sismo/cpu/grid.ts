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

// Shared breakdown grid for question blocks: a DataGrid over a small SQL-sorted
// top-N set (name · [group] · value · share), with the share rendered as a
// mini-bar in the cell. DataGrid gives the toolbar, in-grid sorting and
// filtering for free; the rows arrive already ranked and capped from SQL.

import m from 'mithril';
import {DataGrid} from '../../../components/widgets/datagrid/datagrid';
import type {
  ColumnSchema,
  SchemaRegistry,
} from '../../../components/widgets/datagrid/datagrid_schema';
import {InMemoryDataSource} from '../../../components/widgets/datagrid/in_memory_data_source';
import type {Row} from '../../../trace_processor/query_result';
import {fmtPercent} from '../format';

export interface BreakdownGridRow {
  readonly name: string;
  // Numeric, so the grid sorts correctly; formatted for display via formatValue.
  readonly value: number;
  // Share of the whole, 0..1 — rendered as the mini-bar + percent.
  readonly share: number;
  // Optional secondary label (e.g. the process a thread belongs to). Shown as a
  // text column only when the grid declares a groupTitle.
  readonly group?: string;
}

export interface BreakdownGridAttrs {
  readonly nameTitle: string;
  readonly valueTitle: string;
  readonly formatValue: (n: number) => string;
  readonly rows: ReadonlyArray<BreakdownGridRow>;
  // When set, a secondary text column (from row.group) is shown after the name.
  readonly groupTitle?: string;
}

export function breakdownGrid(attrs: BreakdownGridAttrs): m.Children {
  const {nameTitle, valueTitle, formatValue, rows, groupTitle} = attrs;
  const columns: ColumnSchema = {
    name: {title: nameTitle, columnType: 'text'},
    value: {
      title: valueTitle,
      columnType: 'quantitative',
      cellRenderer: (v) => formatValue(Number(v)),
    },
    share: {
      title: 'Share',
      columnType: 'quantitative',
      cellRenderer: (v) => renderShare(Number(v)),
    },
  };
  if (groupTitle !== undefined) {
    columns.group = {title: groupTitle, columnType: 'text'};
  }
  const schema: SchemaRegistry = {row: columns};

  const data: Row[] = rows.map((r) => {
    const row: Row = {name: r.name, value: r.value, share: r.share};
    if (groupTitle !== undefined) row.group = r.group ?? '';
    return row;
  });

  const initialColumns = [
    {id: 'name', field: 'name'},
    ...(groupTitle !== undefined ? [{id: 'group', field: 'group'}] : []),
    {id: 'value', field: 'value'},
    {id: 'share', field: 'share'},
  ];

  return m(DataGrid, {
    className: 'pf-sismo-grid',
    schema,
    rootSchema: 'row',
    data: new InMemoryDataSource(data),
    initialColumns,
    enablePivotControls: false,
    showExportButton: false,
  });
}

function renderShare(frac: number): m.Children {
  return m(
    '.pf-sismo-cellbar',
    m(
      '.pf-sismo-cellbar__track',
      m('.pf-sismo-cellbar__fill', {
        style: `width:${Math.min(100, frac * 100).toFixed(1)}%`,
      }),
    ),
    m('span.pf-sismo-cellbar__pct', fmtPercent(frac)),
  );
}
