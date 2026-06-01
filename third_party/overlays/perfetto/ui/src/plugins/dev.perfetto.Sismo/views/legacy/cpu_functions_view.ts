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

// CPU "Functions" tab: where the cycles actually went, broken down by symbol
// (leaf-frame self time) and by library/mapping. Driven by CPU samples.

import m from 'mithril';
import {Section} from '../../../../widgets/section';
import {Card} from '../../../../widgets/card';
import {Grid, GridCell, GridHeaderCell} from '../../../../widgets/grid';
import {EmptyState} from '../../../../widgets/empty_state';
import {Callout} from '../../../../widgets/callout';
import {Intent} from '../../../../widgets/common';
import type {HotMappingRow, HotSymbolRow, MicroarchData} from '../../cpu_data';
import {fmtCount, fmtPercent} from '../../format';

export function renderCpuFunctions(m_: MicroarchData): m.Children {
  if (!m_.hasSamples) {
    return m(
      Section,
      {
        title: 'Functions',
        subtitle:
          'Where the cycles actually went, broken down by symbol and by ' +
          'library. Requires CPU sampling.',
      },
      m(EmptyState, {
        icon: 'science',
        title: 'No CPU samples in this trace',
        description:
          'Re-record with `sismo record` to capture stack samples; ' +
          'they’re what drives the hot-symbol breakdown.',
      }),
    );
  }
  if (!m_.hasSymbols) {
    return m(
      Section,
      {
        title: 'Functions',
        subtitle:
          'Where the cycles actually went, broken down by symbol and by library.',
      },
      m(
        Callout,
        {icon: 'info', intent: Intent.Primary},
        `${fmtCount(m_.totalSamples)} samples were captured but none ` +
          'were symbolised. Make sure debug info is available — ' +
          'unstripped binaries on Linux, dSYMs on macOS.',
      ),
    );
  }
  return m(
    Section,
    {
      title: 'Functions',
      subtitle:
        `Where the cycles actually went. Based on ${fmtCount(m_.totalSamples)} ` +
        'sampled stacks (leaf frame = currently-executing function).',
    },
    m(
      '.pf-sismo-page__microarch',
      m(
        '.pf-sismo-page__microarch-col',
        m('.pf-sismo-page__tab-pane-label', 'Hot symbols'),
        renderHotSymbolTable(m_.hotSymbols),
      ),
      m(
        '.pf-sismo-page__microarch-col',
        m('.pf-sismo-page__tab-pane-label', 'Hot libraries / mappings'),
        renderHotMappingTable(m_.hotMappings),
      ),
    ),
  );
}

export function renderHotSymbolTable(rows: ReadonlyArray<HotSymbolRow>): m.Children {
  if (rows.length === 0) {
    return m(EmptyState, {icon: 'code', title: 'No hot symbols'});
  }
  const data = rows.map((r) => [
    m(
      GridCell,
      {wrap: true},
      m('span', r.name),
      r.mappingName !== null &&
        m('span.pf-sismo-page__muted', ` — ${shortMapping(r.mappingName)}`),
    ),
    m(GridCell, {align: 'right'}, fmtCount(r.samples)),
    m(GridCell, {align: 'right'}, fmtPercent(r.share)),
  ]);
  return m(
    Card,
    {className: 'pf-sismo-page__table-card'},
    m(Grid, {
      columns: [
        {key: 'symbol', header: m(GridHeaderCell, 'Symbol')},
        {key: 'samples', header: m(GridHeaderCell, 'Samples')},
        {key: 'share', header: m(GridHeaderCell, '% of samples')},
      ],
      rowData: data,
    }),
  );
}

export function renderHotMappingTable(rows: ReadonlyArray<HotMappingRow>): m.Children {
  if (rows.length === 0) {
    return m(EmptyState, {icon: 'inventory_2', title: 'No mapping data'});
  }
  const data = rows.map((r) => [
    m(GridCell, {wrap: true}, shortMapping(r.name)),
    m(GridCell, {align: 'right'}, fmtCount(r.samples)),
    m(GridCell, {align: 'right'}, fmtPercent(r.share)),
  ]);
  return m(
    Card,
    {className: 'pf-sismo-page__table-card'},
    m(Grid, {
      columns: [
        {key: 'mapping', header: m(GridHeaderCell, 'Mapping')},
        {key: 'samples', header: m(GridHeaderCell, 'Samples')},
        {key: 'share', header: m(GridHeaderCell, '% of samples')},
      ],
      rowData: data,
    }),
  );
}

// Mapping names from stack_profile_mapping are full paths; trim to a basename
// so the table column stays readable.
function shortMapping(path: string): string {
  const slash = path.lastIndexOf('/');
  return slash >= 0 ? path.slice(slash + 1) : path;
}
