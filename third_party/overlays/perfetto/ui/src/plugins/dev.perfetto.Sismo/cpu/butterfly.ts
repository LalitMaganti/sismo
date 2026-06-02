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

// The caller/callee butterfly panel — VTune's Caller/Callee view in Sismo voice.
// "Called by" on the left, the focus function as a chip in the middle, "Calls
// into" on the right. Each row drills to that function's own page.

import m from 'mithril';
import {Card} from '../../../widgets/card';
import {EmptyState} from '../../../widgets/empty_state';
import {Grid, GridCell, GridHeaderCell} from '../../../widgets/grid';
import {actionLink, renderBar} from '../page_common';
import {fmtCount, fmtPercent} from '../format';
import type {Butterfly, ButterflyEdge} from '../cpu_data';

// `drill` opens the named function's own detail page (the caller wires it to
// onDrill('function', name, name)). `sides` selects which columns to show — the
// stack page's Callers tab wants the left column only.
export function renderButterfly(
  data: Butterfly,
  drill: (name: string) => void,
  sides: 'both' | 'callers' | 'callees' = 'both',
): m.Children {
  const callers =
    sides !== 'callees' &&
    renderColumn(
      'Called by',
      'who drives its cost',
      'No callers recorded — it appears only as a root.',
      data.callers,
      drill,
    );
  const callees =
    sides !== 'callers' &&
    renderColumn(
      'Calls into',
      'where its inclusive cost goes',
      'No callees recorded — it is a leaf.',
      data.callees,
      drill,
    );
  return m(
    '.pf-sismo-detail__pane',
    m(
      '.pf-sismo-butterfly',
      callers,
      m(
        '.pf-sismo-butterfly__focus',
        m('span.pf-sismo-butterfly__focus-name', data.name),
        m(
          'span.pf-sismo-butterfly__focus-sub',
          `${fmtCount(data.inclusiveSamples)} samples through it`,
        ),
      ),
      callees,
    ),
    m(
      '.pf-sismo-page__muted',
      'Edges are weighted by samples flowing through this function. Call sites ' +
        'are merged by name, so a recursive function can appear as its own ' +
        'caller or callee.',
    ),
  );
}

function renderColumn(
  title: string,
  sub: string,
  emptyText: string,
  edges: ReadonlyArray<ButterflyEdge>,
  drill: (name: string) => void,
): m.Children {
  return m(
    '.pf-sismo-butterfly__col',
    m(
      '.pf-sismo-butterfly__col-head',
      m('span.pf-sismo-butterfly__col-title', title),
      m('span.pf-sismo-butterfly__col-sub', sub),
    ),
    edges.length === 0
      ? m(EmptyState, {icon: 'more_horiz', title: emptyText})
      : m(
          Card,
          {className: 'pf-sismo-page__table-card'},
          m(Grid, {
            columns: [
              {key: 'name', header: m(GridHeaderCell, 'Function')},
              {key: 'samples', header: m(GridHeaderCell, 'Samples')},
              {key: 'share', header: m(GridHeaderCell, 'Share')},
            ],
            rowData: edges.map((e) => [
              m(
                GridCell,
                {wrap: true},
                actionLink(e.name, 'code', () => drill(e.name)),
              ),
              m(GridCell, {align: 'right'}, fmtCount(e.samples)),
              m(GridCell, renderBar(e.share, fmtPercent(e.share))),
            ]),
          }),
        ),
  );
}
