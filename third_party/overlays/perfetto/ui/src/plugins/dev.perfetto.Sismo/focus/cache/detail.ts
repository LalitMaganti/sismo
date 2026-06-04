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

// The cache function page: the bottom of the drill, focused entirely on this
// function's misses. A headline band — how many misses, what share of the
// trace's, and WHICH MEMORY they hit (the region mix) — then the source/asm
// listing with per-line misses and, beside each hot line, the data it touched.
// The cache domain's own detail; it composes the source/asm renderer widget but
// frames it with the data-side context the cache analyst actually came for.

import m from 'mithril';
import type {Trace} from '../../../../public/trace';
import {QuerySlot, SerialTaskQueue} from '../../../../base/query_slot';
import {EmptyState} from '../../../../widgets/empty_state';
import {loadSourceAsm, type SourceAsm} from '../../cpu_data';
import {SourceAsmPanel} from '../../cpu/source_view';
import {fmtCount, fmtPercent} from '../../format';
import type {PrivilegedSet} from '../../privileged_set';
import {loadTotalMisses} from './queries';
import {regionColor, regionLabel} from './region_color';

interface CacheDetailAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
  // The function (symbol) to inspect.
  readonly name: string;
}

interface DetailData {
  readonly asm: SourceAsm;
  readonly totalMisses: number;
}

export class CacheDetailView implements m.ClassComponent<CacheDetailAttrs> {
  private readonly queue = new SerialTaskQueue();
  private readonly slot = new QuerySlot<DetailData>(this.queue);

  onremove(): void {
    this.slot.dispose();
  }

  view({attrs}: m.CVnode<CacheDetailAttrs>): m.Children {
    let data: DetailData | undefined;
    try {
      data = this.slot.use({
        key: {name: attrs.name, upids: [...attrs.priv.upids]},
        queryFn: async () => ({
          asm: await loadSourceAsm(attrs.trace.engine, attrs.priv, attrs.name),
          totalMisses: await loadTotalMisses(attrs.trace.engine, attrs.priv),
        }),
      }).data;
    } catch {
      data = undefined;
    }
    if (data === undefined) {
      return m(EmptyState, {icon: 'hourglass_empty', title: `Loading ${attrs.name}…`});
    }
    return m(
      '.pf-sismo-detail__pane.pf-sismo-cachedetail',
      this.renderHeader(data),
      m(SourceAsmPanel, {data: data.asm}),
    );
  }

  private renderHeader(data: DetailData): m.Children {
    const {asm, totalMisses} = data;
    const misses = asm.totalSelf;
    const share = totalMisses > 0 ? misses / totalMisses : 0;
    const regionTotal = asm.dataTotal > 0 ? asm.dataTotal : 1;
    return m(
      '.pf-sismo-cachedetail__head',
      m('.pf-sismo-cachedetail__name', asm.name),
      m(
        '.pf-sismo-cachedetail__stats',
        m(
          '.pf-sismo-cachedetail__stat',
          m('.pf-sismo-cachedetail__stat-val', fmtCount(misses)),
          m('.pf-sismo-cachedetail__stat-label', 'misses (self)'),
        ),
        m(
          '.pf-sismo-cachedetail__stat',
          m('.pf-sismo-cachedetail__stat-val', fmtPercent(share)),
          m('.pf-sismo-cachedetail__stat-label', 'of sampled misses'),
        ),
      ),
      asm.functionData.length > 0 &&
        m(
          '.pf-sismo-cachedetail__data',
          m('.pf-sismo-cachedetail__data-title', 'Memory this function misses on'),
          m(
            '.pf-sismo-cachefn__bar.pf-sismo-cachedetail__bar',
            asm.functionData.map((r) =>
              m('.pf-sismo-cachefn__seg', {
                style: {
                  width: `${(r.count / regionTotal) * 100}%`,
                  background: regionColor(r.symbol),
                },
                title: `${r.symbol}: ${fmtCount(r.count)} (${fmtPercent(r.count / regionTotal)})`,
              }),
            ),
          ),
          this.renderLegend(asm.functionData, regionTotal),
        ),
    );
  }

  // Legend for the header bar: collapse file/object regions into one "file"
  // entry (their exact names live in the bar segments' tooltips).
  private renderLegend(
    functionData: ReadonlyArray<{readonly symbol: string; readonly count: number}>,
    regionTotal: number,
  ): m.Children {
    const byLabel = new Map<string, number>();
    for (const r of functionData) {
      const l = regionLabel(r.symbol);
      byLabel.set(l, (byLabel.get(l) ?? 0) + r.count);
    }
    const entries = [...byLabel.entries()].sort((a, b) => b[1] - a[1]);
    return m(
      '.pf-sismo-cachefn__legend',
      entries.map(([label, count]) =>
        m(
          '.pf-sismo-cachefn__legend-item',
          m('span.pf-sismo-cachefn__swatch', {style: {background: regionColor(label)}}),
          `${label} — ${fmtCount(count)} (${fmtPercent(count / regionTotal)})`,
        ),
      ),
    );
  }
}
