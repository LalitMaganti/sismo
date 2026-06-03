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

// The Source/Assembly panel — VTune's annotated source+disassembly in Sismo
// voice. A monospace listing of the function body, each line carrying its
// per-metric self counts and a muted intensity bar (no stoplight colour — the
// number is the signal). A Source | Source+ASM | Assembly toggle interleaves the
// bundled disassembly; the Assembly view draws a branch-arrow gutter
// (objdump --visualize-jumps style) so loops and control flow are legible.
// Degrades to a disasm-only listing, or a raw per-instruction histogram, when
// source/disasm weren't bundled.

import m from 'mithril';
import {Button, ButtonVariant} from '../../../widgets/button';
import {Callout} from '../../../widgets/callout';
import {EmptyState} from '../../../widgets/empty_state';
import {fmtCount, fmtPercent} from '../format';
import {segmentedSwitcher, type Segment} from './segmented';
import {layoutArcs, type Arc} from './branch_arrows';
import {highlightAsm, highlightSource, langFromPath} from './highlight';
import type {AnnInsn, AnnRow, SourceAsm} from '../cpu_data';

type Mode = 'source' | 'both' | 'asm';

// Fixed row height (px) — the arrow gutter's geometry is computed from it, so it
// MUST match `.pf-sismo-srcasm__row { height }` in styles.scss.
const ROW_H = 20;
// Horizontal step between nested arrow lanes, and the rail's right-edge padding.
const LANE_STEP = 9;
const RAIL_PAD = 7;

interface Attrs {
  readonly data: SourceAsm;
}

export class SourceAsmPanel implements m.ClassComponent<Attrs> {
  private mode: Mode;
  private root?: HTMLElement;

  constructor({attrs}: m.CVnode<Attrs>) {
    this.mode = attrs.data.hasSource ? 'source' : 'asm';
  }

  view({attrs}: m.CVnode<Attrs>): m.Children {
    const d = attrs.data;
    if (!d.hasSource && !d.hasDisasm && d.insnCounts.length === 0) {
      return m(EmptyState, {
        icon: 'code_off',
        title: 'No source or disassembly to annotate',
        description:
          'Neither source nor a disassembly listing was bundled for this ' +
          'binary, and no sampled instruction addresses resolved. Record with ' +
          'a build that carries debug info to see line-level detail.',
      });
    }

    return m(
      '.pf-sismo-detail__pane',
      this.renderToolbar(d),
      m(Callout, {icon: 'help_outline'}, captionFor(d)),
      this.renderListing(d),
    );
  }

  private renderToolbar(d: SourceAsm): m.Children {
    const segs: Array<Segment<Mode>> = [];
    if (d.hasSource) segs.push({key: 'source', label: 'Source', icon: 'notes'});
    if (d.hasSource && d.hasDisasm) {
      segs.push({key: 'both', label: 'Source+ASM', icon: 'segment'});
    }
    if (d.hasDisasm) {
      segs.push({key: 'asm', label: 'Assembly', icon: 'memory'});
    }
    const title = m(
      'span.pf-sismo-srcasm__file',
      d.file !== null ? d.file : d.name,
    );
    return m(
      '.pf-sismo-srcasm__toolbar',
      title,
      m(
        '.pf-sismo-srcasm__tools',
        d.maxLineSamples > 0 &&
          m(Button, {
            label: 'Jump to hottest',
            icon: 'local_fire_department',
            variant: ButtonVariant.Minimal,
            onclick: () => this.scrollToHottest(),
          }),
        segs.length > 1 &&
          segmentedSwitcher<Mode>(segs, this.mode, (k) => {
            this.mode = k;
          }),
      ),
    );
  }

  private scrollToHottest(): void {
    const el = this.root?.querySelector('.pf-sismo-srcasm__row--hottest');
    el?.scrollIntoView({block: 'center', behavior: 'smooth'});
  }

  private renderListing(d: SourceAsm): m.Children {
    const asmMode = this.mode === 'asm' || !d.hasSource;
    const body = asmMode ? this.renderAsm(d) : this.renderSource(d);
    return m(
      '.pf-sismo-srcasm',
      {
        oncreate: (v: m.VnodeDOM<Attrs>) => {
          this.root = v.dom as HTMLElement;
        },
      },
      this.renderHeader(d, asmMode),
      body,
    );
  }

  // Sticky column header. The arrow-gutter column has no label.
  private renderHeader(d: SourceAsm, asmMode: boolean): m.Children {
    return m(
      '.pf-sismo-srcasm__row.pf-sismo-srcasm__head',
      asmMode &&
        this.arcLayout(d).laneCount > 0 &&
        m('.pf-sismo-srcasm__rail', {
          style: railStyle(this.arcLayout(d).laneCount),
        }),
      m(
        'span.pf-sismo-srcasm__count',
        {title: 'Self time — timer samples caught on this line/instruction.'},
        'Self',
      ),
      m(
        'span.pf-sismo-srcasm__pct',
        {title: 'Share of this function’s self time.'},
        '%',
      ),
      m('span.pf-sismo-srcasm__heat'),
      m('span.pf-sismo-srcasm__lineno', asmMode ? 'addr' : 'line'),
      m('span.pf-sismo-srcasm__code', asmMode ? 'instruction' : 'source'),
    );
  }

  // Cache the arc layout per data object so we don't recompute it twice a render.
  private cachedArcsFor?: SourceAsm;
  private cachedArcs?: ReturnType<typeof layoutArcs>;
  private arcLayout(d: SourceAsm) {
    if (this.cachedArcsFor !== d) {
      this.cachedArcs = layoutArcs(d.insnCounts);
      this.cachedArcsFor = d;
    }
    return this.cachedArcs!;
  }

  // ---- Assembly (with branch-arrow gutter) ---------------------------------

  private renderAsm(d: SourceAsm): m.Children {
    const insns = d.insnCounts;
    const max = insns.reduce((a, i) => Math.max(a, i.samples), 0);
    const {arcs, laneCount} = this.arcLayout(d);
    return m(
      '.pf-sismo-srcasm__body',
      {style: {position: 'relative'}},
      laneCount > 0 && this.renderArrows(insns.length, arcs, laneCount),
      insns.map((insn) =>
        this.renderInsnRow(insn, d.totalSelf, max, laneCount, false),
      ),
    );
  }

  // One absolutely-positioned SVG overlaying the rail column, drawing an arc per
  // local branch: out to its lane, down/up to the target row, back in with a
  // rightward arrowhead. Back-edges (loops) get a distinct class.
  private renderArrows(
    rowCount: number,
    arcs: ReadonlyArray<Arc>,
    laneCount: number,
  ): m.Children {
    const railW = laneCount * LANE_STEP + RAIL_PAD;
    const yOf = (idx: number) => idx * ROW_H + ROW_H / 2;
    const children: m.Children[] = [];
    for (const a of arcs) {
      const laneX = railW - (a.lane + 1) * LANE_STEP;
      const y1 = yOf(a.fromIdx);
      const y2 = yOf(a.toIdx);
      children.push(
        m('path.pf-sismo-srcasm__arc', {
          className: a.backEdge ? 'pf-sismo-srcasm__arc--loop' : undefined,
          d: `M${railW},${y1} H${laneX} V${y2} H${railW}`,
        }),
      );
      // Arrowhead at the target, pointing right into the row.
      children.push(
        m('path.pf-sismo-srcasm__arc-head', {
          d: `M${railW - 4},${y2 - 3} L${railW},${y2} L${railW - 4},${y2 + 3}`,
        }),
      );
    }
    return m(
      'svg.pf-sismo-srcasm__arrows',
      {
        width: railW,
        height: rowCount * ROW_H,
        style: {width: `${railW}px`, height: `${rowCount * ROW_H}px`},
      },
      children,
    );
  }

  // ---- Source (optionally with interleaved asm) ----------------------------

  private renderSource(d: SourceAsm): m.Children {
    const showAsm = this.mode === 'both';
    const lang = langFromPath(d.file);
    // Thread block-comment state across lines so multi-line /* … */ stays styled.
    let open = false;
    const rows: m.Children[] = [];
    for (const r of d.rows) {
      const hl = highlightSource(r.text, r.text === '' ? 'plain' : lang, open);
      open = hl.open;
      rows.push(this.renderSourceRow(r, d, hl.spans));
      if (showAsm) {
        for (const insn of r.insns) {
          rows.push(
            this.renderInsnRow(insn, d.totalSelf, d.maxLineSamples, 0, true),
          );
        }
      }
    }
    return m('.pf-sismo-srcasm__body', rows);
  }

  private renderSourceRow(
    r: AnnRow,
    d: SourceAsm,
    code: m.Children,
  ): m.Children {
    const hot = r.samples > 0 && r.samples === d.maxLineSamples;
    return m(
      '.pf-sismo-srcasm__row',
      {
        class: hot ? 'pf-sismo-srcasm__row--hottest' : '',
        style: rowShade(r.samples, d.maxLineSamples),
      },
      countCell(r.samples),
      pctCell(r.samples, d.totalSelf),
      heatBar(r.samples, d.maxLineSamples),
      m('span.pf-sismo-srcasm__lineno', r.line ?? ''),
      m(
        'span.pf-sismo-srcasm__code',
        r.text === '' ? ' ' : code,
        hot && m('span.pf-sismo-srcasm__tag', 'hottest'),
      ),
    );
  }

  private renderInsnRow(
    insn: AnnInsn,
    totalSelf: number,
    max: number,
    laneCount: number,
    indented: boolean,
  ): m.Children {
    const hot = !indented && insn.samples > 0 && insn.samples === max;
    return m(
      '.pf-sismo-srcasm__row.pf-sismo-srcasm__row--insn',
      {
        class:
          (indented ? 'pf-sismo-srcasm__row--indent ' : '') +
          (hot ? 'pf-sismo-srcasm__row--hottest' : ''),
        // Indented (under-source) rows aren't heat-shaded — the source line above
        // already carries the line's heat.
        style: indented ? undefined : rowShade(insn.samples, max),
      },
      laneCount > 0 &&
        m('.pf-sismo-srcasm__rail', {style: railStyle(laneCount)}),
      countCell(insn.samples),
      pctCell(insn.samples, totalSelf),
      heatBar(insn.samples, max),
      m('span.pf-sismo-srcasm__addr', `0x${insn.relPc.toString(16)}`),
      m('span.pf-sismo-srcasm__code', highlightAsm(insn.text)),
    );
  }
}

// ---- small render helpers --------------------------------------------------

function countCell(samples: number): m.Children {
  return m('span.pf-sismo-srcasm__count', samples > 0 ? fmtCount(samples) : '');
}

function pctCell(samples: number, total: number): m.Children {
  const txt = samples > 0 && total > 0 ? fmtPercent(samples / total) : '';
  return m('span.pf-sismo-srcasm__pct', txt);
}

// Graded row tint: a single hue at low alpha ∝ share of the hottest line, so a
// glance shows where the heat concentrates. Subtle enough to keep text readable;
// not a stoplight (no hue change by severity).
function rowShade(
  samples: number,
  max: number,
): Record<string, string> | undefined {
  if (samples <= 0 || max <= 0) return undefined;
  const frac = samples / max;
  return {background: `rgba(52, 120, 246, ${(0.22 * frac).toFixed(3)})`};
}

function railStyle(laneCount: number): Record<string, string> {
  return {flex: `0 0 ${laneCount * LANE_STEP + RAIL_PAD}px`};
}

// A muted single-hue intensity bar (width + opacity ∝ share of the hottest
// line). Never a stoplight — it's a sparkline beside the number, not a verdict.
function heatBar(samples: number, max: number): m.Children {
  const frac = max > 0 ? samples / max : 0;
  return m(
    '.pf-sismo-srcasm__heat',
    m('.pf-sismo-srcasm__heat-fill', {
      style: {
        width: `${(frac * 100).toFixed(1)}%`,
        opacity: `${(0.35 + 0.65 * frac).toFixed(2)}`,
      },
      title: samples > 0 ? `${fmtCount(samples)} samples` : '',
    }),
  );
}

function captionFor(d: SourceAsm): string {
  const base =
    'Counts are self time — timer samples whose instruction pointer was caught ' +
    'in this function. Without PEBS/LBR the IP can skid a few instructions past ' +
    'the one that actually stalled, so read a hot line as a neighbourhood, not ' +
    'an exact culprit.';
  if (!d.hasSource && d.hasDisasm) {
    return (
      'Source text was not bundled for this binary — showing the disassembly ' +
      'listing instead. ' +
      base
    );
  }
  if (d.hasSource && !d.hasDisasm) {
    return 'Disassembly was not bundled — showing source only. ' + base;
  }
  if (!d.hasSource && !d.hasDisasm) {
    return (
      'Neither source nor disassembly was bundled — showing the raw ' +
      'per-instruction-address histogram. ' +
      base
    );
  }
  return base;
}
