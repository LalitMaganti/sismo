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
// voice. A monospace listing of the function body, each line carrying its self
// samples and a muted intensity bar (no stoplight colour — the number is the
// signal). A Source | Source+ASM | Assembly toggle interleaves the bundled
// disassembly. Degrades to a disasm-only listing, or a raw per-instruction
// histogram, when source/disasm weren't bundled.

import m from 'mithril';
import {Callout} from '../../../widgets/callout';
import {EmptyState} from '../../../widgets/empty_state';
import {fmtCount} from '../format';
import {segmentedSwitcher, type Segment} from './segmented';
import type {AnnInsn, AnnRow, SourceAsm} from '../cpu_data';

type Mode = 'source' | 'both' | 'asm';

interface Attrs {
  readonly data: SourceAsm;
}

export class SourceAsmPanel implements m.ClassComponent<Attrs> {
  private mode: Mode;

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
    const title =
      d.file !== null
        ? m('span.pf-sismo-srcasm__file', d.file)
        : m('span.pf-sismo-srcasm__file', d.name);
    return m(
      '.pf-sismo-srcasm__toolbar',
      title,
      segs.length > 1 &&
        segmentedSwitcher<Mode>(segs, this.mode, (k) => {
          this.mode = k;
          m.redraw();
        }),
    );
  }

  private renderListing(d: SourceAsm): m.Children {
    if (this.mode === 'asm' || !d.hasSource) {
      const maxInsn = d.insnCounts.reduce((a, i) => Math.max(a, i.samples), 0);
      return m(
        '.pf-sismo-srcasm',
        d.insnCounts.map((insn) => this.renderInsn(insn, maxInsn)),
      );
    }
    const showAsm = this.mode === 'both';
    return m(
      '.pf-sismo-srcasm',
      d.rows.map((r) => this.renderSourceRow(r, d, showAsm)),
    );
  }

  private renderSourceRow(
    r: AnnRow,
    d: SourceAsm,
    showAsm: boolean,
  ): m.Children {
    const hot = r.samples > 0 && r.samples === d.maxLineSamples;
    return [
      m(
        '.pf-sismo-srcasm__row',
        {class: r.samples > 0 ? 'pf-sismo-srcasm__row--sampled' : ''},
        m(
          'span.pf-sismo-srcasm__count',
          r.samples > 0 ? fmtCount(r.samples) : '',
        ),
        heatBar(r.samples, d.maxLineSamples),
        m('span.pf-sismo-srcasm__lineno', r.line ?? ''),
        m(
          'span.pf-sismo-srcasm__code',
          r.text === '' ? ' ' : r.text,
          hot && m('span.pf-sismo-srcasm__tag', 'hottest'),
        ),
      ),
      showAsm &&
        r.insns.map((insn) => this.renderInsn(insn, d.maxLineSamples, true)),
    ];
  }

  private renderInsn(
    insn: AnnInsn,
    max: number,
    indented = false,
  ): m.Children {
    return m(
      '.pf-sismo-srcasm__row.pf-sismo-srcasm__row--insn',
      {class: indented ? 'pf-sismo-srcasm__row--indent' : ''},
      m(
        'span.pf-sismo-srcasm__count',
        insn.samples > 0 ? fmtCount(insn.samples) : '',
      ),
      heatBar(insn.samples, max),
      m('span.pf-sismo-srcasm__addr', `0x${insn.relPc.toString(16)}`),
      m('span.pf-sismo-srcasm__code', insn.text),
    );
  }
}

// A muted single-hue intensity bar (opacity ∝ share of the hottest line). Never
// a stoplight — it's a sparkline beside the number, not a verdict.
function heatBar(samples: number, max: number): m.Children {
  const frac = max > 0 ? samples / max : 0;
  return m(
    '.pf-sismo-srcasm__heat',
    m('.pf-sismo-srcasm__heat-fill', {
      style: `width:${(frac * 100).toFixed(1)}%`,
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
      'listing instead. ' + base
    );
  }
  if (d.hasSource && !d.hasDisasm) {
    return 'Disassembly was not bundled — showing source only. ' + base;
  }
  if (!d.hasSource && !d.hasDisasm) {
    return (
      'Neither source nor disassembly was bundled — showing the raw ' +
      'per-instruction-address histogram. ' + base
    );
  }
  return base;
}
