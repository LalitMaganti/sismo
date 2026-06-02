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

// The "why is this function slow" detail tab. Structured to feel familiar to a
// VTune user — Summary, Caller/Callee, Source/Assembly, Microarchitecture — but
// in Sismo's neutral voice: evidence, never a verdict. A function is a symbol
// aggregated across all its call sites (bottom-up).

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {QuerySlot, SerialTaskQueue} from '../../../base/query_slot';
import {Callout} from '../../../widgets/callout';
import {EmptyState} from '../../../widgets/empty_state';
import {Icon} from '../../../widgets/icon';
import {
  loadButterfly,
  loadFunctionDetail,
  loadFunctionMicroarch,
  loadSourceAsm,
  loadRepresentativeSample,
  type Butterfly,
  type FunctionDetail,
  type FunctionMicroarch,
  type SourceAsm,
  type TmaModel,
} from '../cpu_data';
import type {PrivilegedSet} from '../privileged_set';
import {
  actionLink,
  loadingBody,
  renderStatCard,
  revealInTimeline,
  type StatCard,
} from '../page_common';
import {fmtCount, fmtIpc, fmtMetric, fmtPercent} from '../format';
import {segmentedSwitcher, type Segment} from './segmented';
import {renderButterfly} from './butterfly';
import {SourceAsmPanel} from './source_view';
import type {EntityKind} from './session';

type FnSub = 'summary' | 'butterfly' | 'source' | 'uarch';
const FN_SEGMENTS: ReadonlyArray<Segment<FnSub>> = [
  {key: 'summary', label: 'Summary', icon: 'dashboard'},
  {key: 'butterfly', label: 'Caller/callee', icon: 'account_tree'},
  {key: 'source', label: 'Source/ASM', icon: 'code'},
  {key: 'uarch', label: 'Microarchitecture', icon: 'speed'},
];

// Open (or focus) another detail tab — a butterfly edge to that function's page.
export type DrillFn = (kind: EntityKind, id: string, label: string) => void;

interface CpuDetailAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
  readonly kind: EntityKind;
  // The function name.
  readonly id: string;
  readonly label: string;
  readonly onDrill: DrillFn;
}

export class CpuDetailTab implements m.ClassComponent<CpuDetailAttrs> {
  private subFn: FnSub = 'summary';

  private readonly queue = new SerialTaskQueue();
  private readonly fnSlot = new QuerySlot<FunctionDetail>(this.queue);
  private readonly uarchSlot = new QuerySlot<FunctionMicroarch>(this.queue);
  private readonly bfSlot = new QuerySlot<Butterfly>(this.queue);
  private readonly srcSlot = new QuerySlot<SourceAsm>(this.queue);

  onremove(): void {
    this.fnSlot.dispose();
    this.uarchSlot.dispose();
    this.bfSlot.dispose();
    this.srcSlot.dispose();
  }

  view({attrs}: m.CVnode<CpuDetailAttrs>): m.Children {
    return m(
      '.pf-sismo-tab',
      this.renderHead(attrs),
      m(
        '.pf-sismo-tab__modebar',
        segmentedSwitcher<FnSub>(FN_SEGMENTS, this.subFn, (k) => {
          this.subFn = k;
          m.redraw();
        }),
      ),
      m('.pf-sismo-tab__body', this.renderFnSub(this.subFn, attrs)),
    );
  }

  private renderHead(attrs: CpuDetailAttrs): m.Children {
    return m(
      '.pf-sismo-detail__head',
      m('.pf-sismo-detail__head-title', attrs.label),
      m(
        '.pf-sismo-detail__head-sub',
        'A function across all its call sites — what it cost, who calls it, ' +
          'where the time went in its code, and how efficiently it ran.',
      ),
    );
  }

  private renderFnSub(k: FnSub, attrs: CpuDetailAttrs): m.Children {
    switch (k) {
      case 'summary':
        return this.renderFnSummary(attrs);
      case 'butterfly':
        return this.renderFnButterfly(attrs);
      case 'source':
        return this.renderSource(attrs);
      case 'uarch':
        return this.renderEfficiency(attrs);
    }
  }

  private renderFnSummary(attrs: CpuDetailAttrs): m.Children {
    const fn = this.fnData(attrs);
    if (fn === undefined) return loadingBody('Reading samples…');
    const ua = this.uarchData(attrs);

    const cards: StatCard[] = [
      {
        label: 'Self',
        value: fmtPercent(
          fn.scopeSamples > 0 ? fn.selfSamples / fn.scopeSamples : null,
        ),
        help:
          'Profiled samples whose innermost (on-CPU) frame was this function ' +
          `(${fmtCount(fn.selfSamples)} of ${fmtCount(fn.scopeSamples)}) — its ` +
          'own code, not what it called.',
      },
      {
        label: 'Total',
        value: fmtPercent(
          fn.scopeSamples > 0 ? fn.inclusiveSamples / fn.scopeSamples : null,
        ),
        help:
          'Samples whose stack passes through it anywhere ' +
          `(${fmtCount(fn.inclusiveSamples)}) — self plus everything it called.`,
      },
    ];
    if (ua?.self?.ipc != null) {
      cards.push({
        label: 'CPI',
        value: fmtCpi(ua.self.ipc),
        help:
          `Cycles per instruction (IPC ${fmtIpc(ua.self.ipc)})` +
          (ua.baseline?.ipc != null
            ? `; workload CPI ${fmtCpi(ua.baseline.ipc)}`
            : '') +
          '. Lower is more work per cycle. Approximate (sampled, no PEBS).',
      });
    }
    if (ua?.self?.cycles != null) {
      cards.push({
        label: 'Cycles (approx)',
        value: fmtMetric(ua.self.cycles),
        help: 'Approximate CPU cycles attributed to this function (sampled).',
      });
    }

    if (fn.selfSamples === 0) {
      return m(
        '.pf-sismo-detail__pane',
        m('.pf-sismo-page__stat-row', cards.map(renderStatCard)),
        m(EmptyState, {
          icon: 'search_off',
          title: 'No samples landed directly in this function',
          description:
            'It only appears as a caller. Open Caller/callee to see the calls ' +
            'it takes part in.',
        }),
        this.jump('butterfly', 'Open caller/callee'),
      );
    }

    const facts: m.Children[] = [];
    const selfOfTotal =
      fn.inclusiveSamples > 0 ? fn.selfSamples / fn.inclusiveSamples : null;
    facts.push(
      this.fact(
        'account_tree',
        `${fmtPercent(
          fn.scopeSamples > 0 ? fn.inclusiveSamples / fn.scopeSamples : null,
        )} of profiled samples flow through it; ${fmtPercent(selfOfTotal)} is ` +
          'its own code, the rest is in what it calls.',
        this.jump('butterfly', 'See callers and callees'),
      ),
    );
    if (ua?.self?.dominant != null) {
      facts.push(
        this.fact(
          'speed',
          `When it runs it is mostly ${ua.self.dominant.label.toLowerCase()}` +
            (ua.self.ipc !== null ? ` (IPC ${fmtIpc(ua.self.ipc)})` : '') +
            '.',
          this.jump('uarch', 'See how efficiently it ran'),
        ),
      );
    }
    if (fn.byThread.length > 0) {
      const t = fn.byThread[0];
      const more =
        fn.byThread.length > 1
          ? ` (+${fn.byThread.length - 1} more thread${
              fn.byThread.length > 2 ? 's' : ''
            })`
          : '';
      facts.push(
        this.fact(
          'lan',
          `Most of its self time is on ${t.name} (${fmtPercent(t.share)})${more}` +
            (fn.byModule.length > 0 ? `, in ${fn.byModule[0].name}.` : '.'),
          undefined,
        ),
      );
    }

    return m(
      '.pf-sismo-detail__pane',
      m('.pf-sismo-page__stat-row', cards.map(renderStatCard)),
      facts.length > 0 && m('.pf-sismo-detail__facts', facts),
      ua?.self != null &&
        ua.baseline != null &&
        ua.self.tier !== 'none' &&
        m('.pf-sismo-detail__pane-inset', this.renderTopdown(ua.self, ua.baseline)),
      m(
        '.pf-sismo-page__question-footer',
        actionLink(
          'Show a representative sample on the timeline',
          'open_in_new',
          () => this.revealFunctionSample(attrs),
        ),
      ),
    );
  }

  private renderFnButterfly(attrs: CpuDetailAttrs): m.Children {
    const bf = this.bfData(attrs);
    if (bf === undefined) return loadingBody('Reading the call tree…');
    return renderButterfly(bf, (name) => attrs.onDrill('function', name, name));
  }

  // ---- Source / Assembly ---------------------------------------------------

  private renderSource(attrs: CpuDetailAttrs): m.Children {
    let data: SourceAsm | undefined;
    try {
      data = this.srcSlot.use({
        key: {upids: [...attrs.priv.upids], name: attrs.id},
        queryFn: () => loadSourceAsm(attrs.trace.engine, attrs.priv, attrs.id),
      }).data;
    } catch {
      return loadingBody('Could not read source attribution');
    }
    if (data === undefined) return loadingBody('Reading instruction samples…');
    return m(SourceAsmPanel, {data});
  }

  // ---- Microarchitecture ---------------------------------------------------

  private renderEfficiency(attrs: CpuDetailAttrs): m.Children {
    let ua: FunctionMicroarch | undefined;
    try {
      ua = this.uarchSlot.use({
        key: {upids: [...attrs.priv.upids], name: attrs.id},
        queryFn: () =>
          loadFunctionMicroarch(attrs.trace.engine, attrs.priv, attrs.id),
      }).data;
    } catch {
      return undefined;
    }
    const pane = (body: m.Children) => m('section.pf-sismo-eff', body);
    if (ua === undefined) {
      return pane(m('.pf-sismo-eff__note', ' Reading hardware counters…'));
    }
    if (ua.state === 'no-counters') {
      return pane(
        m(
          '.pf-sismo-eff__note',
          'This trace has no hardware performance counters, so its ' +
            'microarchitecture (IPC, stalls, misses) can’t be characterised — ' +
            'see Source/ASM for where its cycles went.',
        ),
      );
    }
    if (ua.state === 'all-zero') {
      return pane(
        m(
          '.pf-sismo-eff__note',
          'Counters are present but reading zero (typically a VM with no ' +
            'working PMU), so there’s nothing to characterise.',
        ),
      );
    }
    if (ua.self === null || ua.baseline === null) {
      return pane(
        m(
          '.pf-sismo-eff__note',
          `Too few counter samples (${fmtCount(ua.samples)}) to characterise ` +
            'this function’s microarchitecture without the numbers being noise.',
        ),
      );
    }
    return pane(this.renderEfficiencyBody(ua.self, ua.baseline));
  }

  private renderEfficiencyBody(self: TmaModel, base: TmaModel): m.Children {
    const cycShare =
      self.cycles !== null && base.cycles !== null && base.cycles > 0
        ? self.cycles / base.cycles
        : null;
    return [
      self.cycles !== null &&
        m(
          '.pf-sismo-eff__headline',
          m('span.pf-sismo-eff__cyc', `≈ ${fmtMetric(self.cycles)} cycles`),
          cycShare !== null &&
            m(
              'span.pf-sismo-eff__cyc-share',
              ` · ${fmtPercent(cycShare)} of the profiled set’s cycles`,
            ),
        ),
      m(
        '.pf-sismo-eff__caveat',
        'Leaf-attributed from timer samples (no PEBS), and the function and ' +
          'workload figures use slightly different counter accounting — read ' +
          'them as the shape of execution and the size of the gap, not exact ' +
          'per-instruction values. “Workload” is the whole profiled set.',
      ),
      this.renderVitals(self, base),
      this.renderTopdown(self, base),
      this.renderPointer(self, base),
    ];
  }

  private renderVitals(self: TmaModel, base: TmaModel): m.Children {
    const vitals: m.Children[] = [];
    const add = (
      label: string,
      sub: string,
      s: number | null,
      b: number | null,
      fmt: (n: number) => string,
    ) => {
      if (s === null && b === null) return;
      const max = Math.max(s ?? 0, b ?? 0, 1e-9);
      vitals.push(
        m(
          '.pf-sismo-vital',
          m(
            '.pf-sismo-vital__head',
            m('span.pf-sismo-vital__label', label),
            m('span.pf-sismo-vital__sub', sub),
          ),
          m(
            '.pf-sismo-vital__row',
            m('span.pf-sismo-vital__self', s === null ? '—' : fmt(s)),
            m(
              '.pf-sismo-vital__track',
              m('.pf-sismo-vital__fill', {
                style: `width:${((Math.max(0, s ?? 0) / max) * 100).toFixed(
                  1,
                )}%`,
              }),
              b !== null &&
                m('.pf-sismo-vital__mark', {
                  style: `left:${((b / max) * 100).toFixed(1)}%`,
                  title: `workload: ${fmt(b)}`,
                }),
            ),
            m('span.pf-sismo-vital__base', b === null ? '' : `vs ${fmt(b)}`),
          ),
        ),
      );
    };
    add(
      'IPC',
      'instructions per cycle · higher is faster',
      self.ipc,
      base.ipc,
      (n) => fmtIpc(n),
    );
    add(
      'Cache misses',
      'per 1,000 instructions · fewer is better',
      self.cacheMpki,
      base.cacheMpki,
      (n) => n.toFixed(1),
    );
    add(
      'Branch misses',
      'per 1,000 instructions · fewer is better',
      self.branchMpki,
      base.branchMpki,
      (n) => n.toFixed(2),
    );
    return m('.pf-sismo-vitals', vitals);
  }

  // The Top-Down split as one stacked bar + legend; the dominant bucket flagged
  // "largest", the workload's dominant noted. Segment colours are categorical and
  // deliberately muted — they name the bucket, they are not a stoplight.
  private renderTopdown(self: TmaModel, base: TmaModel): m.Children {
    if (self.tier === 'none' || self.buckets.length === 0) return undefined;
    return m(
      '.pf-sismo-tma',
      m(
        '.pf-sismo-eff__sublabel',
        self.tier === 'true-l1'
          ? 'Where its issue slots went'
          : 'Where its cycles stalled',
      ),
      m(
        '.pf-sismo-tma__bar',
        self.buckets.map((bk) =>
          m(`.pf-sismo-tma__seg.pf-sismo-tma__seg--${bk.key}`, {
            style: `width:${(bk.frac * 100).toFixed(1)}%`,
            title: `${bk.label}: ${fmtPercent(bk.frac)}`,
          }),
        ),
      ),
      m(
        '.pf-sismo-tma__legend',
        self.buckets.map((bk) =>
          m(
            '.pf-sismo-tma__key',
            m(`span.pf-sismo-tma__swatch.pf-sismo-tma__seg--${bk.key}`),
            m('span.pf-sismo-tma__key-label', bk.label),
            m('span.pf-sismo-tma__key-pct', fmtPercent(bk.frac)),
            self.dominant?.key === bk.key &&
              m('span.pf-sismo-tma__key-tag', 'largest'),
          ),
        ),
      ),
      base.dominant !== null &&
        m(
          '.pf-sismo-eff__note',
          `Across the whole workload the largest bucket is ` +
            `${base.dominant.label.toLowerCase()} (${fmtPercent(
              base.dominant.frac,
            )}).`,
        ),
    );
  }

  private renderPointer(self: TmaModel, base: TmaModel): m.Children {
    const dom = self.dominant;
    if (dom === null) return undefined;
    const mpki = (n: number | null) => (n === null ? '—' : n.toFixed(1));
    let text: string;
    switch (dom.key) {
      case 'backend':
        text =
          'Most issue slots are backend-bound — the core had work queued but ' +
          'stalled waiting on it (memory or execution-port pressure).';
        if (self.cacheMpki !== null) {
          text +=
            ` Cache misses here are ${mpki(self.cacheMpki)} per 1K instr` +
            ` (workload ${mpki(base.cacheMpki)}).`;
        }
        break;
      case 'frontend':
        text =
          'Mostly frontend-bound — the core stalled fetching or decoding ' +
          'instructions, not waiting on data.';
        break;
      case 'bad-spec':
        text =
          'Bad speculation dominates — cycles ran down mispredicted branch ' +
          'paths whose work was then thrown away.';
        if (self.branchMpki !== null) {
          text +=
            ` Branch misses here are ${self.branchMpki.toFixed(2)} per 1K instr` +
            ` (workload ${base.branchMpki === null ? '—' : base.branchMpki.toFixed(2)}).`;
        }
        break;
      case 'retiring':
        text =
          'Most issue slots retire useful work rather than stalling — by these ' +
          'counters the cost here is the work itself, not a front- or back-end ' +
          'stall.';
        break;
      default:
        text =
          'Cycles here are mostly not stalled — the counters don’t single out a ' +
          'front- or back-end bottleneck.';
        break;
    }
    const baseFrac = base.buckets.find((b) => b.key === dom.key)?.frac;
    const worse =
      baseFrac !== undefined && dom.frac > baseFrac + 0.1
        ? ` That share is higher than the workload’s ${fmtPercent(baseFrac)}.`
        : '';
    return m(Callout, {icon: 'lightbulb_outline'}, text + worse);
  }

  // ---- Shared bits ---------------------------------------------------------

  private revealFunctionSample(attrs: CpuDetailAttrs): void {
    loadRepresentativeSample(attrs.trace.engine, attrs.id, attrs.priv)
      .then((rep) => {
        if (rep === null) {
          revealInTimeline(attrs.trace, {});
          return;
        }
        revealInTimeline(attrs.trace, {
          utids: [rep.utid],
          timeRange: {start: rep.window.start, end: rep.window.end},
        });
      })
      .catch(() => {});
  }

  // A one-line "what stands out" fact on the Summary, with an optional jump into
  // the sub-tab that drills it.
  private fact(icon: string, text: string, jump: m.Children): m.Children {
    return m(
      '.pf-sismo-detail__fact',
      m(Icon, {icon, className: 'pf-sismo-detail__fact-icon'}),
      m('span.pf-sismo-detail__fact-text', text),
      jump,
    );
  }

  private jump(sub: FnSub, label: string): m.Children {
    return actionLink(label, 'arrow_forward', () => {
      this.subFn = sub;
    });
  }

  // ---- Data accessors ------------------------------------------------------

  private fnData(attrs: CpuDetailAttrs): FunctionDetail | undefined {
    try {
      return this.fnSlot.use({
        key: {upids: [...attrs.priv.upids], name: attrs.id},
        queryFn: () =>
          loadFunctionDetail(attrs.trace.engine, attrs.priv, attrs.id),
      }).data;
    } catch {
      return undefined;
    }
  }

  private bfData(attrs: CpuDetailAttrs): Butterfly | undefined {
    try {
      return this.bfSlot.use({
        key: {upids: [...attrs.priv.upids], name: attrs.id},
        queryFn: () => loadButterfly(attrs.trace.engine, attrs.priv, attrs.id),
      }).data;
    } catch {
      return undefined;
    }
  }

  private uarchData(attrs: CpuDetailAttrs): FunctionMicroarch | undefined {
    try {
      return this.uarchSlot.use({
        key: {upids: [...attrs.priv.upids], name: attrs.id},
        queryFn: () =>
          loadFunctionMicroarch(attrs.trace.engine, attrs.priv, attrs.id),
      }).data;
    } catch {
      return undefined;
    }
  }
}

// CPI = inverse of IPC. Lower is better; presented neutrally.
function fmtCpi(ipc: number | null): string {
  if (ipc === null || !isFinite(ipc) || ipc <= 0) return '—';
  return (1 / ipc).toFixed(2);
}
