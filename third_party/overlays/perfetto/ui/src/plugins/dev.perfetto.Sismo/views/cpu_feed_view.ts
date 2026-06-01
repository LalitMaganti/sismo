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

// CPU observation feed: the ranked card stream that replaces the CPU tabs. Each
// card is an OBSERVATION — a measured cost plus an intent-free contrast, phrased
// as a QUESTION, never a verdict. Detectors run over (priv, focus); the feed
// renders them in the order loadObservations already ranked them (cost x
// surprise). A card shows its contrast as a Meter, expands to an evidence lens
// (flamegraph / calltree / per-function or per-thread/per-core table) lazily on
// demand, and links the representative window into the timeline. The off-CPU
// card is an escape hatch to the Latency section, not on-CPU analysis.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {Time} from '../../../base/time';
import {Button, ButtonVariant} from '../../../widgets/button';
import {Card, CardStack} from '../../../widgets/card';
import {Chip} from '../../../widgets/chip';
import {EmptyState} from '../../../widgets/empty_state';
import {Grid, GridCell, GridHeaderCell} from '../../../widgets/grid';
import {Icon} from '../../../widgets/icon';
import {Tooltip} from '../../../widgets/tooltip';
import {FlamegraphPanel} from '../../../components/flamegraph_panel';
import {Flamegraph, type FlamegraphState} from '../../../widgets/flamegraph';
import {LONG, NUM, STR_NULL} from '../../../trace_processor/query_result';
import {Meter, meterReadout} from '../../dev.perfetto.SismoWidgets/meter';
import {
  buildSampleFlamegraphMetrics,
  loadPerfCounterNames,
  type BreakdownKind,
} from '../stack_timeline';
import {
  clipDurExpr,
  loadCallTree,
  loadMicroarchCounters,
  loadObservations,
  overlapClause,
  type CallTree,
  type CallTreeNode,
  type CallTreeDirection,
  type FocusWindow,
  type DrillLens,
  type Observation,
  type ObservationDrill,
  type ObservationKind,
} from '../cpu_data';
import {fmtCount, fmtDurationNs, fmtPercent} from '../format';
import {goToSismoDomain, goToTimeline, revealEntityWindow} from '../page_common';
import type {PrivilegedSet} from '../privileged_set';

interface CpuFeedViewAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
  // The shared focus window; scopes every detector to that region when set.
  readonly focus?: FocusWindow;
}

// Plain-language kind chips — the small badge says what the card is ABOUT, not
// the internal taxonomy name (a blind user doesn't know what "Volume" means).
// Chips FILE the card by topic; they do not state the diagnosis. "Stalled
// cycles" / "Uneven threads" would pre-decide the answer the headline question
// deliberately leaves to the user.
const KIND_LABEL: Record<ObservationKind, string> = {
  volume: 'Where CPU goes',
  efficiency: 'Work per cycle',
  placement: 'Core placement',
  balance: 'Across threads',
  offcpu: 'Running vs waiting',
};

// The collapsed "show evidence" affordance, phrased as an invitation to
// investigate the specific observation rather than a generic "Show evidence" —
// the bridge from "here's a measurement" to "so look at…".
function evidenceLabel(o: Observation): string {
  switch (o.kind) {
    case 'volume':
      return "See what's costing the time";
    case 'efficiency':
      return 'See the per-function detail';
    case 'balance':
      return 'Compare the threads';
    default:
      return 'Show evidence';
  }
}

// One-line literacy support shown above each expanded evidence lens — the drill
// targets (flamegraph/calltree) are themselves expert artifacts, so name what
// the user is looking at.
function lensCaption(lens: DrillLens): string {
  switch (lens) {
    case 'flamegraph':
      return (
        'Each block is a function; wider = more sampled CPU time. ' +
        'Click a block to zoom in.'
      );
    case 'calltree':
      return (
        'Who called whom. Total % is share of sampled CPU; ' +
        'Self is time in that function itself.'
      );
    case 'funcTable':
      return 'Per function: CPU samples landed in it, and its work per cycle.';
    case 'coresTable':
      return "How this thread's CPU time split across the cores it ran on.";
    case 'threadTable':
      return (
        'CPU time per thread in this process; ' +
        'the highlighted row is the one in the question.'
      );
  }
}

export class CpuFeedView implements m.ClassComponent<CpuFeedViewAttrs> {
  private observations?: ReadonlyArray<Observation>;
  // Heavy evidence is built only when a card is expanded; this stores the
  // expanded state and lazily-built lens per observation id.
  private readonly cards = new Map<string, CardState>();
  // Identity of the load currently in flight; lets a stale resolve be dropped
  // when priv/focus change underneath us.
  private loadKey = '';

  constructor({attrs}: m.CVnode<CpuFeedViewAttrs>) {
    this.load(attrs);
  }

  onbeforeupdate(
    {attrs}: m.CVnode<CpuFeedViewAttrs>,
    old: m.CVnode<CpuFeedViewAttrs>,
  ): void {
    if (
      attrs.priv !== old.attrs.priv ||
      attrs.focus?.start !== old.attrs.focus?.start ||
      attrs.focus?.end !== old.attrs.focus?.end
    ) {
      // Discard lenses before dropping their cards so an in-flight async load
      // resolving against an orphaned lens is a no-op instead of a stray redraw.
      for (const s of this.cards.values()) s.lens?.dispose();
      this.cards.clear();
      this.observations = undefined;
      this.load(attrs);
    }
  }

  view({attrs}: m.CVnode<CpuFeedViewAttrs>): m.Children {
    if (this.observations === undefined) {
      return m(EmptyState, {
        icon: 'hourglass_empty',
        title: 'Finding observations…',
      });
    }
    return m(
      '.pf-sismo-feed',
      this.renderIntro(),
      this.observations.length === 0
        ? m(EmptyState, {
            icon: 'check',
            title: 'Nothing stood out on the CPU',
            description:
              'No single function, thread, or per-cycle hotspot took an ' +
              'outsized share of CPU time here. If it still feels slow, the ' +
              'time may be spent waiting (see the Latency section) or outside ' +
              'the current focus.',
          })
        : [
            m(
              CardStack,
              {className: 'pf-sismo-feed__stack', direction: 'vertical'},
              this.observations.map((o) => this.renderCard(attrs, o)),
            ),
            this.renderFooter(),
          ],
    );
  }

  // A standing frame so a first-time user knows what they're looking at: that
  // this is ranked, on-CPU only, and deliberately asks rather than tells.
  private renderIntro(): m.Children {
    return m(
      '.pf-sismo-feed__intro',
      m(
        '.pf-sismo-feed__intro-title',
        'The most notable things your CPU time is doing',
      ),
      m(
        '.pf-sismo-feed__intro-sub',
        'Most notable first. Each card is an observation posed as a question — ' +
          'only you know what this program is meant to do. On-CPU work only; ' +
          'time spent waiting or blocked lives in the Latency section.',
      ),
    );
  }

  private renderFooter(): m.Children {
    return m(
      '.pf-sismo-feed__foot',
      'Ranked by how much CPU each uses and how much it stands out from the ' +
        'rest of this trace.',
    );
  }

  private renderCard(attrs: CpuFeedViewAttrs, o: Observation): m.Children {
    const state = this.cardState(o.id);
    return m(
      Card,
      {className: 'pf-sismo-card', key: o.id},
      this.renderHead(o),
      this.renderMeter(o),
      this.renderActions(attrs, o, state),
      state.expanded && this.renderEvidence(attrs, o, state),
    );
  }

  private renderHead(o: Observation): m.Children {
    return m(
      '.pf-sismo-card__head',
      m(Chip, {label: KIND_LABEL[o.kind], className: 'pf-sismo-card__kind'}),
      m('.pf-sismo-card__question', o.question),
      o.confidence === 'approximate' &&
        m(
          Tooltip,
          {
            trigger: m(
              'span.pf-sismo-card__approx',
              m(Icon, {icon: 'info'}),
              'sampled',
            ),
          },
          o.note ??
            'Measured by sampling many moments, so the exact figure is ' +
              'approximate — the direction is reliable.',
        ),
    );
  }

  private renderMeter(o: Observation): m.Children {
    return m(Meter, {
      label: o.meter.label,
      help: o.meter.help,
      primary: meterReadout(o.meter.primaryBig, o.meter.primaryCaption),
      bar: o.meter.bar,
      tracks: o.meter.tracks,
      legend: o.meter.legend,
      sub: o.meter.sub,
    });
  }

  private renderActions(
    attrs: CpuFeedViewAttrs,
    o: Observation,
    state: CardState,
  ): m.Children {
    // The off-CPU card is a pointer, not analysis: its primary action leaves the
    // CPU section for Latency rather than expanding an on-CPU evidence lens.
    const evidence =
      o.kind === 'offcpu'
        ? m(Button, {
            label: 'Open Latency section',
            icon: 'open_in_new',
            onclick: () => goToSismoDomain(attrs.trace, 'latency'),
          })
        : m(Button, {
            label: state.expanded ? 'Hide evidence' : evidenceLabel(o),
            icon: state.expanded ? 'expand_less' : 'expand_more',
            variant: ButtonVariant.Minimal,
            onclick: () => {
              state.expanded = !state.expanded;
            },
          });
    return m(
      '.pf-sismo-card__actions',
      evidence,
      m(Button, {
        label: o.exemplar.label,
        icon: 'jump_to_element',
        variant: ButtonVariant.Minimal,
        onclick: () => this.openExemplar(attrs, o),
      }),
    );
  }

  private openExemplar(attrs: CpuFeedViewAttrs, o: Observation): void {
    const {utid, upid, window} = o.exemplar;
    // Function exemplars (volume/efficiency) carry a precise window AND the utid
    // of the sample at it: frame that exact moment and select the thread's row,
    // rather than the entity's whole active span.
    if (window !== undefined) {
      goToTimeline(attrs.trace, utid !== undefined ? {utid} : undefined);
      attrs.trace.scrollTo({
        time: {
          start: Time.fromRaw(window.start),
          end: Time.fromRaw(window.end),
          behavior: 'focus',
        },
      });
      return;
    }
    // Entity exemplars (balance/offcpu): reveal the entity and its active span.
    if (utid !== undefined || upid !== undefined) {
      revealEntityWindow(attrs.trace, {utid, upid});
      return;
    }
    goToTimeline(attrs.trace);
  }

  // The evidence body, built once per card on first expand and cached. The lens
  // is chosen by the drill spec; flamegraph/calltree reuse the shared widgets,
  // tables are small focused Grids over the same loaders the legacy tabs use.
  private renderEvidence(
    attrs: CpuFeedViewAttrs,
    o: Observation,
    state: CardState,
  ): m.Children {
    let lens = state.lens;
    if (lens === undefined) {
      lens = this.buildLens(attrs, o.drill);
      state.lens = lens;
    }
    return m(
      '.pf-sismo-card__evidence',
      m('.pf-sismo-card__lens-caption', lensCaption(o.drill.lens)),
      lens.render(),
    );
  }

  private buildLens(
    attrs: CpuFeedViewAttrs,
    drill: ObservationDrill,
  ): EvidenceLens {
    switch (drill.lens) {
      case 'flamegraph':
        return new FlamegraphLens(attrs.trace, attrs.priv, attrs.focus, drill);
      case 'calltree':
        return new CalltreeLens(attrs.trace, attrs.priv, attrs.focus, drill);
      case 'funcTable':
        return new TableLens(attrs.trace, attrs.priv, attrs.focus, drill, 'func');
      case 'threadTable':
        return new TableLens(
          attrs.trace,
          attrs.priv,
          attrs.focus,
          drill,
          'thread',
        );
      case 'coresTable':
        return new TableLens(attrs.trace, attrs.priv, attrs.focus, drill, 'cores');
      default:
        return new TableLens(
          attrs.trace,
          attrs.priv,
          attrs.focus,
          drill,
          'thread',
        );
    }
  }

  private cardState(id: string): CardState {
    let s = this.cards.get(id);
    if (s === undefined) {
      s = {expanded: false};
      this.cards.set(id, s);
    }
    return s;
  }

  private load(attrs: CpuFeedViewAttrs): void {
    const key = `${attrs.priv.upids.join(',')}|${attrs.focus?.start ?? ''}|${
      attrs.focus?.end ?? ''
    }`;
    this.loadKey = key;
    loadObservations(attrs.trace.engine, attrs.priv, attrs.focus)
      .then((obs) => {
        if (this.loadKey !== key) return;
        this.observations = obs;
        m.redraw();
      })
      .catch(() => {
        if (this.loadKey !== key) return;
        this.observations = [];
        m.redraw();
      });
  }
}

// Convenience wrapper for the page: same attrs, rendered directly.
export function renderCpuFeed(attrs: CpuFeedViewAttrs): m.Children {
  return m(CpuFeedView, attrs);
}

// ---- Per-card expand state -------------------------------------------------

interface CardState {
  expanded: boolean;
  lens?: EvidenceLens;
}

// An evidence lens owns its own async load + render; the feed asks it to render
// and it self-redraws as data arrives. One is built per expanded card. dispose()
// is called when the feed drops the lens so a late async resolve does nothing.
interface EvidenceLens {
  render(): m.Children;
  dispose(): void;
}

// ---- Flamegraph lens -------------------------------------------------------

class FlamegraphLens implements EvidenceLens {
  private readonly scope: ReadonlyArray<string>;
  private breakdownBy: BreakdownKind = 'none';
  private metrics;
  private state: FlamegraphState;
  private availableCounters?: ReadonlySet<string>;
  private discarded = false;

  constructor(
    private readonly trace: Trace,
    priv: PrivilegedSet,
    focus: FocusWindow | undefined,
    drill: ObservationDrill,
  ) {
    // Drill `where` clauses are perf_sample predicates (alias `p`); fall back to
    // the standard priv + focus scope when the detector left them empty.
    const clauses: string[] = [...(drill.where ?? [])];
    if (drill.where === undefined || drill.where.length === 0) {
      if (priv.upids.length > 0) {
        clauses.push(
          `p.utid in (SELECT utid FROM thread WHERE upid IN ` +
            `(${priv.upids.join(',')}))`,
        );
      }
      if (focus !== undefined) {
        clauses.push(`p.ts >= ${focus.start} AND p.ts < ${focus.end}`);
      }
    }
    this.scope = clauses;
    this.metrics = buildSampleFlamegraphMetrics(this.scope, this.breakdownBy);
    this.state = Flamegraph.updateState(undefined, this.metrics);
    // Point the evidence at the headline function: zoom the tree to its frame so
    // the card's question and its flamegraph agree.
    if (drill.focusName !== undefined) {
      this.state = {
        ...this.state,
        filters: [
          ...this.state.filters,
          {kind: 'SHOW_FROM_FRAME', filter: drill.focusName},
        ],
      };
    }
    loadPerfCounterNames(this.trace.engine, this.scope)
      .then((counters) => {
        if (this.discarded) return;
        this.availableCounters = counters;
        this.metrics = buildSampleFlamegraphMetrics(
          this.scope,
          this.breakdownBy,
          counters,
        );
        m.redraw();
      })
      .catch(() => {});
  }

  dispose(): void {
    this.discarded = true;
  }

  render(): m.Children {
    return m(
      '.pf-sismo-card__flamegraph',
      m(FlamegraphPanel, {
        trace: this.trace,
        metrics: this.metrics,
        state: this.state,
        onStateChange: (s) => {
          this.state = s;
          const next = (s.breakdownBy ?? 'none') as BreakdownKind;
          if (next !== this.breakdownBy) {
            this.breakdownBy = next;
            this.metrics = buildSampleFlamegraphMetrics(
              this.scope,
              next,
              this.availableCounters,
            );
          }
        },
      }),
    );
  }
}

// ---- Calltree lens ---------------------------------------------------------

interface BuiltTree {
  readonly tree: CallTree;
  readonly childrenOf: Map<number | null, CallTreeNode[]>;
  readonly expanded: Set<number>;
}

const CALLTREE_MIN_ROWS = 20;

class CalltreeLens implements EvidenceLens {
  private readonly direction: CallTreeDirection;
  private built?: BuiltTree;
  private discarded = false;

  constructor(
    trace: Trace,
    priv: PrivilegedSet,
    focus: FocusWindow | undefined,
    drill: ObservationDrill,
  ) {
    this.direction = drill.calltreeDirection ?? 'top-down';
    loadCallTree(trace.engine, priv, this.direction, focus)
      .then((tree) => {
        if (this.discarded) return;
        const childrenOf = new Map<number | null, CallTreeNode[]>();
        for (const n of tree.nodes) {
          const arr = childrenOf.get(n.parentId);
          if (arr) arr.push(n);
          else childrenOf.set(n.parentId, [n]);
        }
        const expanded = new Set<number>();
        expandToFill(childrenOf, expanded, CALLTREE_MIN_ROWS);
        this.built = {tree, childrenOf, expanded};
        m.redraw();
      })
      .catch(() => {});
  }

  render(): m.Children {
    const built = this.built;
    if (built === undefined) {
      return m(EmptyState, {icon: 'hourglass_empty', title: 'Building call tree…'});
    }
    if (!built.tree.hasSamples) {
      return m(EmptyState, {
        icon: 'science',
        title: 'No symbolised stacks for this scope',
      });
    }
    const total = built.tree.totalSamples || 1;
    const rows: m.Children[][] = [];
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
          node.name,
        ),
        m(GridCell, {align: 'right'}, fmtCount(node.totalSamples)),
        m(GridCell, {align: 'right'}, fmtPercent(node.totalSamples / total)),
        m(GridCell, {align: 'right'}, fmtCount(node.selfSamples)),
      ]);
      if (isExpanded) {
        for (const k of kids) visit(k);
      }
    };
    for (const root of built.childrenOf.get(null) ?? []) visit(root);
    return m(Grid, {
      columns: [
        {key: 'fn', header: m(GridHeaderCell, 'Function')},
        {key: 'total', header: m(GridHeaderCell, 'Total')},
        {key: 'totalpct', header: m(GridHeaderCell, 'Total %')},
        {key: 'self', header: m(GridHeaderCell, 'Self')},
      ],
      rowData: rows,
    });
  }

  private toggle(built: BuiltTree, id: number): void {
    if (built.expanded.has(id)) built.expanded.delete(id);
    else built.expanded.add(id);
  }

  dispose(): void {
    this.discarded = true;
  }
}

// ---- Table lenses (func / thread / cores) ----------------------------------
// Small focused Grids scoped to the card's entity. Each runs one query on build
// and self-redraws; the focus row is emphasised so the asymmetry is visible.

type TableKind = 'func' | 'thread' | 'cores';

interface TableRow {
  readonly label: string;
  readonly sub: string | null;
  readonly value: string;
  readonly aux: string | null;
  readonly focused: boolean;
}

class TableLens implements EvidenceLens {
  private rows?: ReadonlyArray<TableRow>;
  private failed = false;
  private discarded = false;
  private readonly valueHeader: string;
  private readonly auxHeader: string;

  constructor(
    trace: Trace,
    priv: PrivilegedSet,
    focus: FocusWindow | undefined,
    private readonly drill: ObservationDrill,
    private readonly kind: TableKind,
  ) {
    this.valueHeader = kind === 'func' ? 'Samples' : 'CPU time';
    this.auxHeader = kind === 'func' ? 'Work/cycle' : 'Share';
    this.load(trace, priv, focus).catch(() => {
      if (this.discarded) return;
      this.failed = true;
      m.redraw();
    });
  }

  dispose(): void {
    this.discarded = true;
  }

  render(): m.Children {
    if (this.failed) {
      return m(EmptyState, {
        icon: 'error_outline',
        title: 'Could not load this breakdown',
      });
    }
    const rows = this.rows;
    if (rows === undefined) {
      return m(EmptyState, {icon: 'hourglass_empty', title: 'Loading…'});
    }
    const rowData = rows.map((r) => [
      m(
        GridCell,
        {className: r.focused ? 'pf-sismo-card__row--focus' : undefined},
        r.label,
        r.sub !== null && m('span.pf-sismo-card__muted', ` — ${r.sub}`),
      ),
      m(GridCell, {align: 'right'}, r.value),
      m(GridCell, {align: 'right'}, r.aux ?? ''),
    ]);
    return m(Grid, {
      columns: [
        {key: 'label', header: m(GridHeaderCell, this.labelHeader())},
        {key: 'value', header: m(GridHeaderCell, this.valueHeader)},
        {key: 'aux', header: m(GridHeaderCell, this.auxHeader)},
      ],
      rowData,
    });
  }

  private labelHeader(): string {
    return this.kind === 'cores' ? 'Core' : this.kind === 'func' ? 'Function' : 'Thread';
  }

  private async load(
    trace: Trace,
    priv: PrivilegedSet,
    focus: FocusWindow | undefined,
  ): Promise<void> {
    if (this.kind === 'thread') {
      this.rows = await this.loadThreads(trace, priv, focus);
    } else if (this.kind === 'cores') {
      this.rows = await this.loadCores(trace, focus);
    } else {
      this.rows = await this.loadFuncs(trace, priv, focus);
    }
    if (this.discarded) return;
    m.redraw();
  }

  private async loadThreads(
    trace: Trace,
    priv: PrivilegedSet,
    focus: FocusWindow | undefined,
  ): Promise<TableRow[]> {
    // Siblings of one process; the skew is the point, so the focus thread is
    // emphasised and the rest sorted under it by runtime. Window sched the same
    // way the balance headline (loadThreadRows) does: overlap filter + clipped
    // duration, so the evidence runtimes match the ratio that produced the card.
    const upid = this.drill.focusUpid;
    const upidClause =
      upid !== undefined
        ? `thread.upid = ${upid}`
        : priv.upids.length > 0
          ? `thread.upid IN (${priv.upids.join(',')})`
          : '1';
    const res = await trace.engine.query(`
      SELECT
        thread.utid AS utid,
        thread.tid AS tid,
        thread.name AS name,
        sum(${clipDurExpr(focus, 'sched.ts', 'sched.dur')}) AS runtime
      FROM sched
      JOIN thread USING (utid)
      WHERE sched.dur > 0 AND ${upidClause}
        AND NOT (sched.utid IN (SELECT utid FROM thread WHERE is_idle))${overlapClause(focus, 'sched.ts', 'sched.dur')}
      GROUP BY thread.utid
      ORDER BY runtime DESC
      LIMIT 40
    `);
    const it = res.iter({utid: NUM, tid: NUM, name: STR_NULL, runtime: LONG});
    const raw: Array<{row: TableRow; ns: number}> = [];
    let totalNs = 0;
    for (; it.valid(); it.next()) {
      const ns = Number(it.runtime);
      totalNs += ns;
      raw.push({
        ns,
        row: {
          label: it.name ?? `tid ${it.tid}`,
          sub: it.tid !== null ? `tid ${it.tid}` : null,
          value: fmtDurationNs(ns),
          aux: null,
          focused: it.utid === this.drill.focusUtid,
        },
      });
    }
    return raw.map(({row, ns}) => ({
      ...row,
      aux: totalNs > 0 ? fmtPercent(ns / totalNs) : null,
    }));
  }

  private async loadCores(
    trace: Trace,
    focus: FocusWindow | undefined,
  ): Promise<TableRow[]> {
    // One thread's runtime split across the cores it ran on. Aggregate by ucpu
    // (the globally-unique core id) not sched.cpu, so multi-machine traces don't
    // collapse same-numbered cores; window the same way loadThreads does.
    const utid = this.drill.focusUtid;
    if (utid === undefined) return [];
    const res = await trace.engine.query(`
      SELECT
        cpu.cpu AS cpu,
        sum(${clipDurExpr(focus, 'sched.ts', 'sched.dur')}) AS runtime
      FROM sched
      JOIN cpu USING (ucpu)
      WHERE sched.utid = ${utid} AND sched.dur > 0${overlapClause(focus, 'sched.ts', 'sched.dur')}
      GROUP BY cpu.cpu
      ORDER BY runtime DESC
    `);
    const it = res.iter({cpu: NUM, runtime: LONG});
    const raw: Array<{cpu: number; ns: number}> = [];
    let totalNs = 0;
    for (; it.valid(); it.next()) {
      const ns = Number(it.runtime);
      totalNs += ns;
      raw.push({cpu: it.cpu, ns});
    }
    return raw.map(({cpu, ns}) => ({
      label: `CPU ${cpu}`,
      sub: null,
      value: fmtDurationNs(ns),
      aux: totalNs > 0 ? fmtPercent(ns / totalNs) : null,
      focused: cpu === this.drill.focusCpu,
    }));
  }

  private async loadFuncs(
    trace: Trace,
    priv: PrivilegedSet,
    focus: FocusWindow | undefined,
  ): Promise<TableRow[]> {
    // The per-function IPC/TMA leaderboard, scoped + emphasising the focus fn.
    const data = await loadMicroarchCounters(trace.engine, priv, 100, focus);
    return data.perFunc.map((f) => ({
      label: f.name,
      sub: null,
      value: fmtCount(f.samples),
      aux:
        f.tma !== null && f.tma.ipc !== null ? f.tma.ipc.toFixed(2) : '—',
      focused: f.name === this.drill.focusName,
    }));
  }
}

// ---- Shared helpers --------------------------------------------------------

// Depth-first, open the heaviest path until at least `target` rows are visible.
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
