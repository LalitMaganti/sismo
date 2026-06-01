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

// The Activity board: the middle rung of the zoom ladder between the atemporal
// Overview and the full timeline. The trace is quantised into equal time slices
// and the same metrics the Overview aggregates are drawn as lanes on one shared
// time axis — machine load, your concurrency, and churn — so they can be read
// against each other (e.g. churn spiking where concurrency collapses). Every
// column is a portal: click it to open that slice in the timeline.

import m from 'mithril';
import type {Trace} from '../../../../public/trace';
import {Section} from '../../../../widgets/section';
import {Card} from '../../../../widgets/card';
import {Anchor} from '../../../../widgets/anchor';
import {Grid, GridCell, GridHeaderCell} from '../../../../widgets/grid';
import {EmptyState} from '../../../../widgets/empty_state';
import {Icon} from '../../../../widgets/icon';
import {Tooltip} from '../../../../widgets/tooltip';
import {
  loadActivityBoard,
  loadWindowConsumers,
  type ActivityBoard,
  type ActivityBucket,
  type WindowThreadRow,
} from '../../cpu_data';
import {renderThreadLink, revealInTimeline} from '../../page_common';
import {
  fmtDuration,
  fmtDurationNs,
  fmtMegacycles,
  fmtPercent,
} from '../../format';
import type {PrivilegedSet} from '../../privileged_set';

interface CpuActivityViewAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
}

interface Lane {
  readonly label: string;
  readonly help: string;
  readonly color: 'load' | 'priv' | 'churn' | 'batch' | 'cycles';
  // Bar height as a 0..1 fraction of the lane.
  readonly frac: (b: ActivityBucket) => number;
  // Human-readable value for the hover tooltip.
  readonly text: (b: ActivityBucket) => string;
}

export class CpuActivityView implements m.ClassComponent<CpuActivityViewAttrs> {
  private board?: ActivityBoard;
  private trace?: Trace;
  // The committed selection: an inclusive range of bucket indices. A plain
  // click is a one-bucket range; dragging brushes a wider window.
  private selStart?: number;
  private selEnd?: number;
  // The committed range when it is exactly one column — lets a repeat click on
  // that same column toggle the selection off.
  private committedSingle?: number;
  private windowRows?: WindowThreadRow[];
  // Live brush state while the mouse is held down.
  private brushAnchor?: number;
  private brushing = false;
  // Monotonic token so a stale window-consumers query can't overwrite a newer
  // selection's result.
  private loadSeq = 0;
  private readonly onWindowUp = () => this.endBrush();

  constructor({attrs}: m.CVnode<CpuActivityViewAttrs>) {
    this.load(attrs.trace, attrs.priv);
  }

  onremove(): void {
    window.removeEventListener('mouseup', this.onWindowUp);
  }

  private inSelection(i: number): boolean {
    return (
      this.selStart !== undefined &&
      this.selEnd !== undefined &&
      i >= this.selStart &&
      i <= this.selEnd
    );
  }

  // Mouse down on a column starts a brush anchored there; the range is [anchor,
  // anchor] until the pointer is dragged across neighbours.
  private startBrush(i: number): void {
    this.brushing = true;
    this.brushAnchor = i;
    this.selStart = i;
    this.selEnd = i;
    window.addEventListener('mouseup', this.onWindowUp);
  }

  // Pointer entered a column mid-drag: widen the range to span anchor→i.
  private extendBrush(i: number): void {
    if (!this.brushing || this.brushAnchor === undefined) return;
    this.selStart = Math.min(this.brushAnchor, i);
    this.selEnd = Math.max(this.brushAnchor, i);
    m.redraw();
  }

  // Pointer released: finalise the range. A no-drag click on the already-
  // selected single column clears the selection; otherwise load its consumers.
  private endBrush(): void {
    window.removeEventListener('mouseup', this.onWindowUp);
    if (!this.brushing) return;
    this.brushing = false;
    const a = this.selStart;
    const b = this.selEnd;
    this.brushAnchor = undefined;
    if (a === undefined || b === undefined) return;
    if (a === b && this.committedSingle === a) {
      this.clearSelection();
      m.redraw();
      return;
    }
    this.committedSingle = a === b ? a : undefined;
    this.loadWindow(a, b);
    m.redraw();
  }

  private clearSelection(): void {
    this.selStart = undefined;
    this.selEnd = undefined;
    this.committedSingle = undefined;
    this.windowRows = undefined;
  }

  // Load the threads busy across the selected bucket range [a, b].
  private loadWindow(a: number, b: number): void {
    const board = this.board;
    const trace = this.trace;
    if (board === undefined || trace === undefined) return;
    const lo = board.buckets[a]?.startTs;
    const hi = board.buckets[b]?.endTs;
    if (lo === undefined || hi === undefined) return;
    this.windowRows = undefined;
    const seq = ++this.loadSeq;
    loadWindowConsumers(trace.engine, lo, hi)
      .then((rows) => {
        if (this.loadSeq === seq) {
          this.windowRows = rows;
          m.redraw();
        }
      })
      .catch(() => {
        if (this.loadSeq === seq) {
          this.windowRows = [];
          m.redraw();
        }
      });
  }

  view({attrs}: m.CVnode<CpuActivityViewAttrs>): m.Children {
    const hasPriv = attrs.priv.upids.length > 0;
    const subtitle =
      'Each column is an equal slice of the trace. The lanes share one time ' +
      'axis, so you can line churn up against concurrency and load. Click a ' +
      'column — or drag across several — to see who was busy in that window, ' +
      'then jump to the timeline framed on it.';
    const board = this.board;
    if (board === undefined) {
      return m(
        Section,
        {title: 'Activity over time', subtitle},
        m(EmptyState, {icon: 'hourglass_empty', title: 'Loading activity…'}),
      );
    }
    if (!board.hasData) {
      return m(
        Section,
        {title: 'Activity over time', subtitle},
        m(EmptyState, {icon: 'timeline', title: 'No scheduling data'}),
      );
    }

    const capNs = Number(board.bucketWidthNs) * board.numCpus;
    const widthNs = Number(board.bucketWidthNs);
    const frac = (ns: bigint) => (capNs > 0 ? Number(ns) / capNs : 0);
    const maxSleeps = Math.max(1, ...board.buckets.map((b) => b.sleeps));
    const maxRun = Math.max(1, ...board.buckets.map((b) => b.avgRunNs));
    const yours = hasPriv ? 'your work' : 'the workload';

    const lanes: Lane[] = [
      {
        label: 'Machine load',
        help:
          'Share of all cores busy in each slice — the whole machine, your ' +
          'work plus everything else. Compare with concurrency below to see ' +
          'contention from other processes.',
        color: 'load',
        frac: (b) => frac(b.busyNs),
        text: (b) => `${fmtPercent(frac(b.busyNs))} of cores busy`,
      },
      {
        label: hasPriv ? 'Your concurrency' : 'Concurrency',
        help:
          `Average cores ${yours} kept busy in each slice (peak = the core ` +
          'count). Shows where the parallelism actually happened.',
        color: 'priv',
        frac: (b) => frac(b.privBusyNs),
        text: (b) =>
          `${(widthNs > 0 ? Number(b.privBusyNs) / widthNs : 0).toFixed(1)} cores`,
      },
      {
        label: 'Run/sleep churn',
        help:
          `How often ${yours} went to sleep (off-CPU) per slice — run→sleep ` +
          'transitions, not preemptions. Tall regions switch between running ' +
          'and sleeping a lot.',
        color: 'churn',
        frac: (b) => b.sleeps / maxSleeps,
        text: (b) => `${b.sleeps} sleeps`,
      },
      {
        label: 'Run length',
        help:
          'Mean length of a run before going off-CPU, per slice. Long bars are ' +
          'batched, sustained work; short bars with high churn above are ' +
          'thrashy — too brief for the CPU to ramp up.',
        color: 'batch',
        frac: (b) => b.avgRunNs / maxRun,
        text: (b) => fmtDurationNs(b.avgRunNs),
      },
    ];

    // Cycles delivered per slice, from the perf counters — only when the trace
    // carried them. Sits next to machine load as the compute-intensity view
    // that doesn't need (flaky) cpufreq: flat-but-loaded slices are low-IPC or
    // stalled work, tall slices are dense compute.
    const maxCyc = Math.max(0, ...board.buckets.map((b) => Number(b.cyclesDelta)));
    if (maxCyc > 0) {
      lanes.splice(2, 0, {
        label: hasPriv ? 'Your cycles' : 'Cycles delivered',
        help:
          `Cycles ${yours} retired in each slice, from the CPU performance ` +
          'counters — compute done over time, independent of frequency. Read ' +
          'against machine load: busy-but-few-cycles means stalled or low-IPC ' +
          'work.',
        color: 'cycles',
        frac: (b) => Number(b.cyclesDelta) / maxCyc,
        text: (b) => fmtMegacycles(b.cyclesDelta),
      });
    }

    const originTs = board.buckets[0].startTs;
    const span = board.buckets[board.buckets.length - 1].endTs - originTs;
    return m(
      Section,
      {title: 'Activity over time', subtitle},
      m(
        '.pf-sismo-board',
        lanes.map((lane) => this.renderLane(attrs.trace, board, lane, originTs)),
        m(
          '.pf-sismo-board__axis',
          m('span', '0'),
          m('span', fmtDuration(attrs.trace, span / 2n)),
          m('span', fmtDuration(attrs.trace, span)),
        ),
      ),
      this.renderSliceDetail(attrs.trace, board, originTs, attrs.priv),
    );
  }

  // "Busiest in this window" drill: the threads active across the selected
  // bucket range, yours starred, with a jump that frames the whole window in
  // the timeline. A single column reads as a slice; a brushed range as a span.
  private renderSliceDetail(
    trace: Trace,
    board: ActivityBoard,
    originTs: bigint,
    priv: PrivilegedSet,
  ): m.Children {
    const a = this.selStart;
    const z = this.selEnd;
    if (a === undefined || z === undefined) return undefined;
    const first = board.buckets[a];
    const last = board.buckets[z];
    if (first === undefined || last === undefined) return undefined;
    const start = first.startTs;
    const end = last.endTs;
    const label =
      `t+${fmtDuration(trace, start - originTs)} – ` +
      `t+${fmtDuration(trace, end - originTs)}`;
    const span = a === z ? 'slice' : `${z - a + 1} slices`;
    const rows = this.windowRows;
    return m(
      '.pf-sismo-page__tab-pane',
      m('.pf-sismo-page__tab-pane-label', `Busiest in ${label} (${span})`),
      rows === undefined
        ? m(EmptyState, {icon: 'hourglass_empty', title: 'Loading…'})
        : rows.length === 0
          ? m(EmptyState, {icon: 'block', title: 'Nothing ran in this window'})
          : renderWindowTable(trace, rows, priv),
      m(
        '.pf-sismo-page__question-footer',
        m(
          Anchor,
          {
            href: '#!/viewer',
            icon: 'arrow_forward',
            onclick: (e: Event) => {
              e.preventDefault();
              revealInTimeline(trace, {timeRange: {start, end}});
            },
          },
          'Open this window in the timeline',
        ),
      ),
    );
  }

  private renderLane(
    trace: Trace,
    board: ActivityBoard,
    lane: Lane,
    originTs: bigint,
  ): m.Children {
    return m(
      '.pf-sismo-board__lane',
      m(
        '.pf-sismo-board__lane-head',
        m('span.pf-sismo-board__lane-label', lane.label),
        m(
          Tooltip,
          {
            trigger: m(Icon, {
              icon: 'help_outline',
              className: 'pf-sismo-page__help-icon',
            }),
          },
          lane.help,
        ),
      ),
      m(
        '.pf-sismo-board__strip',
        board.buckets.map((b, i) =>
          m(
            '.pf-sismo-board__bucket',
            {
              className: this.inSelection(i)
                ? 'pf-sismo-board__bucket--selected'
                : undefined,
              title:
                `t+${fmtDuration(trace, b.startTs - originTs)} — ` +
                lane.text(b),
              // Brush: press to anchor, drag across columns to widen, release
              // to commit. preventDefault stops the drag selecting page text.
              onmousedown: (e: MouseEvent) => {
                e.preventDefault();
                this.startBrush(i);
              },
              onmouseenter: () => this.extendBrush(i),
            },
            m(`.pf-sismo-board__fill.pf-sismo-board__fill--${lane.color}`, {
              style: {height: `${clamp01(lane.frac(b)) * 100}%`},
            }),
          ),
        ),
      ),
    );
  }

  private async load(trace: Trace, priv: PrivilegedSet): Promise<void> {
    this.trace = trace;
    try {
      this.board = await loadActivityBoard(trace.engine, priv);
    } catch {
      this.board = {hasData: false, numCpus: 0, bucketWidthNs: 0n, buckets: []};
    }
    m.redraw();
  }
}

function clamp01(n: number): number {
  if (!isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

// The threads busy in the selected slice, runtime-descending. Threads belonging
// to the profiled set are starred so your work stands out against the context.
function renderWindowTable(
  trace: Trace,
  rows: ReadonlyArray<WindowThreadRow>,
  priv: PrivilegedSet,
): m.Children {
  return m(
    Card,
    {className: 'pf-sismo-page__table-card'},
    m(Grid, {
      columns: [
        {key: 'thread', header: m(GridHeaderCell, 'Thread')},
        {key: 'process', header: m(GridHeaderCell, 'Process')},
        {key: 'time', header: m(GridHeaderCell, 'Time in slice')},
      ],
      rowData: rows.map((r) => {
        const mine = r.upid !== null && priv.upids.includes(r.upid);
        return [
          m(
            GridCell,
            {wrap: true},
            mine &&
              m(Icon, {
                icon: 'star',
                filled: true,
                className: 'pf-sismo-page__help-icon',
              }),
            renderThreadLink(trace, r.threadName, r.tid, r.utid),
          ),
          m(GridCell, {wrap: true}, r.processName ?? '—'),
          m(GridCell, {align: 'right'}, fmtDuration(trace, r.runtimeNs)),
        ];
      }),
    }),
  );
}
