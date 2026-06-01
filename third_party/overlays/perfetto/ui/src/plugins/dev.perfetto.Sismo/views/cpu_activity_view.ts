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
import type {Trace} from '../../../public/trace';
import {Section} from '../../../widgets/section';
import {EmptyState} from '../../../widgets/empty_state';
import {Icon} from '../../../widgets/icon';
import {Tooltip} from '../../../widgets/tooltip';
import {
  loadActivityBoard,
  type ActivityBoard,
  type ActivityBucket,
} from '../cpu_data';
import {revealInTimeline} from '../page_common';
import {
  fmtDuration,
  fmtDurationNs,
  fmtMegacycles,
  fmtPercent,
} from '../format';
import type {PrivilegedSet} from '../privileged_set';

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

  constructor({attrs}: m.CVnode<CpuActivityViewAttrs>) {
    this.load(attrs.trace, attrs.priv);
  }

  view({attrs}: m.CVnode<CpuActivityViewAttrs>): m.Children {
    const hasPriv = attrs.priv.upids.length > 0;
    const subtitle =
      'Each column is an equal slice of the trace. The lanes share one time ' +
      'axis, so you can line churn up against concurrency and load. Click any ' +
      'column to open that slice in the timeline.';
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
        board.buckets.map((b) =>
          m(
            '.pf-sismo-board__bucket',
            {
              title:
                `t+${fmtDuration(trace, b.startTs - originTs)} — ` +
                lane.text(b),
              onclick: () =>
                revealInTimeline(trace, {
                  timeRange: {start: b.startTs, end: b.endTs},
                }),
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
    try {
      this.board = await loadActivityBoard(trace.engine, priv);
    } catch {
      this.board = {hasData: false, numCpus: 0, bucketWidthNs: 0n, buckets: []};
    }
  }
}

function clamp01(n: number): number {
  if (!isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}
