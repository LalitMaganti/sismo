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

// The "Bottleneck" lens, structured as the question a developer actually walks
// in with — "why is my code slow?" — and answered top-down: vital signs →
// where the pipeline's slots went (Top-Down L1) → which functions are paying.
// L1 is true four-bucket slot accounting when the ARM slot events are present,
// else a coarser cycle-stall split (labelled as such).

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {Section} from '../../../widgets/section';
import {Card} from '../../../widgets/card';
import {Callout} from '../../../widgets/callout';
import {Grid, GridCell, GridHeaderCell} from '../../../widgets/grid';
import {Intent} from '../../../widgets/common';
import {EmptyState} from '../../../widgets/empty_state';
import {
  computeTma,
  loadMicroarchCounters,
  type MicroarchCounters,
  type MicroarchFuncRow,
  type TmaBucket,
  type TmaModel,
} from '../cpu_data';
import {
  renderQuestionBlock,
  renderSeeAllLink,
  renderStatCard,
  type StatCard,
} from '../page_common';
import {fmtIpc, fmtMetric, fmtPercent} from '../format';
import type {PrivilegedSet} from '../privileged_set';

const EMPTY_COUNTERS: MicroarchCounters = {
  state: 'no-counters',
  totalSamples: 0,
  roles: new Map(),
  perFunc: [],
};

async function fetchCounters(
  trace: Trace,
  priv: PrivilegedSet,
): Promise<MicroarchCounters> {
  try {
    return await loadMicroarchCounters(trace.engine, priv);
  } catch {
    return EMPTY_COUNTERS;
  }
}

interface CpuBottleneckViewAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
}

const TITLE = 'Bottleneck';
const SUBTITLE =
  'Why your code is slow, top-down: how productive the cycles were, where the ' +
  'CPU pipeline’s slots went, and which functions are paying for it.';

// Stacked Top-Down bar + swatch legend. Segment colour is keyed off the bucket
// so Retiring reads green, Bad-Spec red, Frontend amber, Backend blue. Shared
// with the Overview's bottleneck block.
function renderTmaBar(buckets: ReadonlyArray<TmaBucket>): m.Children {
  return m(
    '.pf-sismo-tma',
    m(
      '.pf-sismo-tma__bar',
      buckets.map((b) =>
        m(`.pf-sismo-tma__fill.pf-sismo-tma__fill--${b.key}`, {
          style: {width: `${clamp01(b.frac) * 100}%`},
          title: `${b.label} ${fmtPercent(b.frac)}`,
        }),
      ),
    ),
    m(
      '.pf-sismo-tma__legend',
      buckets.map((b) =>
        m(
          '.pf-sismo-tma__legend-item',
          m(`.pf-sismo-tma__swatch.pf-sismo-tma__fill--${b.key}`),
          `${b.label} ${fmtPercent(b.frac)}`,
        ),
      ),
    ),
  );
}

// One-line plain-English read of the dominant bucket — the "why."
function bottleneckVerdict(dominant: TmaBucket): string {
  switch (dominant.key) {
    case 'retiring':
    case 'not-stalled':
      return (
        'Mostly doing useful work — the pipeline wasn’t stalled. To go faster, ' +
        'cut work (fewer instructions / better algorithm), not stalls.'
      );
    case 'bad-spec':
      return (
        'Bad speculation dominates — mispredicted branches and indirect/virtual ' +
        'calls are sending the core down wrong paths and wasting slots.'
      );
    case 'frontend':
      return (
        'Frontend-bound — the core was starved for instructions to run ' +
        '(i-cache misses, fetch/decode), not short of data.'
      );
    case 'backend':
      return (
        'Backend-bound — the core was waiting on the backend: usually memory ' +
        'latency, sometimes execution-unit contention.'
      );
  }
}

export class CpuBottleneckView
  implements m.ClassComponent<CpuBottleneckViewAttrs>
{
  private data?: MicroarchCounters;

  constructor({attrs}: m.CVnode<CpuBottleneckViewAttrs>) {
    this.load(attrs.trace, attrs.priv);
  }

  view(): m.Children {
    const d = this.data;
    if (d === undefined) {
      return m(
        Section,
        {title: TITLE, subtitle: SUBTITLE},
        m(EmptyState, {
          icon: 'hourglass_empty',
          title: 'Loading hardware counters…',
        }),
      );
    }
    if (d.state === 'no-counters') {
      return m(
        Section,
        {title: TITLE, subtitle: SUBTITLE},
        m(
          Callout,
          {icon: 'science', intent: Intent.Primary},
          'No hardware counters in this trace. Re-record with `sismo record` ' +
            'on hardware whose PMU exposes the follower counters (cycles, ' +
            'instructions, and the Top-Down slot/stall events) to answer this.',
        ),
      );
    }
    if (d.state === 'all-zero') {
      return m(
        Section,
        {title: TITLE, subtitle: SUBTITLE},
        m(
          Callout,
          {icon: 'warning', intent: Intent.Warning},
          'Hardware counters were recorded but read zero — the PMU isn’t ' +
            'counting (typical in a VM without a working vPMU). Record on bare ' +
            'metal or with vPMU passthrough.',
        ),
      );
    }

    const model = computeTma(d.roles);
    return m(
      Section,
      {title: TITLE, subtitle: SUBTITLE},
      this.renderVitals(model),
      model !== null && model.buckets.length > 0
        ? this.renderLevel1(model)
        : m(
            Callout,
            {icon: 'info', intent: Intent.None},
            'This trace has IPC / MPKI but no stall or slot events, so the ' +
              'cycles can’t be split into where they went. Re-record with the ' +
              'Top-Down slot events (or stalled-cycles) to unlock the breakdown.',
          ),
      this.renderFunctions(d.perFunc),
    );
  }

  private renderVitals(model: TmaModel | null): m.Children {
    const retiring = retiringFrac(model);
    const cards: StatCard[] = [
      {
        label: 'IPC',
        value: fmtIpc(model?.ipc ?? null),
        help:
          'Instructions per cycle — the single best headline. Higher means ' +
          'more work per cycle; the ceiling is the core’s issue width.',
      },
    ];
    // Plain-English "was the CPU working or waiting?" — the share of pipeline
    // slots that didn't retire an instruction. Replaces the raw cache/branch
    // MPKI counters; the bar below already breaks the stall down by cause.
    if (retiring !== null) {
      cards.push({
        label: 'Cycles stalled',
        value: fmtPercent(1 - retiring),
        help:
          'Share of the pipeline’s issue slots that did NOT retire an ' +
          'instruction — time lost to frontend/backend stalls or bad ' +
          'speculation rather than doing work. The bar below shows where it went.',
      });
    }
    cards.push({
      label: 'Instructions',
      value: fmtMetric(model?.instructions ?? null),
      help: 'Total instructions retired across the in-scope samples.',
    });
    return m('.pf-sismo-page__stat-row', cards.map(renderStatCard));
  }

  // Precondition: model.buckets is non-empty (so dominant is set).
  private renderLevel1(model: TmaModel): m.Children {
    const note =
      model.tier === 'true-l1'
        ? 'Slot accounting: each bucket is a share of all the CPU’s issue slots.'
        : 'Cycle-stall accounting (no slot events on this trace): Retiring and ' +
          'Bad-Speculation are lumped into “Not stalled.” Record the Top-Down ' +
          'slot events for the true four-bucket split.';
    return m(
      '.pf-sismo-page__tab-pane',
      m('.pf-sismo-page__tab-pane-label', 'Where the pipeline’s slots went'),
      renderTmaBar(model.buckets),
      model.dominant !== null &&
        m(
          Callout,
          {icon: 'lightbulb', intent: Intent.None},
          bottleneckVerdict(model.dominant),
        ),
      m('.pf-sismo-page__muted', note),
    );
  }

  private renderFunctions(rows: ReadonlyArray<MicroarchFuncRow>): m.Children {
    if (rows.length === 0) {
      return m(EmptyState, {icon: 'code', title: 'No symbolised samples'});
    }
    const hasStalls = rows.some(
      (r) => r.feStallPct !== null || r.beStallPct !== null,
    );
    const columns = [
      {key: 'fn', header: m(GridHeaderCell, 'Function')},
      {key: 'samples', header: m(GridHeaderCell, 'Samples')},
      {key: 'ipc', header: m(GridHeaderCell, 'IPC')},
    ];
    if (hasStalls) {
      columns.push(
        {key: 'fe', header: m(GridHeaderCell, 'Frontend stall')},
        {key: 'be', header: m(GridHeaderCell, 'Backend stall')},
      );
    }
    const data = rows.map((r) => {
      const cells = [
        m(
          GridCell,
          {wrap: true},
          m('span', r.name),
          r.mappingName !== null &&
            m('span.pf-sismo-page__muted', ` — ${shortMapping(r.mappingName)}`),
        ),
        m(GridCell, {align: 'right'}, `${r.samples}`),
        m(GridCell, {align: 'right'}, fmtIpc(r.ipc)),
      ];
      if (hasStalls) {
        cells.push(
          m(GridCell, {align: 'right'}, fmtPercent(r.feStallPct)),
          m(GridCell, {align: 'right'}, fmtPercent(r.beStallPct)),
        );
      }
      return cells;
    });
    return m(
      '.pf-sismo-page__tab-pane',
      m('.pf-sismo-page__tab-pane-label', 'Which functions are paying'),
      m(
        Card,
        {className: 'pf-sismo-page__table-card'},
        m(Grid, {columns, rowData: data}),
      ),
    );
  }

  private async load(trace: Trace, priv: PrivilegedSet): Promise<void> {
    this.data = await fetchCounters(trace, priv);
  }
}

// Overview question #4 block — the same data as the lens, trimmed to vital
// signs + the L1 bar, with a see-all into the Bottleneck lens. Always renders so
// the question never silently disappears; explains what to record when counters
// are absent.
const OV_QUESTION = 'When your code ran, was the CPU computing or waiting?';
const OV_WHY =
  'Whether the cycles did work or stalled, and on what — the Bottleneck lens ' +
  'drills into where the pipeline’s slots went and which functions pay.';

export class CpuBottleneckOverview
  implements m.ClassComponent<CpuBottleneckViewAttrs>
{
  private data?: MicroarchCounters;

  constructor({attrs}: m.CVnode<CpuBottleneckViewAttrs>) {
    fetchCounters(attrs.trace, attrs.priv).then((d) => {
      this.data = d;
      m.redraw();
    });
  }

  view({attrs}: m.CVnode<CpuBottleneckViewAttrs>): m.Children {
    const footer = renderSeeAllLink(attrs.trace, 'Drill into the bottleneck', 'bottleneck');
    const d = this.data;
    if (d === undefined) {
      return renderQuestionBlock(
        {question: OV_QUESTION, why: OV_WHY},
        m(EmptyState, {icon: 'hourglass_empty', title: 'Loading counters…'}),
      );
    }
    if (d.state !== 'ok') {
      const msg =
        d.state === 'all-zero'
          ? 'Hardware counters read zero (no working PMU — typical in a VM).'
          : 'No hardware counters in this trace. Re-record on a host whose PMU ' +
            'exposes them to see the computing-vs-stalling breakdown.';
      return renderQuestionBlock(
        {question: OV_QUESTION, why: OV_WHY, footer},
        m(Callout, {icon: 'science', intent: Intent.None}, msg),
      );
    }
    const model = computeTma(d.roles);
    const retiring = retiringFrac(model);
    const vitals: StatCard[] = [
      {label: 'IPC', value: fmtIpc(model?.ipc ?? null), help: 'Instructions per cycle.'},
    ];
    if (retiring !== null) {
      vitals.push({
        label: 'Cycles stalled',
        value: fmtPercent(1 - retiring),
        help:
          'Share of pipeline slots that didn’t retire an instruction — the bar ' +
          'below shows whether that was frontend, backend or bad speculation.',
      });
    }
    return renderQuestionBlock(
      {question: OV_QUESTION, why: OV_WHY, footer},
      m('.pf-sismo-page__stat-row', vitals.map(renderStatCard)),
      model !== null &&
        model.buckets.length > 0 &&
        m(
          '.pf-sismo-page__tab-pane',
          m('.pf-sismo-page__tab-pane-label', 'Where the pipeline’s slots went'),
          renderTmaBar(model.buckets),
        ),
    );
  }
}

// Share of pipeline slots (true-L1) or cycles (coarse tier) that retired useful
// work — `1 - this` is the "Cycles stalled" vital. Null when there's no L1
// model to read it from (vitals fall back to IPC + Instructions only).
function retiringFrac(model: TmaModel | null): number | null {
  if (model === null) return null;
  const b = model.buckets.find(
    (x) => x.key === 'retiring' || x.key === 'not-stalled',
  );
  return b !== undefined ? b.frac : null;
}

function clamp01(n: number): number {
  if (!isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

function shortMapping(path: string): string {
  const slash = path.lastIndexOf('/');
  return slash >= 0 ? path.slice(slash + 1) : path;
}
