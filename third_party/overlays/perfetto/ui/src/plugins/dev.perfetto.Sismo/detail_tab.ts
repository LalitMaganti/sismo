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

// Instruments-style whole-trace detail pane: a persistent tab with a jump-bar
// (Tabs) that switches between several analyses of the entire trace, all
// independent of any timeline selection. Mirrors the way Instruments' bottom
// pane offers Call Tree / Sample List / etc. for the focused instrument.

import m from 'mithril';
import type {Trace} from '../../public/trace';
import {Select} from '../../widgets/select';
import {Card} from '../../widgets/card';
import {Grid, GridCell, GridHeaderCell} from '../../widgets/grid';
import {EmptyState} from '../../widgets/empty_state';
import {Callout} from '../../widgets/callout';
import {Intent} from '../../widgets/common';
import {Anchor} from '../../widgets/anchor';
import {FlamegraphPanel} from '../../components/flamegraph_panel';
import {Flamegraph, type FlamegraphState} from '../../widgets/flamegraph';
import {getThreadOrProcUri} from '../../public/utils';
import {NUM} from '../../trace_processor/query_result';
import {buildSampleFlamegraphMetrics} from './stack_timeline';
import {
  loadCoreActivity,
  loadHeaviestFunctions,
  loadSampleList,
  loadThreadStates,
  type CoreActivityRow,
  type HeaviestFunctionRow,
  type SampleListRow,
  type ThreadStateRow,
} from './cpu_data';
import {clamp01, fmtCount, fmtDuration, fmtPercent} from './format';
import {loadingBody} from './page_common';
import type {PrivilegedSet} from './privileged_set';

type ViewKey =
  | 'call_tree'
  | 'heaviest'
  | 'sample_list'
  | 'thread_states'
  | 'core_activity'
  | 'ipc';

const RUN_COLOR = '#3478f6';
const RUNNABLE_COLOR = '#f5a623';
const BLOCKED_COLOR = '#9aa0a6';
const SLEEP_COLOR = '#d0d4d9';

interface DetailTabAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
  readonly hasSamples: boolean;
  readonly hasSched: boolean;
}

// One lazily-loaded cache slot per data-backed view.
class Cache<T> {
  data?: T;
  error?: string;
  private started = false;
  async ensure(load: () => Promise<T>): Promise<void> {
    if (this.started) return;
    this.started = true;
    try {
      this.data = await load();
    } catch (e) {
      this.error = e instanceof Error ? e.message : 'Failed to load';
    }
    m.redraw();
  }
}

class SismoDetailTab implements m.ClassComponent<DetailTabAttrs> {
  private active: ViewKey;
  private flamegraphState: FlamegraphState;
  private readonly flamegraphMetrics;
  private readonly heaviest = new Cache<HeaviestFunctionRow[]>();
  private readonly samples = new Cache<SampleListRow[]>();
  private readonly threadStates = new Cache<ThreadStateRow[]>();
  private readonly cores = new Cache<CoreActivityRow[]>();

  constructor({attrs}: m.CVnode<DetailTabAttrs>) {
    const scope =
      attrs.priv.upids.length > 0
        ? [
            `p.utid in (SELECT utid FROM thread WHERE upid IN (${attrs.priv.upids.join(',')}))`,
          ]
        : [];
    this.flamegraphMetrics = buildSampleFlamegraphMetrics(scope);
    this.flamegraphState = Flamegraph.updateState(
      undefined,
      this.flamegraphMetrics,
    );
    this.active = attrs.hasSamples ? 'call_tree' : 'thread_states';
  }

  view({attrs}: m.CVnode<DetailTabAttrs>): m.Children {
    // Grouped dropdown jump-bar, mirroring Instruments' detail-pane selector
    // (System Trace / Profiler sections). Only groups with data are shown.
    const groups: Array<{label: string; opts: Array<[ViewKey, string]>}> = [];
    if (attrs.hasSamples) {
      groups.push({
        label: 'CPU Profiler',
        opts: [
          ['call_tree', 'Profile (call tree)'],
          ['heaviest', 'Heaviest functions'],
          ['sample_list', 'Samples'],
        ],
      });
    }
    if (attrs.hasSched) {
      groups.push({
        label: 'Scheduling',
        opts: [
          ['thread_states', 'Summary: thread states'],
          ['core_activity', 'Core activity'],
        ],
      });
    }
    groups.push({label: 'Counters', opts: [['ipc', 'IPC & stalls']]});

    const selector = m(
      Select,
      {
        value: this.active,
        onchange: (e: Event) => {
          this.active = (e.target as HTMLSelectElement).value as ViewKey;
        },
      },
      groups.map((g) =>
        m(
          'optgroup',
          {label: g.label},
          g.opts.map(([key, label]) => m('option', {value: key}, label)),
        ),
      ),
    );

    return m(
      '.pf-sismo-detail',
      m(
        '.pf-sismo-detail__toolbar',
        m('span.pf-sismo-detail__toolbar-label', 'View:'),
        selector,
      ),
      m('.pf-sismo-detail__view', this.activeContent(attrs)),
    );
  }

  // Build content only for the active view so inactive views don't run queries.
  private activeContent(attrs: DetailTabAttrs): m.Children {
    switch (this.active) {
      case 'call_tree':
        return this.renderCallTree(attrs.trace);
      case 'heaviest':
        return this.renderHeaviest(attrs);
      case 'sample_list':
        return this.renderSampleList(attrs);
      case 'thread_states':
        return this.renderThreadStates(attrs);
      case 'core_activity':
        return this.renderCoreActivity(attrs);
      case 'ipc':
        return renderIpcStub();
    }
  }

  private renderCallTree(trace: Trace): m.Children {
    return m(FlamegraphPanel, {
      trace,
      metrics: this.flamegraphMetrics,
      state: this.flamegraphState,
      onStateChange: (s) => {
        this.flamegraphState = s;
      },
    });
  }

  private renderHeaviest(attrs: DetailTabAttrs): m.Children {
    this.heaviest.ensure(() =>
      loadHeaviestFunctions(attrs.trace.engine, attrs.priv),
    );
    const c = this.heaviest;
    if (c.error !== undefined) return errorCallout(c.error);
    if (c.data === undefined) return loading();
    if (c.data.length === 0) {
      return m(EmptyState, {icon: 'code', title: 'No symbolised samples'});
    }
    const rows = c.data.map((r) => [
      m(GridCell, {wrap: true}, r.name),
      m(GridCell, {align: 'right'}, fmtCount(r.samples)),
      m(GridCell, {align: 'right'}, fmtPercent(r.share)),
      m(GridCell, proportionBar(r.share, RUN_COLOR)),
    ]);
    return m(
      Card,
      {className: 'pf-sismo-detail__card'},
      m(Grid, {
        columns: [
          {key: 'fn', header: m(GridHeaderCell, 'Function (self)')},
          {key: 'samples', header: m(GridHeaderCell, 'Samples')},
          {key: 'pct', header: m(GridHeaderCell, '% of samples')},
          {key: 'bar', header: m(GridHeaderCell, '')},
        ],
        rowData: rows,
      }),
    );
  }

  private renderSampleList(attrs: DetailTabAttrs): m.Children {
    this.samples.ensure(() => loadSampleList(attrs.trace.engine, attrs.priv));
    const c = this.samples;
    if (c.error !== undefined) return errorCallout(c.error);
    if (c.data === undefined) return loading();
    if (c.data.length === 0) {
      return m(EmptyState, {icon: 'list', title: 'No samples'});
    }
    const start = attrs.trace.traceInfo.start;
    const rows = c.data.map((r) => [
      m(
        GridCell,
        {align: 'right'},
        fmtDuration(attrs.trace, r.ts - start),
      ),
      m(
        GridCell,
        {wrap: true},
        m(
          Anchor,
          {
            onclick: () => goToThread(attrs.trace, r.utid),
          },
          r.threadName,
          r.tid !== null &&
            m('span.pf-sismo-page__muted', ` (tid ${r.tid})`),
        ),
      ),
      m(GridCell, {wrap: true}, r.leaf),
    ]);
    return [
      c.data.length >= 500 &&
        m(
          Callout,
          {icon: 'info', intent: Intent.None},
          'Showing the first 500 samples in time order.',
        ),
      m(
        Card,
        {className: 'pf-sismo-detail__card'},
        m(Grid, {
          columns: [
            {key: 'ts', header: m(GridHeaderCell, 'Time')},
            {key: 'thread', header: m(GridHeaderCell, 'Thread')},
            {key: 'leaf', header: m(GridHeaderCell, 'Running symbol')},
          ],
          rowData: rows,
        }),
      ),
    ];
  }

  private renderThreadStates(attrs: DetailTabAttrs): m.Children {
    this.threadStates.ensure(() =>
      loadThreadStates(attrs.trace.engine, attrs.priv),
    );
    const c = this.threadStates;
    if (c.error !== undefined) return errorCallout(c.error);
    if (c.data === undefined) return loading();
    if (c.data.length === 0) {
      return m(EmptyState, {icon: 'schedule', title: 'No scheduling data'});
    }
    const trace = attrs.trace;
    const rows = c.data.map((r) => {
      const total =
        Number(r.runningNs) +
        Number(r.runnableNs) +
        Number(r.uninterruptibleNs) +
        Number(r.sleepingNs) +
        Number(r.otherNs);
      return [
        m(
          GridCell,
          {wrap: true},
          m(
            Anchor,
            {onclick: () => goToThread(trace, r.utid)},
            r.threadName,
            r.tid !== null && m('span.pf-sismo-page__muted', ` (tid ${r.tid})`),
          ),
        ),
        m(GridCell, {align: 'right'}, fmtDuration(trace, r.runningNs)),
        m(GridCell, {align: 'right'}, fmtDuration(trace, r.runnableNs)),
        m(
          GridCell,
          {align: 'right'},
          fmtDuration(trace, r.uninterruptibleNs + r.sleepingNs),
        ),
        m(GridCell, {align: 'right'}, fmtCount(r.numRunSlices)),
        m(GridCell, stateBar(r, total)),
      ];
    });
    return [
      stateLegend(),
      m(
        Card,
        {className: 'pf-sismo-detail__card'},
        m(Grid, {
          columns: [
            {key: 'thread', header: m(GridHeaderCell, 'Thread')},
            {key: 'run', header: m(GridHeaderCell, 'Running')},
            {key: 'runnable', header: m(GridHeaderCell, 'Runnable')},
            {key: 'blocked', header: m(GridHeaderCell, 'Blocked')},
            {key: 'switches', header: m(GridHeaderCell, 'On-CPU intervals')},
            {key: 'bar', header: m(GridHeaderCell, '')},
          ],
          rowData: rows,
        }),
      ),
    ];
  }

  private renderCoreActivity(attrs: DetailTabAttrs): m.Children {
    this.cores.ensure(() => loadCoreActivity(attrs.trace.engine, attrs.priv));
    const c = this.cores;
    if (c.error !== undefined) return errorCallout(c.error);
    if (c.data === undefined) return loading();
    if (c.data.length === 0) {
      return m(EmptyState, {icon: 'memory', title: 'No scheduling data'});
    }
    const busiest = c.data.reduce(
      (mx, r) => Math.max(mx, Number(r.busyNs)),
      0,
    );
    const trace = attrs.trace;
    const rows = c.data.map((r) => [
      m(GridCell, `CPU ${r.cpu}`),
      m(GridCell, {align: 'right'}, fmtDuration(trace, r.busyNs)),
      m(GridCell, {align: 'right'}, fmtCount(r.threads)),
      m(
        GridCell,
        proportionBar(busiest > 0 ? Number(r.busyNs) / busiest : 0, RUN_COLOR),
      ),
    ]);
    return m(
      Card,
      {className: 'pf-sismo-detail__card'},
      m(Grid, {
        columns: [
          {key: 'cpu', header: m(GridHeaderCell, 'Core')},
          {key: 'busy', header: m(GridHeaderCell, 'Busy time')},
          {key: 'threads', header: m(GridHeaderCell, 'Distinct threads')},
          {key: 'bar', header: m(GridHeaderCell, '')},
        ],
        rowData: rows,
      }),
    );
  }
}

function goToThread(trace: Trace, utid: number): void {
  trace.navigate('#!/viewer');
  const uri = getThreadOrProcUri(null, utid);
  if (uri !== undefined) trace.scrollTo({track: {uri, expandGroup: true}});
}

function proportionBar(frac: number, color: string): m.Children {
  const pct = clamp01(frac) * 100;
  return m(
    '.pf-sismo-detail__bar',
    m('.pf-sismo-detail__bar-fill', {
      style: {width: `${pct}%`, background: color},
    }),
  );
}

function stateBar(r: ThreadStateRow, total: number): m.Children {
  if (total <= 0) return m('.pf-sismo-detail__bar');
  const seg = (ns: bigint, color: string) =>
    m('.pf-sismo-detail__bar-fill', {
      style: {width: `${(Number(ns) / total) * 100}%`, background: color},
    });
  return m(
    '.pf-sismo-detail__bar',
    seg(r.runningNs, RUN_COLOR),
    seg(r.runnableNs, RUNNABLE_COLOR),
    seg(r.uninterruptibleNs, BLOCKED_COLOR),
    seg(r.sleepingNs, SLEEP_COLOR),
  );
}

function stateLegend(): m.Children {
  const item = (color: string, label: string) =>
    m(
      '.pf-sismo-detail__legend-item',
      m('span.pf-sismo-page__swatch', {style: {background: color}}),
      label,
    );
  return m(
    '.pf-sismo-detail__legend',
    item(RUN_COLOR, 'Running'),
    item(RUNNABLE_COLOR, 'Runnable (waiting for CPU)'),
    item(BLOCKED_COLOR, 'Uninterruptible (D)'),
    item(SLEEP_COLOR, 'Sleeping (S)'),
  );
}

function renderIpcStub(): m.Children {
  return m(
    Callout,
    {icon: 'science', intent: Intent.Primary},
    m('strong', 'IPC & stall analysis needs hardware counters.'),
    m(
      'p',
      "This trace was recorded with only the sampling timebase. To break " +
        'down instructions-per-cycle and frontend/backend stalls per function, ' +
        're-record with PMU follower counters enabled (instructions, ' +
        'stalled-cycles-frontend/backend, cache-misses). Once captured, each ' +
        'sample carries the full counter vector and this view attributes IPC ' +
        'and stall causes down the call tree.',
    ),
  );
}

function loading(): m.Children {
  return loadingBody('Loading…');
}

function errorCallout(msg: string): m.Children {
  return m(Callout, {icon: 'error', intent: Intent.Danger}, msg);
}

// Registers the persistent whole-trace detail tab and opens it by default.
// No-op when the trace has neither CPU samples nor scheduling data.
export async function registerSismoDetailTab(
  trace: Trace,
  priv: PrivilegedSet,
): Promise<void> {
  const counts = await trace.engine.query(`
    SELECT
      (SELECT count() FROM perf_sample WHERE callsite_id IS NOT NULL) AS samples,
      (SELECT count() FROM sched LIMIT 1) AS sched
  `);
  const row = counts.firstRow({samples: NUM, sched: NUM});
  const hasSamples = row.samples > 0;
  const hasSched = row.sched > 0;
  if (!hasSamples && !hasSched) return;

  const uri = 'dev.perfetto.Sismo#detail_tab';
  trace.tabs.registerTab({
    uri,
    isEphemeral: false,
    // Pinned for the trace's lifetime — it's the primary Sismo detail surface,
    // so don't let it be accidentally closed. Needs the closable field added by
    // third_party/patches/perfetto/0005-nopr-tab-closable.patch.
    closable: false,
    content: {
      getTitle: () => 'Profile (full trace)',
      render: () => m(SismoDetailTab, {trace, priv, hasSamples, hasSched}),
    },
  });
  trace.tabs.addDefaultTab(uri);
}
