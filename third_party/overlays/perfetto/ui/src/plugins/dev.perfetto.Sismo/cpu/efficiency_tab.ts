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

// "How were cycles spent": not how much CPU was used (that's Where the cycles
// went) but how *productively*. Without PEBS we can't honestly attribute
// counters to a single function, so the honest instrument is the call tree
// weighted by a stall counter — a shape, not a false-precise figure. One tab per
// counter (cache misses / branch misses / backend stalls); the flamegraph's own
// metric picker is hidden, the tabs ARE the picker, each with a line on what
// weighting by it means. Cycle weighting lives on "Where the cycles went", not
// here.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {Callout} from '../../../widgets/callout';
import {EmptyState} from '../../../widgets/empty_state';
import {FlamegraphPanel} from '../../../components/flamegraph_panel';
import {Flamegraph, type FlamegraphState} from '../../../widgets/flamegraph';
import {
  buildSampleFlamegraphMetrics,
  loadPerfCounterNames,
  sampleScopePredicates,
  type BreakdownKind,
} from '../stack_timeline';
import type {PrivilegedSet} from '../privileged_set';
import {Setting, oneOf} from '../settings';
import {segmentedSwitcher, type Segment} from './segmented';

// Each tab weights the same stacks by one stall counter. The metric strings
// match the labels buildSampleFlamegraphMetrics produces.
interface MetricTab {
  readonly key: string;
  readonly label: string;
  readonly icon: string;
  readonly metric: string;
  readonly caption: string;
}

const METRIC_TABS: ReadonlyArray<MetricTab> = [
  {
    key: 'cache',
    label: 'Cache misses',
    icon: 'memory',
    metric: 'Cache misses (approx)',
    caption:
      'Stacks weighted by cache misses — where the code waits on memory ' +
      '(data not in cache). Wider = more misses attributed to that stack.',
  },
  {
    key: 'branch',
    label: 'Branch misses',
    icon: 'call_split',
    metric: 'Branch misses (approx)',
    caption:
      'Stacks weighted by branch mispredictions — where the CPU guessed a ' +
      'branch wrong and had to refill the pipeline.',
  },
  {
    key: 'backend',
    label: 'Backend stalls',
    icon: 'block',
    metric: 'Backend-bound slots (approx)',
    caption:
      'Stacks weighted by backend-bound issue slots — where the core could ' +
      'not retire work, usually memory or execution-port pressure. Needs the ' +
      'Top-Down counters.',
  },
];

const TAB_KEYS = METRIC_TABS.map((t) => t.key) as [string, ...string[]];

// Which weighting was last viewed, carried across traces.
const metricSetting = new Setting<string>(
  'cpu.cyclesSpent.metric',
  'cache',
  oneOf(TAB_KEYS),
);

interface CpuEfficiencyAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
}

export class CpuEfficiencyTab implements m.ClassComponent<CpuEfficiencyAttrs> {
  private active: string = metricSetting.get();
  private readonly scope: string[];
  private fgMetrics;
  private fgState: FlamegraphState;
  // Counter set, kept so a breakdown change can rebuild the metrics in place.
  private fgCounters?: ReadonlySet<string>;
  // Selected "Break down by" dimension; in-memory only (efficiency doesn't share
  // the where-tab's persisted prefs). 'none' so the control still appears.
  private fgBreakdown: BreakdownKind = 'none';

  constructor({attrs}: m.CVnode<CpuEfficiencyAttrs>) {
    this.scope = sampleScopePredicates(attrs.priv);
    this.fgMetrics = buildSampleFlamegraphMetrics(this.scope, this.fgBreakdown);
    this.fgState = Flamegraph.updateState(undefined, this.fgMetrics);

    // Confirming the counter set unlocks the "Backend-bound slots" weighting.
    loadPerfCounterNames(attrs.trace.engine, this.scope)
      .then((counters) => {
        this.fgCounters = counters;
        this.fgMetrics = buildSampleFlamegraphMetrics(
          this.scope,
          this.fgBreakdown,
          counters,
        );
        m.redraw();
      })
      .catch(() => {});
  }

  // The tabs whose metric the trace actually has (backend needs counters).
  private availableTabs(): MetricTab[] {
    const names = new Set(this.fgMetrics.map((mt) => mt.name));
    return METRIC_TABS.filter((t) => names.has(t.metric));
  }

  view({attrs}: m.CVnode<CpuEfficiencyAttrs>): m.Children {
    const tabs = this.availableTabs();
    if (tabs.length === 0) {
      return m(
        '.pf-sismo-tab',
        m(EmptyState, {
          icon: 'memory',
          title: 'No CPU performance counters in this trace',
          description:
            'Weighting by stalls needs hardware counters (cache/branch/…). ' +
            'Record with the counter set enabled to see this.',
        }),
      );
    }
    // Honour the saved tab when its metric exists, else fall back to the first
    // available (e.g. backend selected on a trace without the Top-Down counters).
    const active = tabs.find((t) => t.key === this.active) ?? tabs[0];
    const desired = active.metric;
    if (this.fgState.selectedMetricName !== desired) {
      this.fgState = {...this.fgState, selectedMetricName: desired};
    }

    const segments: Segment<string>[] = tabs.map((t) => ({
      key: t.key,
      label: t.label,
      icon: t.icon,
    }));

    return m(
      '.pf-sismo-tab',
      m(
        '.pf-sismo-tab__modebar',
        segmentedSwitcher<string>(segments, active.key, (k) => {
          this.active = k;
          metricSetting.set(k);
        }),
      ),
      m(Callout, {icon: 'help_outline'}, active.caption),
      m(
        '.pf-sismo-tab__body',
        m(
          '.pf-sismo-tab__flamegraph',
          m(FlamegraphPanel, {
            trace: attrs.trace,
            metrics: this.fgMetrics,
            state: this.fgState,
            hideMetricSelector: true,
            onStateChange: (s: FlamegraphState) => {
              this.fgState = s;
              // The breakdown lives in the widget's Display menu; when it changes
              // rebuild the metrics (new tree shape) so a counter weighting splits
              // per thread/process. A new array re-triggers the query.
              const next = (s.breakdownBy ?? 'none') as BreakdownKind;
              if (next !== this.fgBreakdown) {
                this.fgBreakdown = next;
                this.fgMetrics = buildSampleFlamegraphMetrics(
                  this.scope,
                  next,
                  this.fgCounters,
                );
              }
            },
          }),
        ),
      ),
    );
  }
}
