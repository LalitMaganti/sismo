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

// CPU "Flamegraph" tab: the privileged-scoped call tree built from CPU samples
// — the "where did my code's time go" centerpiece. Same flamegraph metrics the
// timeline detail pane uses, promoted here to a first-class page tab.

import m from 'mithril';
import type {Trace} from '../../../../public/trace';
import {EmptyState} from '../../../../widgets/empty_state';
import {Section} from '../../../../widgets/section';
import {FlamegraphPanel} from '../../../../components/flamegraph_panel';
import {Flamegraph, type FlamegraphState} from '../../../../widgets/flamegraph';
import {
  buildSampleFlamegraphMetrics,
  loadPerfCounterNames,
  type BreakdownKind,
} from '../../stack_timeline';
import {loadMicroarch, type FocusWindow, type MicroarchData} from '../../cpu_data';
import {renderCpuFunctions} from './cpu_functions_view';
import type {PrivilegedSet} from '../../privileged_set';

interface CpuFlamegraphViewAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
  readonly hasSamples: boolean;
  // The shared focus window; scopes both the flamegraph and the flat breakdown.
  readonly focus?: FocusWindow;
}

export class CpuFlamegraphView
  implements m.ClassComponent<CpuFlamegraphViewAttrs>
{
  private readonly scope: ReadonlyArray<string>;
  private breakdownBy: BreakdownKind = 'none';
  private flamegraphMetrics;
  private flamegraphState: FlamegraphState;
  // Counter track names present in this trace; undefined until the async probe
  // below resolves. Drives which counter-weighted views are offered.
  private availableCounters?: ReadonlySet<string>;
  // The flat hot-symbol / hot-library breakdown, scoped to the same window.
  private microarch?: MicroarchData;

  constructor({attrs}: m.CVnode<CpuFlamegraphViewAttrs>) {
    // Scope the flamegraph to the profiled processes when we know them, and to
    // the focus window when one is set, so the call tree shows your code in the
    // region of interest. `p` is the perf_sample alias inside the metric.
    const clauses: string[] = [];
    if (attrs.priv.upids.length > 0) {
      clauses.push(
        `p.utid in (SELECT utid FROM thread WHERE upid IN ` +
          `(${attrs.priv.upids.join(',')}))`,
      );
    }
    if (attrs.focus !== undefined) {
      clauses.push(`p.ts >= ${attrs.focus.start} AND p.ts < ${attrs.focus.end}`);
    }
    this.scope = clauses;
    // Pass an explicit breakdown (starting 'none') so the widget shows the
    // "Break down by" control; switching it rebuilds the metric below.
    this.flamegraphMetrics = buildSampleFlamegraphMetrics(
      this.scope,
      this.breakdownBy,
    );
    this.flamegraphState = Flamegraph.updateState(
      undefined,
      this.flamegraphMetrics,
    );
    // Discover which perf counters this trace carries, then enrich the metric
    // set with the counter-weighted views the data actually supports (adds the
    // backend-bound view when the Top-Down counters are present).
    loadPerfCounterNames(attrs.trace.engine, this.scope).then((counters) => {
      this.availableCounters = counters;
      this.flamegraphMetrics = buildSampleFlamegraphMetrics(
        this.scope,
        this.breakdownBy,
        counters,
      );
      m.redraw();
    });
    loadMicroarch(attrs.trace.engine, attrs.priv, attrs.focus)
      .then((d) => {
        this.microarch = d;
        m.redraw();
      })
      .catch(() => {});
  }

  view({attrs}: m.CVnode<CpuFlamegraphViewAttrs>): m.Children {
    if (!attrs.hasSamples) {
      return m(EmptyState, {
        icon: 'science',
        title: 'No CPU samples in this trace',
        description:
          'Re-record with `sismo record` to capture stack samples; ' +
          'they’re what the flamegraph is built from.',
      });
    }
    return [
      m(
        Section,
        {
          title: 'Flamegraph',
          subtitle:
            'Your code as a sampled flamegraph — click to zoom into a ' +
            'subtree. The flat breakdown is below; the expandable tree is on ' +
            'the Calltree tab.',
        },
        m(
          '.pf-sismo-page__flamegraph',
          m(FlamegraphPanel, {
            trace: attrs.trace,
            metrics: this.flamegraphMetrics,
            state: this.flamegraphState,
            onStateChange: (s) => {
              this.flamegraphState = s;
              // The widget owns the "Break down by" control; when its selection
              // changes we rebuild the metric (new tree shape) and keep the
              // rest of the state. A new metrics array re-triggers the query.
              const next = (s.breakdownBy ?? 'none') as BreakdownKind;
              if (next !== this.breakdownBy) {
                this.breakdownBy = next;
                this.flamegraphMetrics = buildSampleFlamegraphMetrics(
                  this.scope,
                  next,
                  this.availableCounters,
                );
              }
            },
          }),
        ),
      ),
      this.microarch !== undefined && renderCpuFunctions(this.microarch),
    ];
  }
}
