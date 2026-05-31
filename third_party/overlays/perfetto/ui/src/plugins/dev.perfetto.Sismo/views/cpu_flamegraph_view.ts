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
import type {Trace} from '../../../public/trace';
import {EmptyState} from '../../../widgets/empty_state';
import {FlamegraphPanel} from '../../../components/flamegraph_panel';
import {Flamegraph, type FlamegraphState} from '../../../widgets/flamegraph';
import {buildSampleFlamegraphMetrics} from '../stack_timeline';
import type {PrivilegedSet} from '../privileged_set';

export interface CpuFlamegraphViewAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
  readonly hasSamples: boolean;
}

export class CpuFlamegraphView
  implements m.ClassComponent<CpuFlamegraphViewAttrs>
{
  private readonly flamegraphMetrics;
  private flamegraphState: FlamegraphState;

  constructor({attrs}: m.CVnode<CpuFlamegraphViewAttrs>) {
    // Scope the flamegraph to the profiled processes when we know them, so the
    // call tree shows your code rather than the whole system. Mirrors the scope
    // clause the timeline detail pane uses.
    const scope =
      attrs.priv.upids.length > 0
        ? [
            `p.utid in (SELECT utid FROM thread WHERE upid IN ` +
              `(${attrs.priv.upids.join(',')}))`,
          ]
        : [];
    this.flamegraphMetrics = buildSampleFlamegraphMetrics(scope);
    this.flamegraphState = Flamegraph.updateState(
      undefined,
      this.flamegraphMetrics,
    );
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
    return m(
      '.pf-sismo-page__flamegraph',
      m(FlamegraphPanel, {
        trace: attrs.trace,
        metrics: this.flamegraphMetrics,
        state: this.flamegraphState,
        onStateChange: (s) => {
          this.flamegraphState = s;
        },
      }),
    );
  }
}
