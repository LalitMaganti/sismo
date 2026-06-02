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

// "How cycles were scheduled": the two questions are "how parallel was my work,
// really" and "did it land on the right cores". Two pieces, both lifted from the
// old IA (which read far better than a raw heatmap):
//   - Over time: lanes on a shared time axis (machine load, your concurrency,
//     cycles, churn); brush a window to see who was busy and jump to it on the
//     timeline.
//   - By core: per-core utilisation, your-vs-system split, sparkline, contention
//     and migrations, grouped by cluster; each core links to its timeline track.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {QuerySlot, SerialTaskQueue} from '../../../base/query_slot';
import {EmptyState} from '../../../widgets/empty_state';
import {Spinner} from '../../../widgets/spinner';
import {
  loadCpuSummary,
  loadPerCore,
  type CpuCoreRow,
  type CpuSummary,
} from '../cpu_data';
import type {PrivilegedSet} from '../privileged_set';
import {Setting, oneOf} from '../settings';
import {CpuActivityView} from '../views/cpu_activity_view';
import {CpuCoresView} from '../views/cpu_cores_view';
import {segmentedSwitcher, type Segment} from './segmented';

const PIECES = ['overtime', 'cores'] as const;
type Piece = (typeof PIECES)[number];

const pieceSetting = new Setting<Piece>(
  'cpu.scheduled.piece',
  'overtime',
  oneOf(PIECES),
);

const SEGMENTS: ReadonlyArray<Segment<Piece>> = [
  {key: 'overtime', label: 'Over time', icon: 'timeline'},
  {key: 'cores', label: 'By core', icon: 'developer_board'},
];

interface CpuScheduledAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
}

interface CoresData {
  readonly summary: CpuSummary;
  readonly perCore: CpuCoreRow[];
}

export class CpuScheduledTab implements m.ClassComponent<CpuScheduledAttrs> {
  private piece: Piece = pieceSetting.get();
  private readonly queue = new SerialTaskQueue();
  private readonly coresSlot = new QuerySlot<CoresData>(this.queue);

  onremove(): void {
    this.coresSlot.dispose();
  }

  view({attrs}: m.CVnode<CpuScheduledAttrs>): m.Children {
    return m(
      '.pf-sismo-tab',
      m(
        '.pf-sismo-tab__modebar',
        segmentedSwitcher<Piece>(SEGMENTS, this.piece, (p) => {
          this.piece = p;
          pieceSetting.set(p);
        }),
      ),
      m('.pf-sismo-tab__body', this.renderPiece(attrs)),
    );
  }

  private renderPiece(attrs: CpuScheduledAttrs): m.Children {
    if (this.piece === 'overtime') {
      return m(CpuActivityView, {trace: attrs.trace, priv: attrs.priv});
    }
    return this.renderCores(attrs);
  }

  private renderCores(attrs: CpuScheduledAttrs): m.Children {
    let data: CoresData | undefined;
    try {
      data = this.coresSlot.use({
        key: {upids: [...attrs.priv.upids]},
        queryFn: async () => ({
          summary: await loadCpuSummary(attrs.trace.engine, attrs.priv),
          perCore: await loadPerCore(attrs.trace.engine, attrs.priv),
        }),
      }).data;
    } catch {
      return m(EmptyState, {
        icon: 'error_outline',
        title: 'Could not read per-core scheduling for this trace',
      });
    }
    if (data === undefined) {
      return m(
        EmptyState,
        {icon: 'hourglass_empty', title: 'Reading per-core scheduling…'},
        m(Spinner, {easing: true}),
      );
    }
    return m(CpuCoresView, {
      trace: attrs.trace,
      summary: data.summary,
      perCore: data.perCore,
      priv: attrs.priv,
    });
  }
}
