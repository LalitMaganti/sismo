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

// The CPU landing page: a stack of question-blocks, each stating what the trace
// says about one question the user might be asking. Always populated — every
// block renders regardless of whether anything looks notable; that is how the
// user can trust the tool to show the facts, not just its guesses. Deep-dive
// tabs (built as later vertical slices) answer "show me more" off each block.
//
// Async data is fetched through QuerySlot: each block's loader is scheduled
// declaratively from view(), re-running only when the privileged set changes,
// with races and cancellation handled by the shared task queue.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {QuerySlot, SerialTaskQueue} from '../../../base/query_slot';
import {EmptyState} from '../../../widgets/empty_state';
import type {PrivilegedSet} from '../privileged_set';
import {loadingBlock} from './block';
import {loadTriage, renderTriageBlock, type TriageSummary} from './triage';
import {loadWhereSummary, renderWhereBlock, type WhereSummary} from './where';
import {
  loadParallelSummary,
  renderParallelBlock,
  type ParallelSummary,
} from './parallel';
import {
  loadBurstSummary,
  renderBurstBlock,
  type BurstSummary,
} from './bursts';
import {
  loadEfficiencySummary,
  renderEfficiencyBlock,
  type EfficiencySummary,
} from './efficiency';

interface CpuLandingAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
}

export class CpuLandingPage implements m.ClassComponent<CpuLandingAttrs> {
  // One queue so the slots run serially (safe against shared temp tables).
  private readonly queue = new SerialTaskQueue();
  private readonly triageSlot = new QuerySlot<TriageSummary>(this.queue);
  private readonly whereSlot = new QuerySlot<WhereSummary>(this.queue);
  private readonly parallelSlot = new QuerySlot<ParallelSummary>(this.queue);
  private readonly burstSlot = new QuerySlot<BurstSummary>(this.queue);
  private readonly efficiencySlot = new QuerySlot<EfficiencySummary>(this.queue);

  view({attrs}: m.CVnode<CpuLandingAttrs>): m.Children {
    const {trace, priv} = attrs;
    // Fresh mutable copy so the key is plain JSON (QuerySlot compares by value).
    const key = {upids: [...priv.upids]};
    return m(
      '.pf-sismo-landing',
      m(
        '.pf-sismo-landing__intro',
        m(
          '.pf-sismo-landing__intro-title',
          'What your trace says about CPU usage',
        ),
        m(
          '.pf-sismo-landing__intro-sub',
          'Each question below is answered straight from your trace. Go deeper ' +
            'when an answer makes you want to — the tabs let you investigate.',
        ),
      ),
      this.renderTriage(attrs, key),
      this.block(
        this.whereSlot,
        key,
        () => loadWhereSummary(trace.engine, priv),
        'How much CPU did you use, and where did it go?',
        renderWhereBlock,
      ),
      this.block(
        this.parallelSlot,
        key,
        () => loadParallelSummary(trace.engine, priv),
        'Were your threads running in parallel, or serialized?',
        renderParallelBlock,
      ),
      this.block(
        this.burstSlot,
        key,
        () => loadBurstSummary(trace.engine, priv),
        'Steady work, or lots of small bursts?',
        renderBurstBlock,
      ),
      this.block(
        this.efficiencySlot,
        key,
        () => loadEfficiencySummary(trace.engine, priv),
        'How efficiently did the CPU run?',
        renderEfficiencyBlock,
      ),
    );
  }

  onremove(): void {
    this.triageSlot.dispose();
    this.whereSlot.dispose();
    this.parallelSlot.dispose();
    this.burstSlot.dispose();
    this.efficiencySlot.dispose();
  }

  // Fetch one block's summary through its slot and render it; a failed or
  // in-flight query leaves the question visible with a loading line rather than
  // dropping the block.
  private block<T>(
    slot: QuerySlot<T>,
    key: {upids: number[]},
    queryFn: () => Promise<T>,
    question: string,
    render: (data: T) => m.Children,
  ): m.Children {
    let data: T | undefined;
    try {
      data = slot.use({key, queryFn}).data;
    } catch {
      data = undefined;
    }
    return data !== undefined ? render(data) : loadingBlock(question);
  }

  private renderTriage(
    attrs: CpuLandingAttrs,
    key: {upids: number[]},
  ): m.Children {
    let data: TriageSummary | undefined;
    try {
      data = this.triageSlot.use({
        key,
        queryFn: () => loadTriage(attrs.trace.engine, attrs.priv),
      }).data;
    } catch {
      return m(EmptyState, {
        icon: 'error_outline',
        title: 'Could not read thread states for this trace',
      });
    }
    if (data === undefined) {
      return loadingBlock('Is this even a CPU problem?');
    }
    return renderTriageBlock(attrs.trace, data);
  }
}
