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

// The Latency landing page: a fixed, ordered stack of question-blocks an app
// developer reads top-down to understand a waiting problem —
//   L1  Is it busy, or waiting?        (the router)
//   L2  What was it waiting for?        (kind of wait)
//   L3  Who was making you wait?        (privileged-vs-context blame)
//   L4  A few long stalls, or churn?    (concentration)
// Every block is always rendered. L1/L2 share one thread-state query; each of
// L3/L4 has its own. Deep-dive tabs answer "show me more" off each block.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {QuerySlot, SerialTaskQueue} from '../../../base/query_slot';
import {EmptyState} from '../../../widgets/empty_state';
import type {PrivilegedSet} from '../privileged_set';
import {loadingBlock} from '../cpu/block';
import {
  loadCpuTriage,
  loadHeaviestFunctions,
  loadRunnableSummary,
  loadWaitBreakdown,
  type CpuTriage,
  type HeaviestFunctionRow,
  type RunnableSummary,
  type WaitBreakdown,
} from '../cpu_data';
import {
  renderLatencyTriageBlock,
  renderWaitKindBlock,
} from './thread_time';
import {renderWaitTypeBlock} from './wait_types';
import {renderBlameBlock} from './blame';
import {loadChurn, renderChurnBlock, type ChurnSummary} from './churn';

interface LatencyLandingAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
  // Switch to a fixed deep-dive tab ('where' | 'who').
  readonly onNavigate: (tab: string) => void;
}

export class LatencyLandingPage
  implements m.ClassComponent<LatencyLandingAttrs>
{
  private readonly queue = new SerialTaskQueue();
  private readonly triageSlot = new QuerySlot<CpuTriage>(this.queue);
  private readonly fnSlot = new QuerySlot<HeaviestFunctionRow[]>(this.queue);
  private readonly waitSlot = new QuerySlot<WaitBreakdown>(this.queue);
  private readonly detailSlot = new QuerySlot<RunnableSummary>(this.queue);
  private readonly churnSlot = new QuerySlot<ChurnSummary>(this.queue);

  view({attrs}: m.CVnode<LatencyLandingAttrs>): m.Children {
    const {trace, priv, onNavigate} = attrs;
    const key = {upids: [...priv.upids]};
    const scope = priv.upids.length > 0 ? 'your threads' : 'all threads';

    return m(
      '.pf-sismo-landing',
      m(
        '.pf-sismo-landing__intro',
        m(
          '.pf-sismo-landing__intro-title',
          'What your trace says about waiting',
        ),
        m(
          '.pf-sismo-landing__intro-sub',
          'When an app is slow, the wall-clock either went to work (on the CPU) ' +
            'or to waiting (off it). Each question below is answered straight ' +
            'from your trace.',
        ),
      ),
      this.threadTimeBlocks(trace, priv, key, scope, onNavigate),
      this.block(
        this.waitSlot,
        key,
        () => loadWaitBreakdown(trace.engine, priv),
        'What kind of wait was it?',
        (d) => renderWaitTypeBlock(d, onNavigate),
      ),
      this.block(
        this.detailSlot,
        key,
        () => loadRunnableSummary(trace.engine, priv),
        'Who or what was making you wait?',
        (d) => renderBlameBlock(d, onNavigate),
      ),
      this.block(
        this.churnSlot,
        key,
        () => loadChurn(trace.engine, priv),
        'A few long stalls, or constant churn?',
        (d) => renderChurnBlock(d),
      ),
    );
  }

  onremove(): void {
    this.triageSlot.dispose();
    this.fnSlot.dispose();
    this.waitSlot.dispose();
    this.detailSlot.dispose();
    this.churnSlot.dispose();
  }

  // L1 + L2 both read the one triage summary, so they share a slot: load once,
  // render both (or both as loading blocks while it's in flight).
  private threadTimeBlocks(
    trace: Trace,
    priv: PrivilegedSet,
    key: {upids: number[]},
    scope: string,
    onNavigate: (tab: string) => void,
  ): m.Children {
    let data: CpuTriage | undefined;
    try {
      data = this.triageSlot.use({
        key,
        queryFn: () => loadCpuTriage(trace.engine, priv),
      }).data;
    } catch {
      return m(EmptyState, {
        icon: 'error_outline',
        title: 'Could not read thread states for this trace',
      });
    }
    if (data === undefined) {
      return [
        loadingBlock('Is it slow because it’s busy, or because it’s waiting?'),
        loadingBlock('What was it waiting for?'),
      ];
    }
    // The busiest on-CPU function, if it's already loaded — the block renders
    // fine without it and picks it up on the next redraw.
    let topFn: {name: string; share: number} | undefined;
    try {
      const fns = this.fnSlot.use({
        key,
        queryFn: () => loadHeaviestFunctions(trace.engine, priv, 1),
      }).data;
      if (fns !== undefined && fns.length > 0) {
        topFn = {name: fns[0].name, share: fns[0].share};
      }
    } catch {
      topFn = undefined;
    }
    return [
      renderLatencyTriageBlock(trace, data, scope, onNavigate, topFn),
      renderWaitKindBlock(data, scope, onNavigate),
    ];
  }

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
    if (data === undefined) return loadingBlock(question);
    return render(data);
  }
}
