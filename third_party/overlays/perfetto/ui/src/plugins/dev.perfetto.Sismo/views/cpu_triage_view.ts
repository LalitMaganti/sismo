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

// Overview question #0 — the triage / domain router: "Was your process running,
// or waiting to run?" Of the time the set wanted a CPU (running + runnable), how
// much it actually got. It describes the split without judging it; when threads
// spent real time runnable, that's scheduling latency and the block routes to
// the Latency domain rather than pretending the CPU-usage views can help.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {EmptyState} from '../../../widgets/empty_state';
import {loadCpuTriage, type CpuTriage} from '../cpu_data';
import {renderQuestionBlock} from '../page_common';
import type {PrivilegedSet} from '../privileged_set';
import {renderOnOffCpuMeter, renderTriageRoute} from './triage_meters';

interface CpuTriageViewAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
}

const QUESTION = 'Was your process running, or waiting to run?';

function why(scope: string): string {
  return (
    `Before optimising CPU usage, check ${scope} were actually CPU-bound. If ` +
    'they spent the time waiting for a core, the bottleneck is scheduling ' +
    'latency, not CPU usage.'
  );
}

export class CpuTriageView implements m.ClassComponent<CpuTriageViewAttrs> {
  private data?: CpuTriage;

  constructor({attrs}: m.CVnode<CpuTriageViewAttrs>) {
    this.load(attrs.trace, attrs.priv);
  }

  view({attrs}: m.CVnode<CpuTriageViewAttrs>): m.Children {
    const scope = attrs.priv.upids.length > 0 ? 'your threads' : 'all threads';
    if (this.data === undefined) {
      return renderQuestionBlock(
        {question: QUESTION, why: why(scope)},
        m(EmptyState, {
          icon: 'hourglass_empty',
          title: 'Loading thread states…',
        }),
      );
    }
    const d = this.data;
    if (!d.hasData) {
      return renderQuestionBlock(
        {question: QUESTION, why: why(scope)},
        m(EmptyState, {icon: 'schedule', title: 'No thread-state data'}),
      );
    }

    // The binary on-CPU vs off-CPU gauge frames the block; a standing link
    // hands the off-CPU half to the Latency tab, which breaks it down by why.
    return renderQuestionBlock(
      {question: QUESTION, why: why(scope)},
      m('.pf-sismo-page__meters', [renderOnOffCpuMeter(d, scope)]),
      renderTriageRoute(attrs.trace, {
        icon: 'schedule',
        message: `Off-CPU time — ${scope} waiting for a core, blocked, or asleep — is broken down by why in the Latency view.`,
        linkText: 'Open the Latency view',
        domain: 'latency',
      }),
    );
  }

  private async load(trace: Trace, priv: PrivilegedSet): Promise<void> {
    try {
      this.data = await loadCpuTriage(trace.engine, priv);
    } catch {
      this.data = {
        hasData: false,
        runningNs: 0n,
        runnableNs: 0n,
        uninterruptibleNs: 0n,
        sleepingNs: 0n,
        otherNs: 0n,
      };
    }
  }
}
