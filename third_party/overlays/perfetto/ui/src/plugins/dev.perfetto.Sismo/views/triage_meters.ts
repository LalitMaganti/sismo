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

// Thread-state triage rendered as meters, shared by the CPU Overview's triage
// block and the Latency tab. Two gauges over the set's tracked thread-time:
//   • on-CPU vs off-CPU — the binary "did you get the CPU" split. The CPU tab
//     uses it to route off-CPU time to Latency; the Latency tab uses it to
//     route mostly-on-CPU time back to CPU.
//   • why off-CPU — of the off-CPU time alone, the split across waiting for a
//     core (scheduling latency), blocked on I/O (D), benign sleep (S), other.
// The breakdown lives on the Latency tab: "go off CPU → here's why".

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {Anchor} from '../../../widgets/anchor';
import {Callout} from '../../../widgets/callout';
import {Intent} from '../../../widgets/common';
import type {CpuTriage} from '../cpu_data';
import {Meter, meterReadout} from '../../dev.perfetto.SismoWidgets/meter';
import {fmtPercent} from '../format';
import {actionHandler, goToSismoDomain} from '../page_common';
import type {SismoDomain} from '../nav_state';

interface TriageShares {
  // Fractions of total tracked thread-time.
  readonly onCpu: number | null;
  readonly offCpu: number | null;
  readonly offCpuNs: number;
  // Fractions of off-CPU time (sum to ~1 when there is any off-CPU time).
  readonly waiting: number | null; // runnable — scheduling latency
  readonly blocked: number | null; // uninterruptible (D) — I/O
  readonly sleeping: number | null; // interruptible (S) — benign
  readonly other: number | null;
  readonly hasOther: boolean;
}

export function triageShares(d: CpuTriage): TriageShares {
  const total = Number(
    d.runningNs + d.runnableNs + d.uninterruptibleNs + d.sleepingNs + d.otherNs,
  );
  const offNs = Number(
    d.runnableNs + d.uninterruptibleNs + d.sleepingNs + d.otherNs,
  );
  const frac = (ns: bigint, denom: number): number | null =>
    denom > 0 ? Number(ns) / denom : null;
  return {
    onCpu: frac(d.runningNs, total),
    offCpu: total > 0 ? offNs / total : null,
    offCpuNs: offNs,
    waiting: frac(d.runnableNs, offNs),
    blocked: frac(d.uninterruptibleNs, offNs),
    sleeping: frac(d.sleepingNs, offNs),
    other: frac(d.otherNs, offNs),
    hasOther: d.otherNs > 0n,
  };
}

// The routing nudge shared by both triage gauges: one quiet callout whose own
// text ends in the link to the sibling tab. The CPU and Latency tabs always
// carry a link to each other, regardless of the on/off-CPU split — there's no
// reliable threshold for "you should look at the other tab", so we don't guess
// one and never raise the intent above None.
export function renderTriageRoute(
  trace: Trace,
  opts: {
    readonly icon: string;
    readonly message: m.Children;
    readonly linkText: string;
    readonly domain: SismoDomain;
  },
): m.Children {
  return m(
    Callout,
    {icon: opts.icon, intent: Intent.None},
    m(
      'span',
      opts.message,
      ' ',
      m(
        Anchor,
        {
          href: `#!/sismo/${opts.domain}`,
          icon: 'arrow_forward',
          onclick: actionHandler(() => goToSismoDomain(trace, opts.domain)),
        },
        opts.linkText,
      ),
    ),
  );
}

// The binary gauge: of tracked thread-time, on a core vs off it.
export function renderOnOffCpuMeter(d: CpuTriage, scope: string): m.Children {
  const s = triageShares(d);
  return m(Meter, {
    label: 'On CPU vs off CPU',
    help:
      `Of ${scope}’ tracked thread-time, how much was spent executing on a ` +
      'core versus off-CPU — waiting for a core, blocked, or asleep.',
    primary: meterReadout(fmtPercent(s.onCpu), ' on CPU — the rest was off-CPU'),
    bar: [
      {color: 'primary', frac: s.onCpu},
      {color: 'idle', frac: s.offCpu},
    ],
    legend: [
      {color: 'primary', label: 'On CPU', value: fmtPercent(s.onCpu)},
      {color: 'idle', label: 'Off CPU', value: fmtPercent(s.offCpu)},
    ],
  });
}

// The "why off-CPU" breakdown: of the off-CPU time, the reasons it was off.
export function renderOffCpuBreakdownMeter(
  d: CpuTriage,
  scope: string,
): m.Children {
  const s = triageShares(d);
  return m(Meter, {
    label: 'Why were you off CPU?',
    help:
      `Of ${scope}’ off-CPU time, the split across: waiting for a free core ` +
      '(scheduling latency), blocked in the kernel on I/O (uninterruptible, ' +
      'D), benign sleep waiting on an event or timer (interruptible, S), and ' +
      'other states.',
    primary: meterReadout(
      fmtPercent(s.waiting),
      ' of off-CPU time was waiting for a core',
    ),
    bar: [
      {color: 'secondary', frac: s.waiting},
      {color: 'caution', frac: s.blocked},
      {color: 'info', frac: s.sleeping},
      {color: 'idle', frac: s.other},
    ],
    legend: [
      {
        color: 'secondary',
        label: 'Waiting for a core',
        value: fmtPercent(s.waiting),
      },
      {color: 'caution', label: 'Blocked / I/O', value: fmtPercent(s.blocked)},
      {color: 'info', label: 'Sleeping', value: fmtPercent(s.sleeping)},
      ...(s.hasOther
        ? [{color: 'idle' as const, label: 'Other', value: fmtPercent(s.other)}]
        : []),
    ],
  });
}
