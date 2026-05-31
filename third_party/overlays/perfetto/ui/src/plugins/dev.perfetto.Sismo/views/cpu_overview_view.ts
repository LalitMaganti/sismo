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

// CPU "Overview" tab: three meters (cycle budget / CPU usage / parallelism)
// plus orientation stats. The at-a-glance landing for the CPU domain.
//
// Usage and parallelism share a numerator (runtime) but differ in denominator:
// usage divides by walltime (idle counts against you), parallelism divides by
// active walltime (idle gaps removed). So parallelism ≥ usage, and the gap
// between them is how idle the set was.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {Section} from '../../../widgets/section';
import {Card} from '../../../widgets/card';
import {Icon} from '../../../widgets/icon';
import {Tooltip} from '../../../widgets/tooltip';
import type {CpuSummary} from '../cpu_data';
import {Meter, meterReadout} from '../../dev.perfetto.SismoWidgets/meter';
import {
  fmtCount,
  fmtDuration,
  fmtFreqKhz,
  fmtMegacycles,
  fmtMegacyclesNum,
  fmtPercent,
} from '../format';

export function renderCpuOverview(trace: Trace, s: CpuSummary): m.Children {
  const meters: m.Children[] = [];
  // Cycle budget needs cpufreq data to compute the peak-frequency denominator.
  // Without it we can still show usage and parallelism, which only need sched.
  if (s.peakMegacycles !== null && s.megacycles !== null) {
    meters.push(renderCycleBudgetMeter(s));
  }
  meters.push(renderUsageMeter(s));
  meters.push(renderParallelismMeter(s));

  // Secondary stat row: orientation facts that don't need a meter.
  const cards: HeadlineCard[] = [
    {
      label: 'Walltime',
      value: fmtDuration(trace, s.walltimeNs),
      help: 'max(ts) − min(ts) across sched rows.',
    },
    {
      label: 'Cores',
      value:
        s.numClusters > 1
          ? `${s.numCpus} (${s.numClusters} clusters)`
          : `${s.numCpus}`,
    },
    {
      label: 'Avg freq',
      value: fmtFreqKhz(s.avgFreqKhz),
      help: 'Runtime-weighted average across (cpu, frequency).',
    },
    {
      label: 'Peak freq',
      value: fmtFreqKhz(s.maxFreqKhz),
      help: 'Highest CPU frequency observed during the trace.',
    },
    {
      label: 'Processes',
      value: fmtCount(s.numProcesses),
    },
    {
      label: 'Threads',
      value: fmtCount(s.numThreads),
    },
  ];

  return m(
    Section,
    {
      title: 'CPU at a glance',
      subtitle:
        'How much of the machine your processes held over the whole trace ' +
        '(usage), and how many cores they kept busy while actually running ' +
        '(parallelism) — measured against everything else on the system.',
    },
    m('.pf-sismo-page__meters', meters),
    m('.pf-sismo-page__stat-row', cards.map(renderHeadlineCard)),
  );
}

interface HeadlineCard {
  readonly label: string;
  readonly value: string;
  readonly help?: string;
}

// Cycles delivered vs the peak-frequency budget — a frequency story (were
// cores running fast), complementary to the occupancy story below.
function renderCycleBudgetMeter(s: CpuSummary): m.Children {
  const pct = s.bandwidthUtilization ?? 0;
  return m(Meter, {
    label: 'Cycles spent',
    help:
      'Cycles delivered across all cores / cycles that would have been ' +
      'delivered if every core ran at its peak observed frequency for the ' +
      'full walltime. Requires cpufreq data.',
    primary: [
      m('span.pf-sismo-meter__big', fmtMegacycles(s.megacycles)),
      m('span.pf-sismo-meter__caption', ' of '),
      m('span.pf-sismo-meter__big', fmtMegacyclesNum(s.peakMegacycles)),
    ],
    bar: [{color: 'primary', frac: pct}],
    sub: `${fmtPercent(pct)} of peak-frequency budget`,
  });
}

// CPU usage: share of the machine's total core-time the set held over the
// whole trace (idle counts against it). Stacks yours | others | idle, which
// sum to the full core count.
function renderUsageMeter(s: CpuSummary): m.Children {
  const ncpus = s.numCpus;
  const wall = s.walltimeNs;
  const hasPriv = s.privilegedRuntimeNs !== null;
  const totalCores = avgCores(s.totalRuntimeNs, wall);
  const privCores = avgCores(s.privilegedRuntimeNs, wall);
  const ctxCores =
    totalCores !== null && privCores !== null ? totalCores - privCores : null;
  const frac = (cores: number | null) => machineFrac(cores, ncpus);
  const idleFrac = totalCores !== null ? 1 - (frac(totalCores) ?? 0) : null;

  return m(Meter, {
    label: 'CPU usage',
    help:
      'Share of the machine’s total core-time your processes consumed over ' +
      'the whole trace. Idle time counts against you: a process that does a ' +
      'burst of work then sleeps scores low here.',
    primary: meterReadout(
      fmtPercent(frac(hasPriv ? privCores : totalCores)),
      hasPriv ? ' used by your processes' : ' of the machine used',
    ),
    bar: hasPriv
      ? [
          {color: 'primary', frac: frac(privCores)},
          {color: 'secondary', frac: frac(ctxCores)},
          {color: 'idle', frac: idleFrac},
        ]
      : [
          {color: 'primary', frac: frac(totalCores)},
          {color: 'idle', frac: idleFrac},
        ],
    legend: hasPriv
      ? [
          {color: 'primary', label: 'Yours', value: fmtPercent(frac(privCores))},
          {color: 'secondary', label: 'Others', value: fmtPercent(frac(ctxCores))},
          {color: 'idle', label: 'Idle', value: fmtPercent(idleFrac)},
        ]
      : [
          {color: 'primary', label: 'Used', value: fmtPercent(frac(totalCores))},
          {color: 'idle', label: 'Idle', value: fmtPercent(idleFrac)},
        ],
  });
}

// Parallelism: avg cores busy while the set was actually running (idle gaps
// excluded). Reported as a fraction of the machine's cores. Yours and others
// have different active windows, so they can't stack — two tracks instead.
function renderParallelismMeter(s: CpuSummary): m.Children {
  const ncpus = s.numCpus;
  const wall = s.walltimeNs;
  const hasPriv = s.privilegedRuntimeNs !== null;
  const ctxRuntime =
    s.totalRuntimeNs !== null && s.privilegedRuntimeNs !== null
      ? s.totalRuntimeNs - s.privilegedRuntimeNs
      : null;
  const privPar = avgCores(s.privilegedRuntimeNs, s.privilegedActiveWalltimeNs);
  const ctxPar = avgCores(ctxRuntime, s.contextActiveWalltimeNs);
  const wholePar = avgCores(s.totalRuntimeNs, s.activeWalltimeNs);
  const frac = (cores: number | null) => machineFrac(cores, ncpus);
  const cores = (c: number | null) => fmtCoresFrac(c, ncpus);

  const help =
    'Average number of cores in use while your processes were running — ' +
    'idle gaps are excluded. Shows how wide your work was when it actually ' +
    'happened, independent of how often it ran. Compare with CPU usage, ' +
    'which includes idle time.';

  if (hasPriv) {
    return m(Meter, {
      label: 'Parallelism',
      help,
      primary: meterReadout(cores(privPar), ' cores when your processes ran'),
      tracks: [
        {label: 'Yours', color: 'primary', frac: frac(privPar), value: cores(privPar)},
        {label: 'Others', color: 'secondary', frac: frac(ctxPar), value: cores(ctxPar)},
      ],
      sub:
        `Your processes ran during ` +
        `${fmtPercent(activeFrac(s.privilegedActiveWalltimeNs, wall))} of the trace`,
    });
  }
  return m(Meter, {
    label: 'Parallelism',
    help,
    primary: meterReadout(cores(wholePar), ' cores while anything ran'),
    bar: [{color: 'primary', frac: frac(wholePar)}],
    sub:
      `Something ran during ` +
      `${fmtPercent(activeFrac(s.activeWalltimeNs, wall))} of the trace`,
  });
}

// Avg cores = runtime ÷ window (both ns). Null if either is missing or the
// window is empty.
function avgCores(
  runtimeNs: bigint | null,
  windowNs: bigint | null,
): number | null {
  if (runtimeNs === null || windowNs === null || windowNs <= 0n) return null;
  return Number(runtimeNs) / Number(windowNs);
}

function machineFrac(cores: number | null, ncpus: number): number | null {
  if (cores === null || ncpus <= 0) return null;
  return Math.max(0, Math.min(1, cores / ncpus));
}

function activeFrac(activeNs: bigint | null, wall: bigint | null): number | null {
  if (activeNs === null || wall === null || wall <= 0n) return null;
  return Math.max(0, Math.min(1, Number(activeNs) / Number(wall)));
}

// "1.2 / 8" — cores busy out of the machine's cores, the parallelism readout.
function fmtCoresFrac(cores: number | null, ncpus: number): string {
  if (cores === null || !isFinite(cores)) return '—';
  return `${cores.toFixed(1)} / ${ncpus}`;
}

function renderHeadlineCard({label, value, help}: HeadlineCard): m.Children {
  return m(
    Card,
    {className: 'pf-sismo-page__stat-card'},
    m(
      '.pf-sismo-page__stat-label',
      label,
      help &&
        m(
          Tooltip,
          {
            trigger: m(Icon, {
              icon: 'help_outline',
              className: 'pf-sismo-page__help-icon',
            }),
          },
          help,
        ),
    ),
    m('.pf-sismo-page__stat-value', value),
  );
}
