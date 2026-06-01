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
import {Callout} from '../../../widgets/callout';
import {Intent} from '../../../widgets/common';
import type {ConcurrencyDist, CpuDetail, CpuSummary} from '../cpu_data';
import {Meter, meterReadout} from '../../dev.perfetto.SismoWidgets/meter';
import {
  renderQuestionBlock,
  renderSeeAllLink,
  renderStatCard,
  type StatCard,
} from '../page_common';
import {CpuTriageView} from './cpu_triage_view';
import {CpuBottleneckOverview} from './cpu_bottleneck_view';
import {renderProcessTable, renderThreadTable} from './cpu_consumers_view';
import {
  renderHotMappingTable,
  renderHotSymbolTable,
} from './cpu_functions_view';
import type {PrivilegedSet} from '../privileged_set';
import {fmtDuration, fmtPercent} from '../format';

// Compact top-N shown on the Overview; the full lists live on the lens tabs.
const TOP_N = 6;

export function renderCpuOverview(
  trace: Trace,
  d: CpuDetail,
  priv: PrivilegedSet,
): m.Children {
  const s = d.summary;
  const hasPriv = priv.upids.length > 0;

  // #1 magnitude: occupancy of the machine over the whole trace.
  const magnitudeMeters: m.Children[] = [renderUsageMeter(s)];

  // Orientation facts about the machine the work ran on.
  const orientation: StatCard[] = [
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
  ];

  // "Who used it" — your things first, in names you recognise. Top-N here; the
  // full lists are one click away on the Threads tab. (Functions get their own
  // block above; this one is the thread/process breakdown of the magnitude.)
  const threads = hasPriv ? d.privilegedThreads : d.topContextThreads;
  const processes = hasPriv ? d.privilegedProcesses : d.topContextProcesses;
  const tables: m.Children[] = [];
  if (threads.length > 0) {
    tables.push(
      namedTable(
        'Busiest threads',
        renderThreadTable(trace, s, threads.slice(0, TOP_N)),
      ),
    );
  }
  // Only worth a processes table when there's more than one to compare; a
  // single profiled process is already named in the banner.
  if (processes.length > 1) {
    tables.push(
      namedTable(
        'Busiest processes',
        renderProcessTable(trace, s, processes.slice(0, TOP_N)),
      ),
    );
  }

  const whereFooter = [
    renderSeeAllLink(trace, 'All threads & processes', 'threads'),
  ];

  // #2 is only a question when there's more than one thread to parallelise.
  const multiThreaded = hasPriv
    ? d.privilegedThreads.length > 1
    : s.numThreads > 1;

  // #3 shape: burst the work into runs and idle gaps. Many short bursts keep
  // the frequency governor from ramping; long sustained bursts let it.
  const b = d.bursts;
  const wallSec = s.walltimeNs !== null ? Number(s.walltimeNs) / 1e9 : null;
  const churn = wallSec !== null && wallSec > 0 ? b.numBursts / wallSec : null;
  const avgBurstNs =
    b.numBursts > 0 ? b.activeNs / BigInt(b.numBursts) : null;
  const shapeCards: StatCard[] = [
    {
      label: 'Wake-ups',
      value: churn === null ? '—' : `${fmtRate(churn)} /s`,
      help:
        'How often the work started running again after going idle (bursts ' +
        'per second). Higher means more frequent, shorter bursts.',
    },
    {
      label: 'Avg burst',
      value: fmtDuration(trace, avgBurstNs),
      help: 'Mean length of a continuous run before the work next went idle.',
    },
  ];

  return [
    // On/off-CPU guard first (per-function CPU time only means something once
    // you know the work was actually on-CPU), then where the code spent it.
    m(CpuTriageView, {trace, priv}),
    renderCodeBlock(trace, d),
    renderQuestionBlock(
      {
        question: 'How much CPU did you use, and who used it?',
        why:
          'Your share of the machine over the whole trace, and the threads ' +
          'and processes that share is made of.',
        footer: whereFooter,
      },
      // Scorecards first, then the breakdowns (meters, then the per-entity
      // tables): aggregated → broken down.
      m('.pf-sismo-page__stat-row', orientation.map(renderStatCard)),
      m('.pf-sismo-page__meters', magnitudeMeters),
      tables.length > 0 && m('.pf-sismo-page__tables', tables),
    ),
    multiThreaded &&
      renderQuestionBlock(
        {
          question:
            'Were your threads actually running in parallel, or serialized?',
          why:
            'Whether multithreading bought you width: how many cores your work ' +
            'kept busy while it was actually running.',
        },
        // The average (parallelism meter) next to its distribution (the
        // concurrency mix), both as meters rather than bare scorecards.
        m('.pf-sismo-page__meters', [
          renderParallelismMeter(s),
          d.concurrency.hasData && renderConcurrencyMeter(d.concurrency),
        ]),
      ),
    b.hasData &&
      renderQuestionBlock(
        {
          question: 'Steady work, or lots of tiny bursts?',
          why:
            'How the work is spread in time. Short, frequent bursts can keep ' +
            'the CPU from ramping to full speed; long sustained bursts let it.',
        },
        m('.pf-sismo-page__stat-row', shapeCards.map(renderStatCard)),
        m('.pf-sismo-page__meters', [
          m(Meter, {
            label: 'Burst lengths',
            help:
              'How active time splits between sustained runs and short ' +
              'bursts. Bursts under 30 ms can be too short for the CPU ' +
              'frequency governor to ramp to full speed.',
            primary: meterReadout(
              fmtPercent(pctOf(b.shortBurstNs, b.activeNs)),
              ' in short bursts (<30 ms)',
            ),
            bar: [
              {color: 'primary', frac: pctOf(b.longBurstNs, b.activeNs)},
              {color: 'secondary', frac: pctOf(b.shortBurstNs, b.activeNs)},
            ],
            legend: [
              {
                color: 'primary',
                label: 'Sustained (≥30 ms)',
                value: fmtPercent(pctOf(b.longBurstNs, b.activeNs)),
              },
              {
                color: 'secondary',
                label: 'Short (<30 ms)',
                value: fmtPercent(pctOf(b.shortBurstNs, b.activeNs)),
              },
            ],
          }),
        ]),
      ),
    m(CpuBottleneckOverview, {trace, priv}),
  ];
}

// The headline "where did your code spend time" block: hot functions (leaf
// self-time) beside the libraries they live in. Driven by CPU samples, scoped
// to the profiled set. Omitted entirely when the trace has no samples; when it
// has samples but none symbolised, a note points at the fix rather than a table.
function renderCodeBlock(trace: Trace, d: CpuDetail): m.Children {
  const ma = d.microarch;
  if (!ma.hasSamples) return undefined;
  const question = 'Where did your program spend its time?';
  const why =
    'The functions your CPU samples landed in — leaf-frame self time, so ' +
    'where the cycles were actually being spent — and the libraries they ' +
    'live in.';
  if (!ma.hasSymbols) {
    return renderQuestionBlock(
      {question, why},
      m(
        Callout,
        {icon: 'info', intent: Intent.Primary},
        'CPU samples were captured but none were symbolised. Make sure debug ' +
          'info is available — unstripped binaries on Linux, dSYMs on macOS — ' +
          'to see which functions the time went to.',
      ),
    );
  }
  return renderQuestionBlock(
    {question, why, footer: renderSeeAllLink(trace, 'All functions', 'flamegraph')},
    m(
      '.pf-sismo-page__microarch',
      m(
        '.pf-sismo-page__microarch-col',
        m('.pf-sismo-page__tab-pane-label', 'Hot functions'),
        renderHotSymbolTable(ma.hotSymbols.slice(0, TOP_N)),
      ),
      ma.hotMappings.length > 0 &&
        m(
          '.pf-sismo-page__microarch-col',
          m('.pf-sismo-page__tab-pane-label', 'Hot libraries'),
          renderHotMappingTable(ma.hotMappings.slice(0, TOP_N)),
        ),
    ),
  );
}

// Fraction a/b as a number in [0,1], or null when the denominator is empty.
function pctOf(a: bigint, b: bigint): number | null {
  return b > 0n ? Number(a) / Number(b) : null;
}

// Compact rate readout: one decimal below 10, whole numbers above.
function fmtRate(n: number): string {
  return n >= 10 ? n.toFixed(0) : n.toFixed(1);
}

function namedTable(label: string, table: m.Children): m.Children {
  return m(
    '.pf-sismo-page__tab-pane',
    m('.pf-sismo-page__tab-pane-label', label),
    table,
  );
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

// The distribution behind the parallelism mean: of the active window, how it
// splits across exactly one core (serial), 2–4, and 5+. Neutral — whether
// serial is "bad" is up to the workload; the bands are just named categories,
// not a good/bad scale.
function renderConcurrencyMeter(c: ConcurrencyDist): m.Children {
  const serial = pctOf(c.serialNs, c.activeNs);
  const few = pctOf(c.fewNs, c.activeNs);
  const many = pctOf(c.manyNs, c.activeNs);
  return m(Meter, {
    label: 'Concurrency mix',
    help:
      'How the active window splits by how many cores ran the work at once: ' +
      'exactly one (serial), 2–4, or 5 or more. The distribution behind the ' +
      'average parallelism above.',
    primary: meterReadout(fmtPercent(serial), ' ran on a single core (serial)'),
    bar: [
      {color: 'idle', frac: serial},
      {color: 'secondary', frac: few},
      {color: 'primary', frac: many},
    ],
    legend: [
      {color: 'idle', label: 'Serial (1)', value: fmtPercent(serial)},
      {color: 'secondary', label: '2–4 cores', value: fmtPercent(few)},
      {color: 'primary', label: 'Wide (5+)', value: fmtPercent(many)},
    ],
    sub:
      c.maxConcurrency > 0
        ? `Peak ${c.maxConcurrency} cores running at once`
        : undefined,
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
