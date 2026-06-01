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

// The single shape every CPU observation card is built from and ranked by.
// Cards NEVER assert verdicts. Headlines are QUESTIONS. Ranking is cost x
// surprise.
//
// Cost is normalized to ONE unit: nanoseconds of CPU/wall time (`costNs`).
// Sample-count detectors convert to ns via the trace's CPU-time-per-sample
// scale (ObservationContext.nsPerSample) so heterogeneous kinds rank on one
// axis.

import type {Engine} from '../../../trace_processor/engine';
import type {PrivilegedSet} from '../privileged_set';
import type {MeterColor, MeterSegment, MeterTrack} from
  '../../dev.perfetto.SismoWidgets/meter';
import type {FocusWindow} from './focus_window';
import {
  loadHeaviestFunctions,
  loadCallTree,
  loadRepresentativeSample,
} from './calltree';
import {loadThreadRows, loadThreadStates, loadCpuTotals} from './cores';
import {loadMicroarchCounters, loadRealCycles} from './microarch';

// ---- Kind ------------------------------------------------------------------

export type ObservationKind =
  | 'volume' // one call path dominates the sampled budget
  | 'efficiency' // IPC far from the trace average / high backend-bound
  | 'placement' // runtime split across heterogeneous cores
  | 'balance' // CPU consumption skewed across threads of one process
  | 'offcpu'; // ESCAPE-HATCH pointer to the Latency section (not analysis)

// ---- Meter spec (declarative; rendered by the feed, not the detector) ------
// Mirrors the existing Meter widget. A card's meter visualizes its contrast as
// EITHER a single stacked bar (dominant vs rest / capacity split) OR independent
// tracks (this vs sibling/avg). meterReadout(big, caption) builds `primary`.

export interface ObservationMeter {
  readonly label: string;
  readonly help?: string;
  readonly primaryBig: string; // headline number, e.g. '60%' or '0.24'
  readonly primaryCaption: string; // muted trailing caption, e.g. 'of CPU'
  // Exactly one of bar | tracks is populated (the other undefined).
  readonly bar?: ReadonlyArray<MeterSegment>;
  readonly tracks?: ReadonlyArray<MeterTrack>;
  readonly legend?: ReadonlyArray<{color: MeterColor; label: string; value: string}>;
  readonly sub?: string;
}

// ---- Drill spec: which evidence lens the card expands into -----------------
// Lenses are the KEEP views. Params are scope, not pre-rendered UI; the feed
// constructs the lens lazily on expand. `where` are perf_sample predicates
// (alias `p`) for flamegraph scope; `priv`/`window` thread the standard scope.

export type DrillLens =
  | 'flamegraph' // FlamegraphPanel via buildSampleFlamegraphMetrics(where,...)
  | 'calltree' // loadCallTree(engine, priv, direction, window)
  | 'funcTable' // per-function IPC/TMA table from loadMicroarchCounters
  | 'coresTable' // per-core / per-thread-x-core breakdown
  | 'threadTable'; // per-thread runtime / state split

export interface ObservationDrill {
  readonly lens: DrillLens;
  // perf_sample predicates (alias `p`) for flamegraph; empty = whole scope.
  readonly where?: ReadonlyArray<string>;
  readonly calltreeDirection?: 'top-down' | 'bottom-up';
  // For funcTable/coresTable/threadTable: optional focus on one entity/function.
  readonly focusName?: string; // function name to scroll/highlight
  readonly focusUtid?: number;
  readonly focusUpid?: number;
  readonly focusCpu?: number;
}

// ---- Exemplar spec: "open this in the timeline" ----------------------------
// Reveals a representative entity (and its active span, via revealEntityWindow)
// or a raw window. Fire-and-forget on click.

export interface ObservationExemplar {
  readonly label: string; // button text, e.g. 'Show TracingMuxer in timeline'
  // Reveal an entity's active span (uses revealEntityWindow(trace, {utid|upid})).
  readonly utid?: number;
  readonly upid?: number;
  // Or frame a raw window (uses goToTimeline + window framing) when no single
  // entity is representative.
  readonly window?: FocusWindow;
}

// ---- The Observation -------------------------------------------------------

export interface Observation {
  readonly id: string; // stable per (kind, entity), e.g. 'volume:fun_f7905'
  readonly kind: ObservationKind;
  // Headline phrased as a QUESTION, never an assertion.
  // e.g. 'X% of CPU goes to fun_f7905() — is that expected?'
  readonly question: string;
  // Normalized COST: nanoseconds of CPU (or wall, for offcpu) time this concerns.
  // Sample-based detectors convert via ctx.nsPerSample. Always finite, >= 0.
  readonly costNs: number;
  // CONTRAST magnitude (intent-free asymmetry). Unitless, >= 0. Larger = more
  // notable. Examples: dominant-share ratio, top/median sibling ratio,
  // |IPC - avg|/avg, off-CPU fraction. Normalized within-kind to [0,1]-ish via
  // observationScore before ranking.
  readonly surprise: number;
  readonly meter: ObservationMeter;
  readonly drill: ObservationDrill;
  readonly exemplar: ObservationExemplar;
  // Feasibility provenance, surfaced as a small caption so approximate/degenerate
  // cards are honest about their grounding.
  readonly confidence: 'feasible' | 'approximate';
  readonly note?: string; // e.g. 'sampled attribution, smears to average'
}

// ---- Detector context & signature ------------------------------------------
// One context is built once per (priv, window) and passed to every detector so
// they share the denominators needed to normalize cost and surprise.

export interface ObservationContext {
  readonly priv: PrivilegedSet;
  readonly window?: FocusWindow;
  // Total on-CPU ns in scope (from loadCpuTotals); denominator for cost%.
  readonly totalCpuNs: bigint;
  // CPU ns represented by one perf_sample = totalCpuNs / totalSamples; lets
  // sample-count detectors emit costNs on the same axis. 0 if no samples.
  readonly nsPerSample: number;
  // Trace-average IPC for the efficiency contrast (~4.87 in the sample trace).
  readonly avgIpc: number | null;
}

export type Detector = (
  engine: Engine,
  ctx: ObservationContext,
) => Promise<ReadonlyArray<Observation>>;

// ---- Tunables --------------------------------------------------------------

const EPSILON = 1e-9;
// Ratio kinds saturate hard past this; without a cap a 100%/0% degenerate
// volume card produces an unbounded surprise and a `note` is set instead.
const RATIO_CAP = 50;
// Detectors below this normalized surprise are dropped so the feed isn't padded
// with non-contrasts.
const SURPRISE_FLOOR = 0.05;
// Off-CPU is a pointer, not on-CPU analysis: soft-cap its normSurprise so an
// equal-magnitude analysis card outranks it.
const OFFCPU_SURPRISE_FACTOR = 0.85;
// Deterministic tie-break ordering after costShare.
const KIND_ORDER: ReadonlyArray<ObservationKind> = [
  'volume',
  'efficiency',
  'placement',
  'balance',
  'offcpu',
];

// ---- Context builder -------------------------------------------------------

export async function buildObservationContext(
  engine: Engine,
  priv: PrivilegedSet,
  window?: FocusWindow,
): Promise<ObservationContext> {
  const totals = await loadCpuTotals(engine, priv, window);
  // Scope to the privileged set when one exists, else the whole trace — the
  // same denominator the detectors' sample/runtime numerators are scoped to.
  const hasPriv = priv.upids.length > 0;
  const totalCpuNs =
    hasPriv && totals.privilegedNs !== null
      ? totals.privilegedNs
      : totals.totalNs;

  const heaviest = await loadHeaviestFunctions(engine, priv, 1, window);
  // nsPerSample = scoped CPU ns / scoped sample count. loadHeaviestFunctions
  // exposes share = samples/total for the top row, so total = samples/share.
  let totalSamples = 0;
  if (heaviest.length > 0 && heaviest[0].share > 0) {
    totalSamples = Math.round(heaviest[0].samples / heaviest[0].share);
  }
  const nsPerSample =
    totalSamples > 0 ? Number(totalCpuNs) / totalSamples : 0;

  // Trace-average IPC from real eBPF counters (cumulative-per-thread max),
  // restricted to the privileged set.
  const real = await loadRealCycles(engine, window);
  const privUpids = new Set(priv.upids);
  let cyc = 0n;
  let instr = 0n;
  if (hasPriv) {
    for (const [upid, v] of real.byUpid) if (privUpids.has(upid)) cyc += v;
    for (const [upid, v] of real.instrByUpid) if (privUpids.has(upid)) instr += v;
  } else {
    for (const v of real.byUpid.values()) cyc += v;
    for (const v of real.instrByUpid.values()) instr += v;
  }
  const avgIpc = cyc > 0n ? Number(instr) / Number(cyc) : null;

  return {priv, window, totalCpuNs, nsPerSample, avgIpc};
}

// ---- volume ----------------------------------------------------------------
// One call path dominates the sample budget: the heaviest single function.
// FROZEN trace caveat: 1 leaf frame across 83 callsites, so the leaf
// leaderboard can be degenerate (100%/0%). The dominant CALLSITE PATH from the
// top-down tree gives a non-degenerate contrast, so prefer it and fall back to
// the leaf leaderboard.

const detectVolume: Detector = async (engine, ctx) => {
  const {priv, window, nsPerSample} = ctx;
  const tree = await loadCallTree(engine, priv, 'top-down', window);
  if (!tree.hasSamples || tree.totalSamples === 0 || nsPerSample === 0) {
    return [];
  }

  // Heaviest single root-to-leaf PATH: at each depth pick the heaviest child of
  // the current node by totalSamples, accumulating its leaf-function name. The
  // path's weight is its deepest node's selfSamples (the leaf actually sampled).
  const byParent = new Map<number | null, typeof tree.nodes>();
  for (const n of tree.nodes) {
    const arr = byParent.get(n.parentId);
    if (arr) arr.push(n);
    else byParent.set(n.parentId, [n]);
  }
  const heaviestChild = (parentId: number | null) => {
    const kids = byParent.get(parentId);
    if (kids === undefined || kids.length === 0) return undefined;
    return kids.reduce((a, b) => (b.totalSamples > a.totalSamples ? b : a));
  };
  let cur = heaviestChild(null);
  let leaf = cur;
  while (cur !== undefined) {
    leaf = cur;
    const next = heaviestChild(cur.id);
    if (next === undefined) break;
    cur = next;
  }
  if (leaf === undefined) return [];

  const topSamples = leaf.totalSamples;
  const total = tree.totalSamples;
  const dominantShare = topSamples / total;
  const restShare = Math.max(0, 1 - dominantShare);
  // Capped dominant/rest ratio; a degenerate 100%/0% trace yields RATIO_CAP and
  // a note flags it.
  const rawRatio = dominantShare / Math.max(restShare, EPSILON);
  const degenerate = restShare < EPSILON;
  const surprise = Math.min(rawRatio, RATIO_CAP);
  const costNs = topSamples * nsPerSample;
  const pct = Math.round(dominantShare * 100);
  const fn = leaf.name;
  const exemplar = await functionExemplar(engine, fn, priv, window);

  return [
    {
      id: `volume:${sanitizeId(fn)}`,
      kind: 'volume',
      question:
        `${pct}% of CPU goes to ${fn}() — is this where you want the time going?`,
      costNs,
      surprise,
      meter: {
        label: 'Dominant function',
        help: 'Share of sampled CPU spent in the single heaviest call path.',
        primaryBig: `${pct}%`,
        primaryCaption: 'of CPU',
        // Neutral baseline (idle grey): the size carries the contrast. secondary
        // is amber and would paint the innocent "rest" as a warning.
        bar: [
          {color: 'primary', frac: dominantShare},
          {color: 'idle', frac: restShare},
        ],
        legend: [
          {color: 'primary', label: fn, value: `${pct}%`},
          {color: 'idle', label: 'rest', value: `${Math.round(restShare * 100)}%`},
        ],
        sub: degenerate
          ? 'one call path carries nearly all of the samples'
          : undefined,
      },
      drill: {lens: 'flamegraph', where: [], focusName: fn},
      exemplar,
      confidence: 'feasible',
      note: degenerate
        ? 'single call path carries every sample; contrast is degenerate'
        : undefined,
    },
  ];
};

// ---- balance ---------------------------------------------------------------
// CPU consumption skewed across threads of one process: top thread vs its
// median sibling. Intent-free distribution asymmetry.

const detectBalance: Detector = async (engine, ctx) => {
  const {priv, window} = ctx;
  // Scope to the profiled workload when a set is selected; otherwise look at
  // every process (`context` of an empty set = all threads) so whole-trace skew
  // is still visible rather than silently empty.
  const kind = priv.upids.length > 0 ? 'privileged' : 'context';
  const rows = await loadThreadRows(engine, priv, kind, undefined, window);
  if (rows.length === 0) return [];

  // Group threads by process (keyed on upid, not name — names collide) so the
  // asymmetry is within one process's siblings.
  const byProcess = new Map<number, typeof rows>();
  for (const r of rows) {
    if (r.upid === null) continue;
    const arr = byProcess.get(r.upid);
    if (arr) arr.push(r);
    else byProcess.set(r.upid, [r]);
  }

  const out: Observation[] = [];
  for (const [upid, threads] of byProcess) {
    if (threads.length < 2) continue;
    const process = threads[0].processName ?? '<unknown>';
    const sorted = [...threads].sort((a, b) =>
      Number(b.runtimeNs - a.runtimeNs),
    );
    const top = sorted[0];
    const median = medianNs(sorted.map((t) => t.runtimeNs));
    if (median <= 0n || top.runtimeNs <= 0n) continue;
    const ratio = Number(top.runtimeNs) / Number(median);
    if (ratio <= 1) continue;
    const costNs = Number(top.runtimeNs);
    const surprise = Math.min(ratio, RATIO_CAP);
    const ratioStr = ratio.toFixed(ratio >= 10 ? 0 : 1);

    out.push({
      id: `balance:${top.utid}`,
      kind: 'balance',
      question:
        `${top.threadName} does ${ratioStr}x the CPU work of a typical ` +
        `thread in ${process} — is this thread meant to carry the load?`,
      costNs,
      surprise,
      meter: {
        label: 'Work across threads',
        help:
          'CPU time of the busiest thread vs a typical (median) thread in ' +
          'the same process.',
        primaryBig: `${ratioStr}x`,
        primaryCaption: 'busiest vs a typical thread',
        // Independent tracks: top and median have no shared denominator.
        tracks: [
          {
            label: top.threadName,
            color: 'primary',
            frac: 1,
            value: fmtMs(top.runtimeNs),
          },
          {
            label: 'typical thread',
            color: 'idle',
            frac: Number(median) / Number(top.runtimeNs),
            value: fmtMs(median),
          },
        ],
      },
      drill: {lens: 'threadTable', focusUpid: upid, focusUtid: top.utid},
      exemplar: {
        label: `Show ${top.threadName} in timeline`,
        utid: top.utid,
      },
      confidence: 'feasible',
    });
  }
  return out;
};

// ---- efficiency ------------------------------------------------------------
// Less work per CPU cycle than the rest of the trace: a hot function whose IPC
// sits BELOW the average (the "why slow" direction — stalls). A function doing
// MORE work per cycle isn't a slowness signal, so only the low side fires.
// APPROXIMATE: per-function counters are sampled and smear toward the average
// (the per-interval delta is credited to the stack at the interval's end).

const detectEfficiency: Detector = async (engine, ctx) => {
  const {priv, window, nsPerSample, avgIpc, totalCpuNs} = ctx;
  if (avgIpc === null || avgIpc <= 0 || nsPerSample === 0) return [];
  const denom = Number(totalCpuNs);
  if (denom <= 0) return [];
  const mc = await loadMicroarchCounters(engine, priv, 50, window);
  if (mc.state !== 'ok') return [];

  const out: Observation[] = [];
  for (const fn of mc.perFunc) {
    const ipc = fn.tma?.ipc;
    if (ipc === undefined || ipc === null) continue; // too few samples for TMA
    if (ipc >= avgIpc) continue; // only the below-average (stalling) side
    let surprise = (avgIpc - ipc) / avgIpc;
    // Backend (memory) stalls amplify the contrast; surfaced on the meter `sub`
    // so the displayed reason names what boosted the rank.
    const backend = fn.tma?.buckets.find((b) => b.key === 'backend');
    if (backend !== undefined) surprise *= 1 + backend.frac;
    const costNs = fn.samples * nsPerSample;
    const pct = Math.round((costNs / denom) * 100);
    const ipcStr = ipc.toFixed(2);
    const avgStr = avgIpc.toFixed(2);
    // Lead with the plain consequence. When backend (memory) stalls are
    // attributed, say so; otherwise state the work-per-cycle contrast directly.
    const question =
      backend !== undefined
        ? `${fn.name} spends most of its CPU cycles waiting on memory rather ` +
          `than computing (${pct}% of CPU) — expected for this code?`
        : `${fn.name} does much less work per CPU cycle than the rest of the ` +
          `trace (${pct}% of CPU) — expected for this code?`;
    const exemplar = await functionExemplar(engine, fn.name, priv, window);

    out.push({
      id: `efficiency:${sanitizeId(fn.name)}`,
      kind: 'efficiency',
      question,
      costNs,
      surprise,
      meter: {
        label: 'Work per CPU cycle',
        help:
          'Instructions completed per CPU cycle, against the trace average. ' +
          'Lower means more cycles spent waiting rather than computing ' +
          '(often on memory).',
        primaryBig: ipcStr,
        primaryCaption: `per cycle vs ${avgStr} average`,
        // Independent tracks scaled to the average so the shortfall is legible.
        // Neutral colour — the size difference carries the contrast; a caution
        // colour would assert a verdict the tool can't make.
        tracks: [
          {label: fn.name, color: 'primary', frac: ipc / avgIpc, value: ipcStr},
          {label: 'trace average', color: 'idle', frac: 1, value: avgStr},
        ],
        sub:
          backend !== undefined
            ? `waiting on memory ~${Math.round(backend.frac * 100)}% of cycles`
            : undefined,
      },
      drill: {lens: 'funcTable', focusName: fn.name},
      exemplar,
      confidence: 'approximate',
      note:
        'Measured by sampling many moments, so the exact figure is ' +
        'approximate — the direction is reliable.',
    });
  }
  return out;
};

// ---- offcpu ----------------------------------------------------------------
// ESCAPE-HATCH pointer, NOT analysis: when threads spend most of their wall time
// off-CPU, this is a Latency question, not a CPU one. Emits AT MOST ONE
// aggregate pointer (a per-thread card per idle thread would flood the feed),
// represented by the busiest thread that is still mostly waiting, with a count
// of how many share that shape. costNs is WALL ns (the one kind in wall time).

// A thread counts as "mostly off-CPU" past this share of its wall time.
const OFFCPU_FRAC_THRESHOLD = 0.5;

const detectOffCpu: Detector = async (engine, ctx) => {
  const {priv, window} = ctx;
  const rows = await loadThreadStates(engine, priv, 100, window);
  // rows arrive ordered by running-time desc, so the first mostly-off-CPU row is
  // the one that did the most on-CPU work yet still spent most of its time
  // waiting — the genuinely interesting "is this latency-bound?" signal.
  let rep: (typeof rows)[number] | undefined;
  let repOffFrac = 0;
  let repOffCpuNs = 0n;
  let repRunningFrac = 0;
  let count = 0;
  for (const r of rows) {
    const totalNs =
      r.runningNs +
      r.runnableNs +
      r.uninterruptibleNs +
      r.sleepingNs +
      r.otherNs;
    if (totalNs <= 0n) continue;
    const offCpuNs = totalNs - r.runningNs;
    if (offCpuNs <= 0n) continue;
    const offFrac = Number(offCpuNs) / Number(totalNs);
    if (offFrac < OFFCPU_FRAC_THRESHOLD) continue;
    count++;
    if (rep === undefined) {
      rep = r;
      repOffFrac = offFrac;
      repOffCpuNs = offCpuNs;
      repRunningFrac = Number(r.runningNs) / Number(totalNs);
    }
  }
  if (rep === undefined) return [];

  const pct = Math.round(repOffFrac * 100);
  const others = count - 1;
  const question =
    others > 0
      ? `${rep.threadName} and ${others} other ` +
        `thread${others > 1 ? 's' : ''} spent most of their time waiting ` +
        'rather than running on the CPU — a Latency question; open the ' +
        'Latency section?'
      : `${rep.threadName} spent ${pct}% of its time waiting rather than ` +
        'running on the CPU — a Latency question; open the Latency section?';

  return [
    {
      id: `offcpu:${rep.utid}`,
      kind: 'offcpu',
      question,
      costNs: Number(repOffCpuNs),
      surprise: repOffFrac,
      meter: {
        label: 'On- vs off-CPU',
        help: 'Wall time this thread spent running vs waiting/blocked/sleeping.',
        primaryBig: `${pct}%`,
        primaryCaption: 'off-CPU (wall)',
        bar: [
          {color: 'primary', frac: repRunningFrac},
          {color: 'idle', frac: repOffFrac},
        ],
        legend: [
          {color: 'primary', label: 'Running', value: `${Math.round(repRunningFrac * 100)}%`},
          {color: 'idle', label: 'Off-CPU', value: `${pct}%`},
        ],
        sub:
          others > 0
            ? `${count} threads in scope are >50% off-CPU`
            : undefined,
      },
      // No on-CPU lens by design; threadTable shows only the state split as
      // context. The card's primary action navigates to the Latency domain.
      drill: {lens: 'threadTable', focusUtid: rep.utid},
      exemplar: {label: `Show ${rep.threadName} in timeline`, utid: rep.utid},
      confidence: 'feasible',
    },
  ];
};

// ---- placement (DEFERRED) --------------------------------------------------
// Requires non-uniform cpu.capacity / cluster_id topology (big.LITTLE / P+E /
// NUMA). The sample trace is uniform, so the detector is registered off until
// topology data exists. Implementation would compose loadPerCore (capacity
// classes) with an inverted loadCoreThreads (per-thread x core runtime).

// ---- Registry --------------------------------------------------------------
// placement excluded until topology data exists (see feasibility notes).
export const detectors: ReadonlyArray<Detector> = [
  detectVolume,
  detectEfficiency,
  detectBalance,
  detectOffCpu,
];

// ---- Ranking ---------------------------------------------------------------

// Map a ratio r in [1, inf) to [0,1): 1x->0, 2x->0.5, 20x->0.95, asymptote 1.
function ratioToNorm(r: number): number {
  if (r <= 1) return 0;
  return 1 - 1 / r;
}

// Normalize surprise WITHIN kind onto a comparable [0,1) axis. Ratio-based
// kinds (volume, balance) go through ratioToNorm; fraction-based kinds
// (efficiency, offcpu) are already in [0,1]. offcpu carries a soft cap.
function normalizedSurprise(o: Observation): number {
  switch (o.kind) {
    case 'volume':
    case 'balance':
      return ratioToNorm(o.surprise);
    case 'efficiency':
      return Math.max(0, Math.min(1, o.surprise));
    case 'offcpu':
      return Math.max(0, Math.min(1, o.surprise)) * OFFCPU_SURPRISE_FACTOR;
    case 'placement':
      return Math.max(0, Math.min(1, o.surprise));
  }
}

// Pure ranking score: costShare x normalizedSurprise. A card needs BOTH
// meaningful cost AND a notable asymmetry to rank high.
export function observationScore(
  o: Observation,
  ctx: ObservationContext,
): number {
  return costShareOf(o, ctx) * normalizedSurprise(o);
}

// Cost as a [0,1] share for ranking. On-CPU kinds divide costNs by the on-CPU
// denominator. off-CPU's costNs is WALL ns and would saturate that ratio to 1,
// defeating the pointer soft-cap, so it uses its own off-CPU wall fraction
// (carried in surprise) which is already a [0,1] fraction on its own axis.
function costShareOf(o: Observation, ctx: ObservationContext): number {
  if (o.kind === 'offcpu') return Math.max(0, Math.min(1, o.surprise));
  const denom = Number(ctx.totalCpuNs);
  if (denom <= 0) return 0;
  return Math.max(0, Math.min(1, o.costNs / denom));
}

// Runs every registered detector over (priv, window), drops non-contrasts below
// the surprise floor, and returns observations sorted by cost x surprise
// descending (tie-break: costShare, then kind order).
export async function loadObservations(
  engine: Engine,
  priv: PrivilegedSet,
  window?: FocusWindow,
): Promise<Observation[]> {
  const ctx = await buildObservationContext(engine, priv, window);
  const batches = await Promise.all(detectors.map((d) => d(engine, ctx)));
  const all: Observation[] = [];
  for (const batch of batches) {
    for (const o of batch) {
      if (normalizedSurprise(o) >= SURPRISE_FLOOR) all.push(o);
    }
  }

  // off-CPU is a signpost OUT of the CPU section, not a finding within it, so it
  // always sorts below every on-CPU analysis card regardless of score — the
  // robust form of "analysis outranks the pointer" (the surprise soft-cap alone
  // let a 100%-off-CPU thread edge past a real volume card).
  const offRank = (o: Observation) => (o.kind === 'offcpu' ? 1 : 0);
  all.sort((a, b) => {
    const ob = offRank(a) - offRank(b);
    if (ob !== 0) return ob;
    const sb = observationScore(b, ctx) - observationScore(a, ctx);
    if (sb !== 0) return sb;
    const cb = costShareOf(b, ctx) - costShareOf(a, ctx);
    if (cb !== 0) return cb;
    return KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind);
  });
  return all;
}

// ---- Small helpers ---------------------------------------------------------

function sanitizeId(name: string): string {
  return name.replace(/[^A-Za-z0-9_]/g, '_');
}

// Exemplar for a function card: land the user on a representative MOMENT of that
// function (median-ts sample, framed by its sched slice) rather than reopening
// the whole window. Carries the sample's utid so the feed can also frame that
// thread's row. Falls back to the passed window when no sample is found — never
// breaks the card. Resilient: any query failure yields the plain window.
async function functionExemplar(
  engine: Engine,
  fn: string,
  priv: PrivilegedSet,
  window: FocusWindow | undefined,
): Promise<ObservationExemplar> {
  let rep = null;
  try {
    rep = await loadRepresentativeSample(engine, fn, priv, window);
  } catch {
    rep = null;
  }
  if (rep === null) {
    return {label: `Show ${fn} in timeline`, window};
  }
  return {label: `Show ${fn} in timeline`, utid: rep.utid, window: rep.window};
}

function medianNs(values: ReadonlyArray<bigint>): bigint {
  if (values.length === 0) return 0n;
  const s = [...values].sort((a, b) => Number(a - b));
  const mid = s.length >> 1;
  if (s.length % 2 === 1) return s[mid];
  return (s[mid - 1] + s[mid]) / 2n;
}

function fmtMs(ns: bigint): string {
  return `${(Number(ns) / 1e6).toFixed(1)} ms`;
}
