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

import type {Engine} from '../../../trace_processor/engine';
import {
  LONG_NULL,
  NUM,
  NUM_NULL,
  STR_NULL,
} from '../../../trace_processor/query_result';
import type {PrivilegedSet} from '../privileged_set';
import {frameNameExpr, sampleScopePredicate} from './sql';

export interface HotSymbolRow {
  name: string;
  mappingName: string | null;
  samples: number;
  share: number;
}

export interface HotMappingRow {
  name: string;
  samples: number;
  share: number;
}

export interface MicroarchData {
  // True if perf_sample has any rows (with or without symbols). Lets the UI
  // distinguish "no sampler ran" from "sampler ran but symbols are missing".
  hasSamples: boolean;
  // True if at least one sample's leaf frame has a non-null name. If false
  // we have raw samples but symbolisation didn't resolve anything — likely
  // missing debuginfo / dSYMs.
  hasSymbols: boolean;
  // Total samples used as the denominator for `share` below. When the
  // privileged set is non-empty this counts only privileged threads.
  totalSamples: number;
  hotSymbols: HotSymbolRow[];
  hotMappings: HotMappingRow[];
}

// Empty microarch result used as a fallback when perf_sample is missing.
export const EMPTY_MICROARCH: MicroarchData = {
  hasSamples: false,
  hasSymbols: false,
  totalSamples: 0,
  hotSymbols: [],
  hotMappings: [],
};

export async function loadMicroarch(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<MicroarchData> {
  // perf_sample is only populated when a sampling data source ran (linux.perf
  // on Linux, sismo's mach_sampler on macOS). Missing table or empty table
  // both land in EMPTY_MICROARCH so the UI can render a "no samples" state.
  const hasTable = await engine
    .query(
      `SELECT name FROM sqlite_master WHERE name = 'perf_sample' LIMIT 1`,
    )
    .catch(() => undefined);
  if (hasTable === undefined || hasTable.numRows() === 0) {
    return EMPTY_MICROARCH;
  }

  // Privileged-scope clause used by every microarch query below.
  const scope =
    priv.upids.length > 0
      ? `AND s.utid IN (
           SELECT utid FROM thread WHERE upid IN (${priv.upids.join(',')})
         )`
      : '';

  const totalsRes = await engine.query(`
    SELECT
      (SELECT count() FROM perf_sample s
        WHERE s.callsite_id IS NOT NULL ${scope}
      ) AS total_with_stack,
      (SELECT count() FROM perf_sample s
        WHERE s.callsite_id IS NOT NULL ${scope}
          AND s.callsite_id IN (
            SELECT c.id
            FROM stack_profile_callsite c
            JOIN stack_profile_frame f ON f.id = c.frame_id
            -- Offline-symbolized frames carry a symbol_set_id with name NULL,
            -- so a name check alone misreports a symbolized trace as bare.
            WHERE f.symbol_set_id IS NOT NULL
              OR (f.name IS NOT NULL AND f.name != '')
          )
      ) AS total_with_symbol
  `);
  const totalsRow = totalsRes.firstRow({
    total_with_stack: NUM,
    total_with_symbol: NUM,
  });
  const totalSamples = totalsRow.total_with_stack;
  if (totalSamples === 0) return EMPTY_MICROARCH;
  const hasSymbols = totalsRow.total_with_symbol > 0;

  if (!hasSymbols) {
    return {
      hasSamples: true,
      hasSymbols: false,
      totalSamples,
      hotSymbols: [],
      hotMappings: [],
    };
  }

  const hotSymRes = await engine.query(`
    SELECT
      ${frameNameExpr('spf')} AS name,
      spm.name AS mapping_name,
      count(*) AS samples
    FROM perf_sample s
    JOIN stack_profile_callsite c ON c.id = s.callsite_id
    JOIN stack_profile_frame spf ON spf.id = c.frame_id
    LEFT JOIN stack_profile_mapping spm ON spm.id = spf.mapping
    WHERE s.callsite_id IS NOT NULL ${scope}
    GROUP BY 1, 2
    ORDER BY samples DESC
    LIMIT 20
  `);
  const hotSymbols: HotSymbolRow[] = [];
  for (
    const it = hotSymRes.iter({
      name: STR_NULL,
      mapping_name: STR_NULL,
      samples: NUM,
    });
    it.valid();
    it.next()
  ) {
    hotSymbols.push({
      name: it.name ?? '[unknown]',
      mappingName: it.mapping_name,
      samples: it.samples,
      share: it.samples / totalSamples,
    });
  }

  const hotMapRes = await engine.query(`
    SELECT
      coalesce(spm.name, '[unknown mapping]') AS name,
      count(*) AS samples
    FROM perf_sample s
    JOIN stack_profile_callsite c ON c.id = s.callsite_id
    JOIN stack_profile_frame spf ON spf.id = c.frame_id
    LEFT JOIN stack_profile_mapping spm ON spm.id = spf.mapping
    WHERE s.callsite_id IS NOT NULL ${scope}
    GROUP BY spm.name
    ORDER BY samples DESC
    LIMIT 20
  `);
  const hotMappings: HotMappingRow[] = [];
  for (
    const it = hotMapRes.iter({
      name: STR_NULL,
      samples: NUM,
    });
    it.valid();
    it.next()
  ) {
    hotMappings.push({
      name: it.name ?? '[unknown mapping]',
      samples: it.samples,
      share: it.samples / totalSamples,
    });
  }

  return {
    hasSamples: true,
    hasSymbols: true,
    totalSamples,
    hotSymbols,
    hotMappings,
  };
}

// ---- Microarchitecture: per-sample PMU follower counters ----------------
//
// Leader-sampling attaches a vector of hardware counter values (instructions,
// cycles, stalls, misses) to each CPU sample. trace_processor exposes them via
// the `linux.perf.counters` stdlib view `linux_perf_sample_with_counters`
// (one row per sample × counter); we pivot by counter name and attribute to the
// leaf frame to get IPC / stall / miss breakdowns per function.

// Counter catalog: the single place that assigns MEANING to the named hardware
// events the collector records. linux_bpf_capture.zig is purely mechanical — it
// records named perf events per ISA; this map is the contract that says what
// each name is *for*. Add a counter here (and as a candidate in the collector)
// and detection, totals and the TMA model below all pick it up. cpu-clock (the
// software timebase) is deliberately absent, so a sampling-only trace maps to no
// roles and reads as 'no-counters'.
type CounterRole =
  | 'cycles'
  | 'instructions'
  | 'cache-miss'
  | 'branch-miss'
  // Coarse cycle-stall split (generic perf events).
  | 'stall-frontend'
  | 'stall-backend'
  // ARM Top-Down slot/op events.
  | 'arm-retired'
  | 'arm-spec'
  | 'arm-slot-frontend'
  | 'arm-slot-backend'
  // Intel Top-Down: `intel-slots` is the MEASURED total-slots denominator (the
  // fixed Top-Down Slots counter); retired/fetch are the L1 numerators — each
  // ÷ slots is its fraction, so there's no issue-width constant.
  | 'intel-slots'
  | 'intel-retired'
  | 'intel-fetch-bubbles';

const COUNTER_ROLES = new Map<string, CounterRole>([
  ['cpu-cycles', 'cycles'],
  ['instructions', 'instructions'],
  ['cache-misses', 'cache-miss'],
  ['branch-misses', 'branch-miss'],
  ['stalled-cycles-frontend', 'stall-frontend'],
  ['stalled-cycles-backend', 'stall-backend'],
  ['op-retired', 'arm-retired'],
  ['op-spec', 'arm-spec'],
  ['stall-slot-frontend', 'arm-slot-frontend'],
  ['stall-slot-backend', 'arm-slot-backend'],
  ['slots', 'intel-slots'],
  ['topdown-slots-retired', 'intel-retired'],
  ['topdown-fetch-bubbles', 'intel-fetch-bubbles'],
]);

// Per-role counter totals for the in-scope set (per-thread max, summed over
// threads). A role is present iff its counter was recorded; the value may be 0
// if the (v)PMU returned zero, which the TMA strategies treat as unusable.
type RoleTotals = ReadonlyMap<CounterRole, number>;

// Usability of per-sample counters in this trace:
//  - 'no-counters': none recorded (sampling-only timebase).
//  - 'all-zero': recorded but reading zero — e.g. a VM whose vPMU isn't
//    counting. Worth saying explicitly rather than showing empty tables.
//  - 'ok': nonzero counters present.
type MicroarchState = 'no-counters' | 'all-zero' | 'ok';

export interface MicroarchFuncRow {
  name: string;
  mappingName: string | null;
  samples: number;
  instructions: number | null;
  cycles: number | null;
  ipc: number | null;
  // Stalled cycles as a fraction of this function's cycles.
  feStallPct: number | null;
  beStallPct: number | null;
}

export interface MicroarchCounters {
  state: MicroarchState;
  // Distinct in-scope samples carrying counters.
  totalSamples: number;
  // Counter totals keyed by role — the catalog turns recorded names into these.
  roles: RoleTotals;
  perFunc: MicroarchFuncRow[];
}

export async function loadMicroarchCounters(
  engine: Engine,
  priv: PrivilegedSet,
  limit = 100,
): Promise<MicroarchCounters> {
  await engine.query('INCLUDE PERFETTO MODULE linux.perf.counters;');
  const scope = sampleScopePredicate(priv);

  // Counter values are CUMULATIVE per thread: the BPF collector accumulates and
  // carries the running per-thread total on every sample, and the counters land
  // on `perf_thread_counter` tracks (reached via the `track` table — the legacy
  // CPU-scoped path used `perf_counter_track`, which is empty for BPF traces).
  // So a thread's total is its LAST = max reading, summed over threads; summing
  // over samples would triangular-overcount (~thousands×). Per-function uses the
  // consecutive-sample delta instead (see below). Verified against a real BPF
  // trace: per-thread-max matches the recorder's reported cycle totals.

  const samplesRes = await engine.query(`
    SELECT count(DISTINCT s.sample_id) AS n
    FROM linux_perf_sample_with_counters s
    WHERE s.callsite_id IS NOT NULL ${scope}
  `);
  const totalSamples = samplesRes.firstRow({n: NUM}).n;

  // Counter totals in long form: per-thread max (cumulative counters; see
  // above) summed over threads, one row per counter name. The catalog maps each
  // name to its role, so there's no per-counter SQL column to maintain.
  const totRes = await engine.query(`
    WITH pt AS (
      SELECT s.utid AS utid, t.name AS cname, max(s.counter_value) AS v
      FROM linux_perf_sample_with_counters s
      JOIN track t ON t.id = s.track_id
      WHERE s.callsite_id IS NOT NULL ${scope}
      GROUP BY s.utid, t.name
    )
    SELECT cname, sum(v) AS total FROM pt GROUP BY cname
  `);
  const roleMap = new Map<CounterRole, number>();
  for (
    const it = totRes.iter({cname: STR_NULL, total: NUM_NULL});
    it.valid();
    it.next()
  ) {
    const role = it.cname !== null ? COUNTER_ROLES.get(it.cname) : undefined;
    if (role !== undefined && it.total !== null) roleMap.set(role, it.total);
  }

  if (roleMap.size === 0) {
    return {state: 'no-counters', totalSamples, roles: roleMap, perFunc: []};
  }
  // Counters wired up but reading zero — the PMU isn't actually counting
  // (typical in a VM without a working vPMU). Nothing meaningful to break down.
  if (
    (roleMap.get('cycles') ?? 0) === 0 &&
    (roleMap.get('instructions') ?? 0) === 0
  ) {
    return {state: 'all-zero', totalSamples, roles: new Map(), perFunc: []};
  }

  // Per-function: cumulative counters can't be summed per callsite. Take the
  // delta between consecutive samples of the same thread+counter (the work done
  // in that interval) and credit it to the callstack sampled at the interval's
  // end. lag() per (utid, track) ordered by ts; the first sample of each series
  // has a NULL delta and drops out of the sums.
  const fnRes = await engine.query(`
    WITH d AS (
      SELECT
        s.callsite_id AS callsite_id,
        s.sample_id AS sample_id,
        t.name AS cname,
        s.counter_value - lag(s.counter_value) OVER (
          PARTITION BY s.utid, s.track_id ORDER BY s.ts
        ) AS dv
      FROM linux_perf_sample_with_counters s
      JOIN track t ON t.id = s.track_id
      WHERE s.callsite_id IS NOT NULL ${scope}
    )
    SELECT
      ${frameNameExpr('spf')} AS name,
      spm.name AS mapping_name,
      count(DISTINCT d.sample_id) AS samples,
      sum(CASE WHEN cname = 'instructions' THEN dv END) AS instructions,
      sum(CASE WHEN cname = 'cpu-cycles' THEN dv END) AS cycles,
      sum(CASE WHEN cname = 'stalled-cycles-frontend' THEN dv END) AS fe,
      sum(CASE WHEN cname = 'stalled-cycles-backend' THEN dv END) AS be
    FROM d
    JOIN stack_profile_callsite c ON c.id = d.callsite_id
    JOIN stack_profile_frame spf ON spf.id = c.frame_id
    LEFT JOIN stack_profile_mapping spm ON spm.id = spf.mapping
    GROUP BY 1, 2
    ORDER BY cycles IS NULL, cycles DESC
    LIMIT ${limit}
  `);
  const perFunc: MicroarchFuncRow[] = [];
  for (
    const it = fnRes.iter({
      name: STR_NULL,
      mapping_name: STR_NULL,
      samples: NUM,
      instructions: NUM_NULL,
      cycles: NUM_NULL,
      fe: NUM_NULL,
      be: NUM_NULL,
    });
    it.valid();
    it.next()
  ) {
    const cyc = it.cycles;
    perFunc.push({
      name: it.name ?? '[unsymbolised]',
      mappingName: it.mapping_name,
      samples: it.samples,
      instructions: it.instructions,
      cycles: cyc,
      ipc: it.instructions !== null && cyc ? it.instructions / cyc : null,
      feStallPct: it.fe !== null && cyc ? it.fe / cyc : null,
      beStallPct: it.be !== null && cyc ? it.be / cyc : null,
    });
  }
  return {state: 'ok', totalSamples, roles: roleMap, perFunc};
}

// ---- Top-Down (TMA) model -------------------------------------------------
//
// Built from the role totals by an ordered list of L1 *strategies*, most precise
// first; the first whose required roles are present wins. Adding a methodology
// is a new strategy; adding a counter is a new catalog entry — neither touches
// the rest. TODO(bottleneck): the slot widths are fixed defaults; detect per
// core (ARM via MIDR, Intel via family/model) when available.
const ARM_SLOT_WIDTH = 8;

type TmaBucketKey =
  | 'retiring'
  | 'bad-spec'
  | 'frontend'
  | 'backend'
  | 'not-stalled';

export interface TmaBucket {
  key: TmaBucketKey;
  label: string;
  frac: number;
}

export interface TmaModel {
  // 'true-l1' = slot accounting; 'coarse' = cycle-stall accounting (Frontend/
  // Backend stall + a lumped "not stalled"); 'none' = not enough counters for
  // any L1, vital signs only.
  tier: 'true-l1' | 'coarse' | 'none';
  buckets: TmaBucket[]; // empty when tier === 'none'
  dominant: TmaBucket | null;
  ipc: number | null;
  instructions: number | null;
  cycles: number | null;
  cacheMpki: number | null;
  branchMpki: number | null;
}

// An L1 methodology: given the role totals, either produce its buckets or bow
// out (null) so the next strategy is tried.
interface TmaStrategy {
  readonly tier: 'true-l1' | 'coarse';
  build(r: RoleTotals): TmaBucket[] | null;
}

const STRATEGIES: ReadonlyArray<TmaStrategy> = [
  // ARM slot accounting → the full four buckets (share of all issue slots,
  // slots = cycles × width).
  {
    tier: 'true-l1',
    build(r) {
      const cycles = r.get('cycles');
      const ret = r.get('arm-retired');
      const spec = r.get('arm-spec');
      const fe = r.get('arm-slot-frontend');
      const be = r.get('arm-slot-backend');
      if (!cycles || ret == null || spec == null || fe == null || be == null) {
        return null;
      }
      const slots = cycles * ARM_SLOT_WIDTH;
      // A bucket over 100% means the slot count is wrong (width mismatch) —
      // refuse rather than show a bogus split. TODO: detect width per core.
      if (ret / slots > 1 || fe / slots > 1 || be / slots > 1) return null;
      return normalize([
        {key: 'retiring', label: 'Retiring', frac: ret / slots},
        {key: 'bad-spec', label: 'Bad speculation', frac: (spec - ret) / slots},
        {key: 'frontend', label: 'Frontend bound', frac: fe / slots},
        {key: 'backend', label: 'Backend bound', frac: be / slots},
      ]);
    },
  },
  // Intel Top-Down: numerators divided by the MEASURED `slots` counter give the
  // fractions directly — total slots comes from the hardware, so no issue-width
  // assumption. Retiring + Frontend are the uop events; Backend is the remainder
  // (it absorbs Bad-Speculation, which needs the PERF_METRICS bad-spec event a
  // Skylake-spoofed guest reports as zero).
  {
    tier: 'true-l1',
    build(r) {
      const slots = r.get('intel-slots');
      const ret = r.get('intel-retired');
      const fe = r.get('intel-fetch-bubbles');
      if (!slots || ret == null || fe == null) return null;
      const retiring = ret / slots;
      const frontend = fe / slots;
      const backend = Math.max(0, 1 - retiring - frontend);
      return normalize([
        {key: 'retiring', label: 'Retiring', frac: retiring},
        {key: 'frontend', label: 'Frontend bound', frac: frontend},
        {key: 'backend', label: 'Backend bound', frac: backend},
      ]);
    },
  },
  // Coarse cycle-stall split → Retiring and Bad-Speculation can't be separated,
  // so they share the "not stalled" remainder.
  {
    tier: 'coarse',
    build(r) {
      const cycles = r.get('cycles');
      const fe = r.get('stall-frontend');
      const be = r.get('stall-backend');
      if (!cycles || (fe == null && be == null)) return null;
      const ff = (fe ?? 0) / cycles;
      const bf = (be ?? 0) / cycles;
      return [
        {key: 'not-stalled', label: 'Not stalled', frac: Math.max(0, 1 - ff - bf)},
        {key: 'frontend', label: 'Frontend stall', frac: ff},
        {key: 'backend', label: 'Backend stall', frac: bf},
      ];
    },
  },
];

function mpki(misses: number | null, instructions: number | null): number | null {
  if (misses === null || instructions === null || instructions === 0) return null;
  return (misses / instructions) * 1000;
}

function normalize(buckets: TmaBucket[]): TmaBucket[] {
  const sum = buckets.reduce((a, b) => a + Math.max(0, b.frac), 0);
  if (sum <= 0) return buckets;
  return buckets.map((b) => ({...b, frac: Math.max(0, b.frac) / sum}));
}

// Vital signs always; the deepest available L1 split when the counters allow.
// Returns null only when there's nothing to say (no cycles or instructions).
export function computeTma(roles: RoleTotals): TmaModel | null {
  const cycles = roles.get('cycles') ?? null;
  const instructions = roles.get('instructions') ?? null;
  if (cycles === null && instructions === null) return null;

  let tier: TmaModel['tier'] = 'none';
  let buckets: TmaBucket[] = [];
  for (const strat of STRATEGIES) {
    const b = strat.build(roles);
    if (b !== null) {
      tier = strat.tier;
      buckets = b;
      break;
    }
  }
  const dominant = buckets.length
    ? buckets.reduce((a, b) => (b.frac > a.frac ? b : a))
    : null;
  return {
    tier,
    buckets,
    dominant,
    ipc: instructions !== null && cycles ? instructions / cycles : null,
    instructions,
    cycles,
    cacheMpki: mpki(roles.get('cache-miss') ?? null, instructions),
    branchMpki: mpki(roles.get('branch-miss') ?? null, instructions),
  };
}

// Real cycles delivered, per thread and per process, from the eBPF cpu-cycles
// counter. The counter is cumulative per thread, so a thread's total is its max
// reading; processes sum their threads. This is the cpufreq-free replacement
// for the cpu_cycles (frequency × time) megacycles. Empty on traces without
// perf counters.
export interface RealCycles {
  byUtid: Map<number, bigint>;
  byUpid: Map<number, bigint>;
}

export async function loadRealCycles(engine: Engine): Promise<RealCycles> {
  const empty: RealCycles = {byUtid: new Map(), byUpid: new Map()};
  const has = await engine
    .query(`SELECT name FROM sqlite_master WHERE name = 'perf_sample' LIMIT 1`)
    .catch(() => undefined);
  if (has === undefined || has.numRows() === 0) return empty;
  try {
    await engine.query('INCLUDE PERFETTO MODULE linux.perf.counters;');
    const res = await engine.query(`
      WITH pt AS (
        SELECT s.utid AS utid, max(s.counter_value) AS cyc
        FROM linux_perf_sample_with_counters s
        JOIN track t ON t.id = s.track_id
        WHERE t.name = 'cpu-cycles' AND s.callsite_id IS NOT NULL
        GROUP BY s.utid
      )
      SELECT pt.utid AS utid, th.upid AS upid, pt.cyc AS cyc
      FROM pt JOIN thread th USING (utid)
    `);
    const byUtid = new Map<number, bigint>();
    const byUpid = new Map<number, bigint>();
    for (
      const it = res.iter({utid: NUM, upid: NUM_NULL, cyc: LONG_NULL});
      it.valid();
      it.next()
    ) {
      const cyc = it.cyc ?? 0n;
      byUtid.set(it.utid, cyc);
      if (it.upid !== null) {
        byUpid.set(it.upid, (byUpid.get(it.upid) ?? 0n) + cyc);
      }
    }
    return {byUtid, byUpid};
  } catch {
    return empty;
  }
}
