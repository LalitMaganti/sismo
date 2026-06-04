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
import {NUM, NUM_NULL, STR_NULL} from '../../../trace_processor/query_result';
import type {PrivilegedSet} from '../privileged_set';
import {frameNameExpr, sampleScopePredicate} from './sql';
import {tsRangeClause, type FocusWindow} from './focus_window';

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
  window?: FocusWindow,
): Promise<MicroarchData> {
  // perf_sample is only populated when a sampling data source ran (linux.perf
  // on Linux, sismo's mach_sampler on macOS). Missing table or empty table
  // both land in EMPTY_MICROARCH so the UI can render a "no samples" state.
  const hasTable = await engine
    .query(`SELECT name FROM sqlite_master WHERE name = 'perf_sample' LIMIT 1`)
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
  const win = tsRangeClause(window, 's.ts');

  const totalsRes = await engine.query(`
    SELECT
      (SELECT count() FROM perf_sample s
        WHERE s.callsite_id IS NOT NULL ${scope}${win}
      ) AS total_with_stack,
      (SELECT count() FROM perf_sample s
        WHERE s.callsite_id IS NOT NULL ${scope}${win}
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
    WHERE s.callsite_id IS NOT NULL ${scope}${win}
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
    WHERE s.callsite_id IS NOT NULL ${scope}${win}
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
  // Per-function microarchitecture, derived by crediting each sample interval's
  // counter delta to the stack sampled at the interval's end, then running the
  // same computeTma() the whole-process bar uses. APPROXIMATE — see the note on
  // FUNC_TMA_MIN_SAMPLES. null when the function has too few samples to derive
  // anything stable (we show the sample count but no ratios).
  tma: TmaModel | null;
}

// Below this many samples a function's counter sums are too noisy to derive
// IPC/TMA/MPKI from — the per-interval deltas haven't averaged out — so we leave
// `tma` null rather than print a number that looks precise but isn't.
const FUNC_TMA_MIN_SAMPLES = 30;

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
  window?: FocusWindow,
): Promise<MicroarchCounters> {
  await engine.query('INCLUDE PERFETTO MODULE linux.perf.counters;');
  const scope = sampleScopePredicate(priv);
  const win = tsRangeClause(window, 's.ts');

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
    WHERE s.callsite_id IS NOT NULL ${scope}${win}
  `);
  const totalSamples = samplesRes.firstRow({n: NUM}).n;

  // Counter totals in long form, one row per counter name; the catalog maps
  // each name to its role. Whole-trace: per-thread max (cumulative counters;
  // see above) summed over threads. Windowed: the same consecutive-sample delta
  // accounting as the per-function breakdown, restricted to the window.
  const totQuery =
    window === undefined
      ? `
    WITH pt AS (
      SELECT s.utid AS utid, t.name AS cname, max(s.counter_value) AS v
      FROM linux_perf_sample_with_counters s
      JOIN track t ON t.id = s.track_id
      WHERE s.callsite_id IS NOT NULL ${scope}
      GROUP BY s.utid, t.name
    )
    SELECT cname, sum(v) AS total FROM pt GROUP BY cname`
      : `
    WITH d AS (
      SELECT
        t.name AS cname,
        s.ts AS ts,
        s.counter_value - lag(s.counter_value) OVER (
          PARTITION BY s.utid, s.track_id ORDER BY s.ts
        ) AS dv
      FROM linux_perf_sample_with_counters s
      JOIN track t ON t.id = s.track_id
      WHERE s.callsite_id IS NOT NULL ${scope}
    )
    SELECT cname, sum(CASE WHEN dv > 0 THEN dv ELSE 0 END) AS total
    FROM d WHERE 1${tsRangeClause(window, 'ts')} GROUP BY cname`;
  const totRes = await engine.query(totQuery);
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
        s.ts AS ts,
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
      sum(CASE WHEN cname = 'cpu-cycles' AND dv > 0 THEN dv END) AS cycles,
      sum(CASE WHEN cname = 'instructions' AND dv > 0 THEN dv END) AS instructions,
      sum(CASE WHEN cname = 'cache-misses' AND dv > 0 THEN dv END) AS cache_miss,
      sum(CASE WHEN cname = 'branch-misses' AND dv > 0 THEN dv END) AS branch_miss,
      sum(CASE WHEN cname = 'stalled-cycles-frontend' AND dv > 0 THEN dv END) AS stall_fe,
      sum(CASE WHEN cname = 'stalled-cycles-backend' AND dv > 0 THEN dv END) AS stall_be,
      sum(CASE WHEN cname = 'op-retired' AND dv > 0 THEN dv END) AS arm_retired,
      sum(CASE WHEN cname = 'op-spec' AND dv > 0 THEN dv END) AS arm_spec,
      sum(CASE WHEN cname = 'stall-slot-frontend' AND dv > 0 THEN dv END) AS arm_fe,
      sum(CASE WHEN cname = 'stall-slot-backend' AND dv > 0 THEN dv END) AS arm_be,
      sum(CASE WHEN cname = 'slots' AND dv > 0 THEN dv END) AS intel_slots,
      sum(CASE WHEN cname = 'topdown-slots-retired' AND dv > 0 THEN dv END) AS intel_retired,
      sum(CASE WHEN cname = 'topdown-fetch-bubbles' AND dv > 0 THEN dv END) AS intel_fe
    FROM d
    JOIN stack_profile_callsite c ON c.id = d.callsite_id
    JOIN stack_profile_frame spf ON spf.id = c.frame_id
    LEFT JOIN stack_profile_mapping spm ON spm.id = spf.mapping
    WHERE 1${tsRangeClause(window, 'd.ts')}
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
      cycles: NUM_NULL,
      instructions: NUM_NULL,
      cache_miss: NUM_NULL,
      branch_miss: NUM_NULL,
      stall_fe: NUM_NULL,
      stall_be: NUM_NULL,
      arm_retired: NUM_NULL,
      arm_spec: NUM_NULL,
      arm_fe: NUM_NULL,
      arm_be: NUM_NULL,
      intel_slots: NUM_NULL,
      intel_retired: NUM_NULL,
      intel_fe: NUM_NULL,
    });
    it.valid();
    it.next()
  ) {
    // Same role catalog as the whole-process totals, so the per-function bar
    // uses the identical computeTma strategy + self-guards (a bucket >100%
    // bails). Only roles whose counter was recorded go in.
    const roles = new Map<CounterRole, number>();
    const put = (role: CounterRole, v: number | null) => {
      if (v !== null) roles.set(role, v);
    };
    put('cycles', it.cycles);
    put('instructions', it.instructions);
    put('cache-miss', it.cache_miss);
    put('branch-miss', it.branch_miss);
    put('stall-frontend', it.stall_fe);
    put('stall-backend', it.stall_be);
    put('arm-retired', it.arm_retired);
    put('arm-spec', it.arm_spec);
    put('arm-slot-frontend', it.arm_fe);
    put('arm-slot-backend', it.arm_be);
    put('intel-slots', it.intel_slots);
    put('intel-retired', it.intel_retired);
    put('intel-fetch-bubbles', it.intel_fe);
    perFunc.push({
      name: it.name ?? '[unsymbolised]',
      mappingName: it.mapping_name,
      samples: it.samples,
      tma: it.samples >= FUNC_TMA_MIN_SAMPLES ? computeTma(roles) : null,
    });
  }
  return {state: 'ok', totalSamples, roles: roleMap, perFunc};
}

// One function's microarchitecture, set against the workload it ran in. The
// per-function side is leaf-attributed and APPROXIMATE (timer-sampled, no PEBS):
// the counter delta over each sample interval is credited to whatever stack was
// caught at the interval's end. So treat `self` as the shape of this function's
// execution, not a precise per-instruction measurement — its value is the
// CONTRAST with `baseline` (the whole profiled set), which tells you whether
// this function runs hotter/stallier than the workload average.
// One time bucket of a function's rates — the SHAPE of how it executed over the
// trace, to sit beside the aggregate `self`. Each rate is null when that bucket
// caught too little of the function (or the wrong counters) to form one.
export interface UarchSeriesPoint {
  readonly ipc: number | null;
  readonly cacheMpki: number | null;
  readonly branchMpki: number | null;
}

// Equal time buckets the per-function rate series is split into across the whole
// trace. A round count that reads as a compact sparkline.
const UARCH_SERIES_BUCKETS = 32;

export interface FunctionMicroarch {
  state: MicroarchState;
  // Samples (delta intervals) attributed to this function's leaf.
  samples: number;
  // null when counters are absent/zero or the function has too few samples for
  // a stable derivation (we don't print a precise-looking number from noise).
  self: TmaModel | null;
  baseline: TmaModel | null;
  // Per-time-bucket rates (length UARCH_SERIES_BUCKETS), oldest first; empty when
  // counters are absent. Noisier than `self` by construction — it's a shape.
  series: UarchSeriesPoint[];
}

export async function loadFunctionMicroarch(
  engine: Engine,
  priv: PrivilegedSet,
  name: string,
): Promise<FunctionMicroarch> {
  await engine.query('INCLUDE PERFETTO MODULE linux.perf.counters;');
  const scope = sampleScopePredicate(priv);
  const esc = name.replace(/'/g, "''");
  const nameExpr = frameNameExpr('spf', null);

  // Baseline = whole-scope role totals: per-thread max (cumulative counters),
  // summed over threads — the same accounting the headline TMA bar uses.
  const baseRes = await engine.query(`
    WITH pt AS (
      SELECT s.utid AS utid, t.name AS cname, max(s.counter_value) AS v
      FROM linux_perf_sample_with_counters s
      JOIN track t ON t.id = s.track_id
      WHERE s.callsite_id IS NOT NULL ${scope}
      GROUP BY s.utid, t.name
    )
    SELECT cname, sum(v) AS total FROM pt GROUP BY cname
  `);
  const baseRoles = new Map<CounterRole, number>();
  for (
    const it = baseRes.iter({cname: STR_NULL, total: NUM_NULL});
    it.valid();
    it.next()
  ) {
    const role = it.cname !== null ? COUNTER_ROLES.get(it.cname) : undefined;
    if (role !== undefined && it.total !== null) baseRoles.set(role, it.total);
  }
  if (baseRoles.size === 0) {
    return {
      state: 'no-counters',
      samples: 0,
      self: null,
      baseline: null,
      series: [],
    };
  }
  if (
    (baseRoles.get('cycles') ?? 0) === 0 &&
    (baseRoles.get('instructions') ?? 0) === 0
  ) {
    return {
      state: 'all-zero',
      samples: 0,
      self: null,
      baseline: null,
      series: [],
    };
  }

  // Self = per-function role sums via the consecutive-sample delta, restricted
  // to samples whose leaf frame is this function (same method as the per-row
  // breakdown in loadMicroarchCounters, filtered to one name and unlimited).
  const selfRes = await engine.query(`
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
    SELECT count(DISTINCT d.sample_id) AS samples, ${ROLE_SUMS}
    FROM d
    JOIN stack_profile_callsite c ON c.id = d.callsite_id
    JOIN stack_profile_frame spf ON spf.id = c.frame_id
    WHERE ${nameExpr} = '${esc}'
  `);
  const sr = selfRes.firstRow({
    samples: NUM,
    cycles: NUM_NULL,
    instructions: NUM_NULL,
    cache_miss: NUM_NULL,
    branch_miss: NUM_NULL,
    stall_fe: NUM_NULL,
    stall_be: NUM_NULL,
    arm_retired: NUM_NULL,
    arm_spec: NUM_NULL,
    arm_fe: NUM_NULL,
    arm_be: NUM_NULL,
    intel_slots: NUM_NULL,
    intel_retired: NUM_NULL,
    intel_fe: NUM_NULL,
  });
  const self =
    sr.samples >= FUNC_TMA_MIN_SAMPLES ? computeTma(rowRoles(sr)) : null;

  // Rate over time: the same per-interval deltas credited to this function's
  // leaf, summed into equal time buckets across the trace, then turned into the
  // per-bucket IPC / miss rates in TS. A bucket that caught nothing of the
  // function stays null (rendered as a gap, not a zero).
  const seriesRes = await engine.query(`
    WITH b AS (SELECT start_ts AS s0, end_ts AS e0 FROM trace_bounds),
    d AS (
      SELECT
        s.callsite_id AS callsite_id,
        s.ts AS ts,
        t.name AS cname,
        s.counter_value - lag(s.counter_value) OVER (
          PARTITION BY s.utid, s.track_id ORDER BY s.ts
        ) AS dv
      FROM linux_perf_sample_with_counters s
      JOIN track t ON t.id = s.track_id
      WHERE s.callsite_id IS NOT NULL ${scope}
    )
    SELECT
      min(${UARCH_SERIES_BUCKETS - 1}, cast((d.ts - b.s0) * ${UARCH_SERIES_BUCKETS}
        / nullif(b.e0 - b.s0, 0) AS INT)) AS bucket,
      sum(CASE WHEN cname = 'cpu-cycles' AND dv > 0 THEN dv END) AS cycles,
      sum(CASE WHEN cname = 'instructions' AND dv > 0 THEN dv END) AS instructions,
      sum(CASE WHEN cname = 'cache-misses' AND dv > 0 THEN dv END) AS cache_miss,
      sum(CASE WHEN cname = 'branch-misses' AND dv > 0 THEN dv END) AS branch_miss
    FROM d
    JOIN stack_profile_callsite c ON c.id = d.callsite_id
    JOIN stack_profile_frame spf ON spf.id = c.frame_id
    CROSS JOIN b
    WHERE ${nameExpr} = '${esc}'
    GROUP BY bucket
  `);
  const series: UarchSeriesPoint[] = Array.from(
    {length: UARCH_SERIES_BUCKETS},
    () => ({ipc: null, cacheMpki: null, branchMpki: null}),
  );
  for (
    const it = seriesRes.iter({
      bucket: NUM_NULL,
      cycles: NUM_NULL,
      instructions: NUM_NULL,
      cache_miss: NUM_NULL,
      branch_miss: NUM_NULL,
    });
    it.valid();
    it.next()
  ) {
    if (it.bucket === null) continue;
    // The last sample (ts === end_ts) lands one past the last bucket; fold it in.
    const i = Math.min(UARCH_SERIES_BUCKETS - 1, Math.max(0, it.bucket));
    const instr = it.instructions;
    series[i] = {
      ipc:
        instr !== null && it.cycles !== null && it.cycles !== 0
          ? instr / it.cycles
          : null,
      cacheMpki: mpki(it.cache_miss, instr),
      branchMpki: mpki(it.branch_miss, instr),
    };
  }

  return {
    state: 'ok',
    samples: sr.samples,
    self,
    baseline: computeTma(baseRoles),
    series,
  };
}

// Counter-delta sums by role, shared by the per-function breakdown in
// loadMicroarchCounters and the self totals in loadFunctionMicroarch. `dv` is the
// consecutive-sample delta from the `d` CTE. Cumulative counters can step
// backwards across a counter reset or a cross-CPU migration mid-series (lag is
// partitioned by utid+track, not CPU), so a `dv > 0` guard drops those negative
// artifacts — matching the windowed totals, which clamp the same way. Without it
// a single backward step silently subtracts real work.
const ROLE_SUMS = `
  sum(CASE WHEN cname = 'cpu-cycles' AND dv > 0 THEN dv END) AS cycles,
  sum(CASE WHEN cname = 'instructions' AND dv > 0 THEN dv END) AS instructions,
  sum(CASE WHEN cname = 'cache-misses' AND dv > 0 THEN dv END) AS cache_miss,
  sum(CASE WHEN cname = 'branch-misses' AND dv > 0 THEN dv END) AS branch_miss,
  sum(CASE WHEN cname = 'stalled-cycles-frontend' AND dv > 0 THEN dv END) AS stall_fe,
  sum(CASE WHEN cname = 'stalled-cycles-backend' AND dv > 0 THEN dv END) AS stall_be,
  sum(CASE WHEN cname = 'op-retired' AND dv > 0 THEN dv END) AS arm_retired,
  sum(CASE WHEN cname = 'op-spec' AND dv > 0 THEN dv END) AS arm_spec,
  sum(CASE WHEN cname = 'stall-slot-frontend' AND dv > 0 THEN dv END) AS arm_fe,
  sum(CASE WHEN cname = 'stall-slot-backend' AND dv > 0 THEN dv END) AS arm_be,
  sum(CASE WHEN cname = 'slots' AND dv > 0 THEN dv END) AS intel_slots,
  sum(CASE WHEN cname = 'topdown-slots-retired' AND dv > 0 THEN dv END) AS intel_retired,
  sum(CASE WHEN cname = 'topdown-fetch-bubbles' AND dv > 0 THEN dv END) AS intel_fe`;

function rowRoles(it: {
  cycles: number | null;
  instructions: number | null;
  cache_miss: number | null;
  branch_miss: number | null;
  stall_fe: number | null;
  stall_be: number | null;
  arm_retired: number | null;
  arm_spec: number | null;
  arm_fe: number | null;
  arm_be: number | null;
  intel_slots: number | null;
  intel_retired: number | null;
  intel_fe: number | null;
}): Map<CounterRole, number> {
  const roles = new Map<CounterRole, number>();
  const put = (role: CounterRole, v: number | null) => {
    if (v !== null) roles.set(role, v);
  };
  put('cycles', it.cycles);
  put('instructions', it.instructions);
  put('cache-miss', it.cache_miss);
  put('branch-miss', it.branch_miss);
  put('stall-frontend', it.stall_fe);
  put('stall-backend', it.stall_be);
  put('arm-retired', it.arm_retired);
  put('arm-spec', it.arm_spec);
  put('arm-slot-frontend', it.arm_fe);
  put('arm-slot-backend', it.arm_be);
  put('intel-slots', it.intel_slots);
  put('intel-retired', it.intel_retired);
  put('intel-fetch-bubbles', it.intel_fe);
  return roles;
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
      if (
        cycles === undefined ||
        cycles === 0 ||
        ret == null ||
        spec == null ||
        fe == null ||
        be == null
      ) {
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
      if (slots === undefined || slots === 0 || ret == null || fe == null) {
        return null;
      }
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
      if (cycles === undefined || cycles === 0 || (fe == null && be == null)) {
        return null;
      }
      const ff = (fe ?? 0) / cycles;
      const bf = (be ?? 0) / cycles;
      return [
        {
          key: 'not-stalled',
          label: 'Not stalled',
          frac: Math.max(0, 1 - ff - bf),
        },
        {key: 'frontend', label: 'Frontend stall', frac: ff},
        {key: 'backend', label: 'Backend stall', frac: bf},
      ];
    },
  },
];

function mpki(
  misses: number | null,
  instructions: number | null,
): number | null {
  if (misses === null || instructions === null || instructions === 0)
    return null;
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
    ipc:
      instructions !== null && cycles !== null && cycles !== 0
        ? instructions / cycles
        : null,
    instructions,
    cycles,
    cacheMpki: mpki(roles.get('cache-miss') ?? null, instructions),
    branchMpki: mpki(roles.get('branch-miss') ?? null, instructions),
  };
}
