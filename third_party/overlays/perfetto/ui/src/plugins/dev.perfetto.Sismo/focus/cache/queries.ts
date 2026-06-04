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

// Cache-focus SQL: the data-side facts the bespoke cache views are built on.
// A cache-focus trace samples on retired L3-miss loads, so every perf_sample is
// one miss, and perf_sample.data_symbol is the memory region the missed access
// landed in. These read that — misses by region, and the per-function region
// mix — none of which the CPU (cycles) views have any notion of.

import type {Engine} from '../../../../trace_processor/engine';
import {LONG, STR} from '../../../../trace_processor/query_result';
import {frameNameExpr, sampleScopePredicate} from '../../cpu_data/sql';
import type {PrivilegedSet} from '../../privileged_set';

// One memory region and the misses that hit it.
export interface RegionMisses {
  readonly region: string;
  readonly misses: number;
}

// A function and the memory it misses on: total misses plus the per-region
// split, ranked within the function (heaviest region first).
export interface CacheFunction {
  readonly name: string;
  readonly misses: number;
  readonly regions: ReadonlyArray<RegionMisses>;
}

// All data-attributed misses in scope — the denominator for "% of misses".
export async function loadTotalMisses(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<number> {
  const scope = sampleScopePredicate(priv);
  const res = await engine.query(`
    SELECT count(*) AS n FROM perf_sample s WHERE s.data_symbol IS NOT NULL ${scope}
  `);
  return Number(res.firstRow({n: LONG}).n);
}

// Total misses attributed to each memory region across the scope, ranked.
export async function loadRegionTotals(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<ReadonlyArray<RegionMisses>> {
  const scope = sampleScopePredicate(priv);
  const res = await engine.query(`
    SELECT s.data_symbol AS region, count(*) AS n
    FROM perf_sample s
    WHERE s.data_symbol IS NOT NULL ${scope}
    GROUP BY region
    ORDER BY n DESC
  `);
  const out: RegionMisses[] = [];
  for (const it = res.iter({region: STR, n: LONG}); it.valid(); it.next()) {
    out.push({region: it.region, misses: Number(it.n)});
  }
  return out;
}

// Functions ranked by the misses sampled in them (self, i.e. the leaf frame),
// each carrying the split of which memory region those misses hit. `limit` caps
// the number of functions returned (the tail is noise).
export async function loadCacheFunctions(
  engine: Engine,
  priv: PrivilegedSet,
  limit = 100,
): Promise<ReadonlyArray<CacheFunction>> {
  const scope = sampleScopePredicate(priv);
  const fn = frameNameExpr('f', '[unsymbolised]');
  // One row per (function, region); fold to per-function in JS so a function
  // carries its whole region mix. The leaf-frame join + GROUP BY mirrors the
  // self-attribution the functions table and source view use.
  const res = await engine.query(`
    SELECT ${fn} AS fn, s.data_symbol AS region, count(*) AS n
    FROM perf_sample s
    JOIN stack_profile_callsite c ON c.id = s.callsite_id
    JOIN stack_profile_frame f ON f.id = c.frame_id
    WHERE s.callsite_id IS NOT NULL AND s.data_symbol IS NOT NULL ${scope}
    GROUP BY fn, region
  `);
  const byFn = new Map<string, {misses: number; regions: Map<string, number>}>();
  for (const it = res.iter({fn: STR, region: STR, n: LONG}); it.valid(); it.next()) {
    const n = Number(it.n);
    let e = byFn.get(it.fn);
    if (e === undefined) byFn.set(it.fn, (e = {misses: 0, regions: new Map()}));
    e.misses += n;
    e.regions.set(it.region, (e.regions.get(it.region) ?? 0) + n);
  }
  const fns: CacheFunction[] = [];
  for (const [name, e] of byFn) {
    const regions = [...e.regions.entries()]
      .map(([region, misses]) => ({region, misses}))
      .sort((a, b) => b.misses - a.misses);
    fns.push({name, misses: e.misses, regions});
  }
  fns.sort((a, b) => b.misses - a.misses);
  return fns.slice(0, limit);
}
