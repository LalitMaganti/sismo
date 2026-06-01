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
  LONG,
  NUM,
  NUM_NULL,
  STR,
  STR_NULL,
} from '../../../trace_processor/query_result';
import type {PrivilegedSet} from '../privileged_set';
import {frameNameExpr, sampleScopePredicate} from './sql';

// One node in the sampled call tree — a callsite (frame at a position in the
// stack), with its self samples (the leaf was here) and total samples (the leaf
// was anywhere in this subtree). The Calltree tab renders these as an
// expandable tree-table; `id`/`parentId` reconstruct the tree, `depth` is the
// stack depth (0 = root frame).
export interface CallTreeNode {
  id: number;
  parentId: number | null;
  depth: number;
  name: string;
  mappingName: string | null;
  selfSamples: number;
  totalSamples: number;
}

export interface CallTree {
  hasSamples: boolean;
  totalSamples: number;
  nodes: CallTreeNode[];
}

const EMPTY_CALL_TREE: CallTree = {
  hasSamples: false,
  totalSamples: 0,
  nodes: [],
};

// Aggregates the scoped CPU samples into a top-down call tree. Each sample's
// leaf callsite contributes 1 to that callsite's self count and to the total of
// every callsite on the path to the root, so a node's total is the size of its
// subtree. Privileged-scoped like the rest of the microarch queries.
export async function loadCallTree(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<CallTree> {
  const hasTable = await engine
    .query(`SELECT name FROM sqlite_master WHERE name = 'perf_sample' LIMIT 1`)
    .catch(() => undefined);
  if (hasTable === undefined || hasTable.numRows() === 0) {
    return EMPTY_CALL_TREE;
  }
  const scope = sampleScopePredicate(priv);
  const res = await engine.query(`
    WITH scoped AS (
      SELECT s.callsite_id AS cs
      FROM perf_sample s
      WHERE s.callsite_id IS NOT NULL ${scope}
    ),
    self_counts AS (
      SELECT cs, count() AS n FROM scoped GROUP BY cs
    ),
    -- Attribute each leaf's self count to the leaf and all its ancestors.
    walk(leaf, cur, n) AS (
      SELECT cs, cs, n FROM self_counts
      UNION ALL
      SELECT w.leaf, c.parent_id, w.n
      FROM walk w
      JOIN stack_profile_callsite c ON c.id = w.cur
      WHERE c.parent_id IS NOT NULL
    ),
    totals AS (
      SELECT cur AS cs, sum(n) AS total FROM walk GROUP BY cur
    )
    SELECT
      c.id AS id,
      c.parent_id AS parent_id,
      c.depth AS depth,
      ${frameNameExpr('f', '[unknown]')} AS name,
      spm.name AS mapping,
      coalesce(sc.n, 0) AS self_samples,
      t.total AS total_samples
    FROM totals t
    JOIN stack_profile_callsite c ON c.id = t.cs
    JOIN stack_profile_frame f ON f.id = c.frame_id
    LEFT JOIN stack_profile_mapping spm ON spm.id = f.mapping
    LEFT JOIN self_counts sc ON sc.cs = c.id
    ORDER BY t.total DESC
  `);
  const it = res.iter({
    id: NUM,
    parent_id: NUM_NULL,
    depth: NUM,
    name: STR,
    mapping: STR_NULL,
    self_samples: NUM,
    total_samples: NUM,
  });
  const nodes: CallTreeNode[] = [];
  let rootTotal = 0;
  for (; it.valid(); it.next()) {
    if (it.parent_id === null) rootTotal += it.total_samples;
    nodes.push({
      id: it.id,
      parentId: it.parent_id,
      depth: it.depth,
      name: it.name,
      mappingName: it.mapping,
      selfSamples: it.self_samples,
      totalSamples: it.total_samples,
    });
  }
  return {
    hasSamples: nodes.length > 0,
    totalSamples: rootTotal,
    nodes,
  };
}

// Detail-pane view rows. These power the whole-trace detail tab (detail_tab.ts)
// and are scoped to the privileged set when present, else the whole trace.

export interface HeaviestFunctionRow {
  name: string;
  samples: number;
  share: number;
}

export interface SampleListRow {
  ts: bigint;
  utid: number;
  tid: number | null;
  threadName: string;
  leaf: string;
}

export async function loadHeaviestFunctions(
  engine: Engine,
  priv: PrivilegedSet,
  limit = 100,
): Promise<HeaviestFunctionRow[]> {
  const scope = sampleScopePredicate(priv);
  // Self time: each sample's leaf frame (the callsite frame) is the function
  // executing at the sample instant. Group by symbol name, summing across the
  // mappings it appears in — the flat self-time view.
  const totalRes = await engine.query(`
    SELECT count() AS n FROM perf_sample s
    WHERE s.callsite_id IS NOT NULL ${scope}
  `);
  const total = totalRes.firstRow({n: NUM}).n;
  if (total === 0) return [];

  const res = await engine.query(`
    SELECT
      ${frameNameExpr('spf')} AS name,
      count(*) AS samples
    FROM perf_sample s
    JOIN stack_profile_callsite c ON c.id = s.callsite_id
    JOIN stack_profile_frame spf ON spf.id = c.frame_id
    WHERE s.callsite_id IS NOT NULL ${scope}
    GROUP BY 1
    ORDER BY samples DESC
    LIMIT ${limit}
  `);
  const rows: HeaviestFunctionRow[] = [];
  for (
    const it = res.iter({name: STR_NULL, samples: NUM});
    it.valid();
    it.next()
  ) {
    rows.push({
      name: it.name ?? '[unsymbolised]',
      samples: it.samples,
      share: it.samples / total,
    });
  }
  return rows;
}

export async function loadSampleList(
  engine: Engine,
  priv: PrivilegedSet,
  limit = 500,
): Promise<SampleListRow[]> {
  const scope = sampleScopePredicate(priv);
  const res = await engine.query(`
    SELECT
      s.ts AS ts,
      s.utid AS utid,
      th.tid AS tid,
      coalesce(th.name, '[utid ' || s.utid || ']') AS thread_name,
      ${frameNameExpr('spf')} AS leaf
    FROM perf_sample s
    JOIN thread th USING (utid)
    JOIN stack_profile_callsite c ON c.id = s.callsite_id
    JOIN stack_profile_frame spf ON spf.id = c.frame_id
    WHERE s.callsite_id IS NOT NULL ${scope}
    ORDER BY s.ts
    LIMIT ${limit}
  `);
  const rows: SampleListRow[] = [];
  for (
    const it = res.iter({
      ts: LONG,
      utid: NUM,
      tid: NUM_NULL,
      thread_name: STR_NULL,
      leaf: STR_NULL,
    });
    it.valid();
    it.next()
  ) {
    rows.push({
      ts: it.ts,
      utid: it.utid,
      tid: it.tid,
      threadName: it.thread_name ?? '<unknown>',
      leaf: it.leaf ?? '[unsymbolised]',
    });
  }
  return rows;
}
