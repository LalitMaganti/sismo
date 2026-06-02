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

// The caller/callee "butterfly" for one function — VTune's Caller/Callee view.
// Edges are weighted by the samples flowing THROUGH the focus function:
//   - callers: each immediate caller gets the inclusive weight of the focus's
//     call sites reached through it ("who drives its cost").
//   - callees: each immediate callee gets the inclusive weight of its own
//     subtree beneath the focus ("where its inclusive cost goes").
// Call sites are merged by resolved name, so a recursive function appears as its
// own caller/callee — the panel says so rather than hiding it.

import type {Engine} from '../../../trace_processor/engine';
import {NUM, NUM_NULL, STR_NULL} from '../../../trace_processor/query_result';
import type {PrivilegedSet} from '../privileged_set';
import {frameNameExpr, sampleScopePredicate} from './sql';
import {SPLIT_LIMIT} from './entity_detail';

// One side of the butterfly: another function, and the samples flowing on the
// edge between it and the focus (as a share of the focus's inclusive samples).
export interface ButterflyEdge {
  readonly name: string;
  readonly mapping: string | null;
  readonly samples: number;
  readonly share: number;
}

export interface Butterfly {
  readonly name: string;
  // Leaf == focus (its own on-CPU cost).
  readonly selfSamples: number;
  // Stack passes through the focus anywhere — the denominator for edge shares.
  readonly inclusiveSamples: number;
  // All in-scope samples.
  readonly scopeSamples: number;
  readonly callers: ReadonlyArray<ButterflyEdge>;
  readonly callees: ReadonlyArray<ButterflyEdge>;
}

export async function loadButterfly(
  engine: Engine,
  priv: PrivilegedSet,
  name: string,
): Promise<Butterfly> {
  const scope = sampleScopePredicate(priv);
  const esc = name.replace(/'/g, "''");
  const nameExpr = frameNameExpr('f', null);

  // The focus's call sites, then every callsite at/under them: a sample is
  // "through" the focus iff its leaf callsite is in `descendants`.
  const matchCte = `
      matchcs AS (
        SELECT c.id AS id
        FROM stack_profile_callsite c
        JOIN stack_profile_frame f ON f.id = c.frame_id
        WHERE ${nameExpr} = '${esc}'
      )`;
  const descCte = `
      descendants(id) AS (
        SELECT id FROM matchcs
        UNION
        SELECT c.id FROM stack_profile_callsite c
        JOIN descendants d ON c.parent_id = d.id
      )`;

  const totals = await engine.query(`
    WITH RECURSIVE
    ${matchCte},
    ${descCte}
    SELECT
      (SELECT count(*) FROM perf_sample s
        WHERE s.callsite_id IS NOT NULL ${scope}) AS scope_samples,
      (SELECT count(*) FROM perf_sample s
        JOIN stack_profile_callsite c ON c.id = s.callsite_id
        JOIN stack_profile_frame f ON f.id = c.frame_id
        WHERE ${nameExpr} = '${esc}' ${scope}) AS self_samples,
      (SELECT count(*) FROM perf_sample s
        WHERE s.callsite_id IN (SELECT id FROM descendants) ${scope}) AS inclusive
  `);
  const tr = totals.firstRow({
    scope_samples: NUM,
    self_samples: NUM_NULL,
    inclusive: NUM,
  });
  const inclusiveSamples = tr.inclusive;
  const denom = inclusiveSamples > 0 ? inclusiveSamples : 1;

  const callers =
    inclusiveSamples > 0 ? await loadCallers(engine, esc, scope, denom) : [];
  const callees =
    inclusiveSamples > 0 ? await loadCallees(engine, esc, scope, denom) : [];

  return {
    name,
    selfSamples: tr.self_samples ?? 0,
    inclusiveSamples,
    scopeSamples: tr.scope_samples,
    callers,
    callees,
  };
}

// Callers: for each focus call site, attribute the inclusive weight of its
// subtree to its immediate parent's resolved name. `su` is the recursive-CTE
// self-alias (kept distinct from the perf_sample alias `s` the scope predicate
// binds to).
async function loadCallers(
  engine: Engine,
  esc: string,
  scope: string,
  denom: number,
): Promise<ButterflyEdge[]> {
  const nameExpr = frameNameExpr('f', null);
  const parentName = frameNameExpr('pf');
  const res = await engine.query(`
    WITH RECURSIVE
      matchcs AS (
        SELECT c.id AS id
        FROM stack_profile_callsite c
        JOIN stack_profile_frame f ON f.id = c.frame_id
        WHERE ${nameExpr} = '${esc}'
      ),
      parents AS (
        SELECT
          m.id AS mc_id,
          ${parentName} AS name,
          spm.name AS mapping
        FROM matchcs m
        JOIN stack_profile_callsite c ON c.id = m.id
        JOIN stack_profile_callsite pc ON pc.id = c.parent_id
        JOIN stack_profile_frame pf ON pf.id = pc.frame_id
        LEFT JOIN stack_profile_mapping spm ON spm.id = pf.mapping
        WHERE c.parent_id IS NOT NULL
      ),
      sub(mc_id, id) AS (
        SELECT id, id FROM matchcs
        UNION
        SELECT su.mc_id, c.id
        FROM stack_profile_callsite c
        JOIN sub su ON c.parent_id = su.id
      )
    SELECT p.name AS name, p.mapping AS mapping, count(*) AS samples
    FROM parents p
    JOIN sub ON sub.mc_id = p.mc_id
    JOIN perf_sample s ON s.callsite_id = sub.id
    WHERE s.callsite_id IS NOT NULL ${scope}
    GROUP BY 1, 2
    ORDER BY samples DESC
    LIMIT ${SPLIT_LIMIT}
  `);
  return collectEdges(res, denom);
}

// Callees: for each immediate child of a focus call site, attribute the
// inclusive weight of the child's subtree to the child's resolved name.
async function loadCallees(
  engine: Engine,
  esc: string,
  scope: string,
  denom: number,
): Promise<ButterflyEdge[]> {
  const nameExpr = frameNameExpr('f', null);
  const kidName = frameNameExpr('kf');
  const res = await engine.query(`
    WITH RECURSIVE
      matchcs AS (
        SELECT c.id AS id
        FROM stack_profile_callsite c
        JOIN stack_profile_frame f ON f.id = c.frame_id
        WHERE ${nameExpr} = '${esc}'
      ),
      kids AS (
        SELECT
          c.id AS kid_id,
          ${kidName} AS name,
          spm.name AS mapping
        FROM stack_profile_callsite c
        JOIN matchcs m ON c.parent_id = m.id
        JOIN stack_profile_frame kf ON kf.id = c.frame_id
        LEFT JOIN stack_profile_mapping spm ON spm.id = kf.mapping
      ),
      sub(kid_id, id) AS (
        SELECT kid_id, kid_id FROM kids
        UNION
        SELECT su.kid_id, c.id
        FROM stack_profile_callsite c
        JOIN sub su ON c.parent_id = su.id
      )
    SELECT k.name AS name, k.mapping AS mapping, count(*) AS samples
    FROM kids k
    JOIN sub ON sub.kid_id = k.kid_id
    JOIN perf_sample s ON s.callsite_id = sub.id
    WHERE s.callsite_id IS NOT NULL ${scope}
    GROUP BY 1, 2
    ORDER BY samples DESC
    LIMIT ${SPLIT_LIMIT}
  `);
  return collectEdges(res, denom);
}

function collectEdges(
  res: Awaited<ReturnType<Engine['query']>>,
  denom: number,
): ButterflyEdge[] {
  const edges: ButterflyEdge[] = [];
  for (
    const it = res.iter({name: STR_NULL, mapping: STR_NULL, samples: NUM});
    it.valid();
    it.next()
  ) {
    edges.push({
      name: it.name ?? '[unsymbolised]',
      mapping: it.mapping,
      samples: it.samples,
      share: it.samples / denom,
    });
  }
  return edges;
}
