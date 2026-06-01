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

import type {PrivilegedSet} from '../privileged_set';

// `IN (-1)` stands in for the unrepresentable `IN ()` so SQL stays valid
// when the privileged set is empty.
export function privInClause(priv: PrivilegedSet): string {
  if (priv.upids.length === 0) return 'IN (-1)';
  return `IN (${priv.upids.join(',')})`;
}

export function privNotInClause(priv: PrivilegedSet): string {
  if (priv.upids.length === 0) return 'NOT IN (-1)';
  return `NOT IN (${priv.upids.join(',')})`;
}

export function sampleScopePredicate(priv: PrivilegedSet): string {
  if (priv.upids.length === 0) return '';
  return `AND s.utid IN (
    SELECT utid FROM thread WHERE upid IN (${priv.upids.join(',')})
  )`;
}

// SQL expression resolving a stack_profile_frame's display name.
//
// Offline symbolization (the ModuleSymbols pass) writes resolved function
// names into `stack_profile_symbol` keyed by `symbol_set_id` and leaves
// `stack_profile_frame.name` NULL. Reading `.name` alone therefore shows
// every offline-symbolized sample as unsymbolised — so prefer the symbol
// table, then fall back to the frame name. For inlined frames a set has
// several rows; the lowest id is the innermost line. Mirrors the flamegraph
// stdlib's `demangle(coalesce(s.name, f.name))` (with raw-name fallbacks for
// the names `demangle` returns NULL on, i.e. already-demangled symbols).
//
// `frame` is the SQL alias of the stack_profile_frame row. `fallback` is the
// string used when nothing resolves; pass `null` to yield SQL NULL instead
// (for callers that build their own label, e.g. `binary+0xoffset`).
export function frameNameExpr(
  frame: string,
  fallback: string | null = '[unsymbolised]',
): string {
  const sym = `(
    SELECT sps.name FROM stack_profile_symbol sps
    WHERE sps.symbol_set_id = ${frame}.symbol_set_id
    ORDER BY sps.id LIMIT 1
  )`;
  const tail = fallback === null ? '' : `,\n    '${fallback}'`;
  return `coalesce(
    demangle(coalesce(${sym}, nullif(${frame}.name, ''))),
    ${sym},
    nullif(${frame}.name, '')${tail}
  )`;
}
