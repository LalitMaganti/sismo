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

// Cross-trace view preferences for the CPU flamegraph. The flamegraph widget is
// stateless across traces by design; carrying a user's metric / colouring /
// breakdown / direction / filters from one trace to the next is a Sismo concern,
// so it lives here (localStorage) rather than in the shared widget.

import type {FlamegraphState, FlamegraphView} from '../../../widgets/flamegraph';

const STORAGE_KEY = 'dev.perfetto.Sismo.cpu.flamegraph.prefs.v1';

// Mirror of the widget's filter kinds. Persisted filters are validated against
// this on load so a hand-edited or stale entry can't poison the state.
type FilterKind =
  | 'SHOW_STACK'
  | 'HIDE_STACK'
  | 'SHOW_FROM_FRAME'
  | 'HIDE_FRAME'
  | 'OPTIONS';
const FILTER_KINDS: ReadonlySet<string> = new Set<FilterKind>([
  'SHOW_STACK',
  'HIDE_STACK',
  'SHOW_FROM_FRAME',
  'HIDE_FRAME',
  'OPTIONS',
]);

// The subset of FlamegraphState that makes sense to carry across traces. PIVOT
// is trace-specific (it names a frame), so it is not persisted — a pivot view
// degrades to top-down on save.
export interface FlamegraphPrefs {
  selectedMetricName?: string;
  colorBy?: string;
  breakdownBy?: string;
  direction?: 'TOP_DOWN' | 'BOTTOM_UP';
  filters?: ReadonlyArray<{kind: FilterKind; filter: string}>;
}

export function loadFlamegraphPrefs(): FlamegraphPrefs {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw === null) return {};
    const parsed = JSON.parse(raw) as unknown;
    if (typeof parsed !== 'object' || parsed === null) return {};
    const o = parsed as Record<string, unknown>;
    const direction =
      o.direction === 'BOTTOM_UP' || o.direction === 'TOP_DOWN'
        ? o.direction
        : undefined;
    return {
      selectedMetricName: str(o.selectedMetricName),
      colorBy: str(o.colorBy),
      breakdownBy: str(o.breakdownBy),
      direction,
      filters: parseFilters(o.filters),
    };
  } catch {
    return {};
  }
}

export function saveFlamegraphPrefs(prefs: FlamegraphPrefs): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs));
  } catch {
    // Storage unavailable or over quota — preferences are best-effort.
  }
}

// Derive the persistable subset from a full FlamegraphState.
export function prefsFromState(state: FlamegraphState): FlamegraphPrefs {
  return {
    selectedMetricName: state.selectedMetricName,
    colorBy: state.colorBy,
    breakdownBy: state.breakdownBy,
    direction: state.view.kind === 'BOTTOM_UP' ? 'BOTTOM_UP' : 'TOP_DOWN',
    filters: state.filters.map((f) => ({kind: f.kind, filter: f.filter})),
  };
}

// Overlay saved prefs onto a freshly-built FlamegraphState. The metric name is
// only honoured when it exists among the metrics actually built for this trace
// (a counter-weighted choice vanishes under a breakdown, and "Backend-bound
// slots" only appears once counters are confirmed) — otherwise we fall back to
// `defaultMetricName`, then to the first metric.
export function applyPrefs(
  state: FlamegraphState,
  prefs: FlamegraphPrefs,
  availableMetricNames: ReadonlySet<string>,
  defaultMetricName: string,
): FlamegraphState {
  const view: FlamegraphView =
    prefs.direction === 'BOTTOM_UP' ? {kind: 'BOTTOM_UP'} : {kind: 'TOP_DOWN'};
  const metric =
    prefs.selectedMetricName !== undefined &&
    availableMetricNames.has(prefs.selectedMetricName)
      ? prefs.selectedMetricName
      : availableMetricNames.has(defaultMetricName)
        ? defaultMetricName
        : state.selectedMetricName;
  return {
    ...state,
    selectedMetricName: metric,
    colorBy: prefs.colorBy ?? state.colorBy,
    breakdownBy: prefs.breakdownBy ?? state.breakdownBy,
    view,
    filters: prefs.filters !== undefined ? [...prefs.filters] : state.filters,
  };
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

function parseFilters(
  v: unknown,
): ReadonlyArray<{kind: FilterKind; filter: string}> | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: Array<{kind: FilterKind; filter: string}> = [];
  for (const item of v) {
    if (typeof item !== 'object' || item === null) continue;
    const {kind, filter} = item as Record<string, unknown>;
    if (typeof kind === 'string' && FILTER_KINDS.has(kind) && typeof filter === 'string') {
      out.push({kind: kind as FilterKind, filter});
    }
  }
  return out;
}
