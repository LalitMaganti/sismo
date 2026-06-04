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

// What this recording captured — read once per trace and handed to every
// (sub-)domain's availability predicate (see nav_state DOMAIN_TREE). The
// unifying idea behind focus mode: a domain is available iff the recording
// carries what it needs. Latency needs sched; Memory needs heap; the survey CPU
// views need a timer timebase; a Cache focus needs a cache-focus recording.

import type {Trace} from '../../public/trace';
import {NUM} from '../../trace_processor/query_result';
import {EMPTY_FOCUS_META, loadFocusMeta, type FocusPreset} from './focus/focus_meta';

export type {FocusPreset};

export interface TraceCapabilities {
  // The sample-based CPU/time views need a *timer* timebase (cpu-clock /
  // cycles). A focus trace samples on an event, so its samples count events,
  // not time — the time profile would be a lie.
  readonly hasTimerTimebase: boolean;
  // Did a sampling data source run at all (perf_sample non-empty)?
  readonly hasSamples: boolean;
  // Scheduling data, for the Latency domain.
  readonly hasSched: boolean;
  // Heap data, for the Memory domain.
  readonly hasHeap: boolean;
  // If this is a focus trace, which preset it was recorded under (else null).
  // Drives which focus sub-domain is available and labels the others.
  readonly focusPreset: FocusPreset | null;
}

export const EMPTY_CAPABILITIES: TraceCapabilities = {
  hasTimerTimebase: false,
  hasSamples: false,
  hasSched: false,
  hasHeap: false,
  focusPreset: null,
};

export async function loadCapabilities(
  trace: Trace,
): Promise<TraceCapabilities> {
  const focus = await loadFocusMeta(trace.engine).catch(() => EMPTY_FOCUS_META);
  const hasSamples = await tableHasRows(trace, 'perf_sample');
  const hasSched = await tableHasRows(trace, 'sched');
  const hasHeap =
    (await tableHasRows(trace, 'heap_profile_allocation')) ||
    (await tableHasRows(trace, 'heap_graph_object'));
  // v1 trusts the recording's focus marker as the source of truth for the
  // timebase: a focus trace has an event timebase by construction, a survey
  // trace a timer. (A real perf_session timebase query can replace this later
  // without changing any predicate.)
  const hasTimerTimebase = hasSamples && focus.preset === null;
  return {
    hasTimerTimebase,
    hasSamples,
    hasSched,
    hasHeap,
    focusPreset: focus.preset,
  };
}

// True iff `table` exists and has at least one row. A missing table throws in
// trace_processor; the catch turns that into `false` so a trace lacking the
// data source degrades cleanly.
async function tableHasRows(trace: Trace, table: string): Promise<boolean> {
  try {
    const res = await trace.engine.query(
      `SELECT (SELECT count() FROM ${table} LIMIT 1) > 0 AS v`,
    );
    return res.firstRow({v: NUM}).v === 1;
  } catch {
    return false;
  }
}
