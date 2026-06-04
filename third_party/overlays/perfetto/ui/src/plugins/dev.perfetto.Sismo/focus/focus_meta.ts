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
import {NUM_NULL, STR_NULL} from '../../../trace_processor/query_result';

// The five CPU-microarchitecture focus presets. A focus trace samples on the
// event named by its preset (e.g. `cache` samples on L3 misses) rather than a
// timer, so it answers one question precisely at the cost of the broad views.
export type FocusPreset = 'cache' | 'branch' | 'frontend';

const FOCUS_PRESETS: ReadonlySet<string> = new Set<FocusPreset>([
  'cache',
  'branch',
  'frontend',
]);

// What a focus recording declares about itself: which preset it used, whether it
// actually got PEBS precision, and the process/function it zoomed in on.
// `preset === null` means this is a survey trace (the default) — every focus
// sub-domain is then unavailable.
export interface FocusMeta {
  readonly preset: FocusPreset | null;
  // True only when the recording genuinely sampled with PEBS (0-skid IP). A
  // focus trace on a host without PEBS still records, but isn't precise — the
  // source viewer must keep its skid caveat.
  readonly precise: boolean;
  readonly focusPid: number | null;
  readonly focusFunc: string | null;
}

export const EMPTY_FOCUS_META: FocusMeta = {
  preset: null,
  precise: false,
  focusPid: null,
  focusFunc: null,
};

// Focus metadata rides on the same sidecar marker as the privileged pids — see
// privileged_set.ts and the emit site in src/sismo_privileged_marker.zig. Both
// are the same temporary hack and get deleted together when a real JSON-in-zip
// sidecar lands.
const MARKER_SLICE_NAME = 'sismo_temporary_privileged_pid_marker';

export async function loadFocusMeta(engine: Engine): Promise<FocusMeta> {
  // trace_processor namespaces TrackEvent debug_annotations under `debug.`;
  // accept the bare keys too as a fallback. The marker is a single instant
  // event, so MAX collapses the (≤1) matching rows per key.
  const res = await engine.query(`
    SELECT
      MAX(CASE WHEN args.key IN ('debug.focus_preset', 'focus_preset')
               THEN args.string_value END) AS preset,
      MAX(CASE WHEN args.key IN ('debug.focus_precise', 'focus_precise')
               THEN CAST(args.int_value AS INTEGER) END) AS precise,
      MAX(CASE WHEN args.key IN ('debug.focus_pid', 'focus_pid')
               THEN CAST(args.int_value AS INTEGER) END) AS focus_pid,
      MAX(CASE WHEN args.key IN ('debug.focus_func', 'focus_func')
               THEN args.string_value END) AS focus_func
    FROM slice
    JOIN args USING (arg_set_id)
    WHERE slice.name = '${MARKER_SLICE_NAME}'
  `);
  const row = res.firstRow({
    preset: STR_NULL,
    precise: NUM_NULL,
    focus_pid: NUM_NULL,
    focus_func: STR_NULL,
  });
  const preset =
    row.preset !== null && FOCUS_PRESETS.has(row.preset)
      ? (row.preset as FocusPreset)
      : null;
  return {
    preset,
    precise: row.precise === 1,
    focusPid: row.focus_pid,
    focusFunc: row.focus_func,
  };
}
