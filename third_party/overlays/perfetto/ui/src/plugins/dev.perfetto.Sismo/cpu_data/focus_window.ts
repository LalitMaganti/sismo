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

// The shared time-focus window: the slice of the trace every temporal CPU tab
// scopes itself to. It is set by the persistent focus strip (or the Activity
// board's brush) and threaded into the loaders, so "zoom into this region" is a
// universal gesture rather than a per-tab one. Undefined means the whole trace.

export interface FocusWindow {
  readonly start: bigint;
  readonly end: bigint;
}

// For point/sample rows (e.g. perf_sample): keep only those inside the window.
// Returns '' when there's no window, so callers can interpolate unconditionally.
export function tsRangeClause(
  window: FocusWindow | undefined,
  tsCol: string,
): string {
  if (window === undefined) return '';
  return ` AND ${tsCol} >= ${window.start} AND ${tsCol} < ${window.end}`;
}

// For duration-bearing slices (sched, thread_state): keep slices that overlap
// the window at all. Pair with clipDurExpr so the summed time is the part that
// actually falls inside.
export function overlapClause(
  window: FocusWindow | undefined,
  tsCol: string,
  durCol: string,
): string {
  if (window === undefined) return '';
  return ` AND ${tsCol} < ${window.end} AND ${tsCol} + ${durCol} > ${window.start}`;
}

// A slice's duration clipped to the window, so summing it gives the in-window
// runtime rather than the slice's whole length. Falls back to the raw duration
// column when there's no window.
export function clipDurExpr(
  window: FocusWindow | undefined,
  tsCol: string,
  durCol: string,
): string {
  if (window === undefined) return durCol;
  return (
    `(min(${tsCol} + ${durCol}, ${window.end}) - ` +
    `max(${tsCol}, ${window.start}))`
  );
}

// Stable identity for a window, for use as a Mithril key so a view reloads when
// the focus changes. 'all' is the whole-trace (undefined) case.
export function focusKey(window: FocusWindow | undefined): string {
  return window === undefined ? 'all' : `${window.start}-${window.end}`;
}
