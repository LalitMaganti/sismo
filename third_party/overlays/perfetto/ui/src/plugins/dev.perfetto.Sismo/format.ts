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

import type {Trace} from '../../public/trace';
import {formatDuration} from '../../components/time_utils';

// Routes through perfetto's formatter so the user's timecode-format setting
// (e.g. "show seconds") applies on this page too.
export function fmtDuration(trace: Trace, ns: bigint | null): string {
  if (ns === null) return '—';
  return formatDuration(trace, ns);
}

export function fmtPercent(frac: number | null, digits = 1): string {
  if (frac === null || !isFinite(frac)) return '—';
  return `${(frac * 100).toFixed(digits)}%`;
}

export function fmtCount(n: number | bigint | null): string {
  if (n === null) return '—';
  return Number(n).toLocaleString();
}

export function fmtFreqKhz(khz: bigint | null): string {
  if (khz === null) return '—';
  const v = Number(khz);
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(2)} GHz`;
  if (v >= 1_000) return `${(v / 1_000).toFixed(0)} MHz`;
  return `${v} kHz`;
}

export function fmtMegacycles(m: bigint | null): string {
  if (m === null) return '—';
  return fmtMegacyclesNum(Number(m));
}

// Same as fmtMegacycles but accepts a plain number — useful for derived
// quantities (peak cycle budget) that aren't naturally bigint.
export function fmtMegacyclesNum(v: number | null): string {
  if (v === null || !isFinite(v)) return '—';
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(2)} Tcyc`;
  if (v >= 1_000) return `${(v / 1_000).toFixed(2)} Gcyc`;
  return `${v.toFixed(0)} Mcyc`;
}

// Used for chart axis ticks, which can't handle bigints.
export function fmtDurationNs(ns: number): string {
  if (!isFinite(ns)) return '—';
  const abs = Math.abs(ns);
  if (abs >= 1e9) return `${(ns / 1e9).toFixed(abs >= 1e10 ? 0 : 1)}s`;
  if (abs >= 1e6) return `${(ns / 1e6).toFixed(abs >= 1e7 ? 0 : 1)}ms`;
  if (abs >= 1e3) return `${(ns / 1e3).toFixed(abs >= 1e4 ? 0 : 1)}µs`;
  return `${ns.toFixed(0)}ns`;
}
