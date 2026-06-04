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

// A hint shown under the Cache-misses weighting on "How were cycles spent": that
// flamegraph is sampled on *time*, so its per-stack misses are approximate. The
// hint offers the exact alternative — re-record focused on cache misses (PEBS),
// which pins each sampled miss to the source line and data address — and hands
// over the rerun command pre-sized with a --sample-density so the rerun yields a
// useful sample count instead of a handful.
//
// The only estimate it makes is the density, justified by comparing the default
// vs scaled sample counts (so the multiplier reconciles for a reader: default x
// density = scaled). It states a capability, not a verdict — it appears next to a
// cache figure because that's the figure it sharpens, not because the workload
// *is* cache-bound.

import m from 'mithril';
import type {Engine} from '../../../trace_processor/engine';
import {Icon} from '../../../widgets/icon';
import {loadMicroarchCounters} from '../cpu_data';
import {fmtMetric} from '../format';
import type {PrivilegedSet} from '../privileged_set';

// Mirror of the `cache` preset's default sampler period in focus_presets.zig
// (events per sample). Only used to *estimate* how many samples a default-density
// focus rerun would yield, so a little drift here just nudges the suggested
// density — it never affects a real recording.
const DEFAULT_CACHE_PERIOD = 2003;

// The sample count a focus rerun should aim for: enough that hot lines carry tens
// of samples, not single digits. The density is chosen to land near this.
const TARGET_FOCUS_SAMPLES = 4000;

// Starting density to suggest when no cache-miss counter was recorded, so the
// rerun can't be sized from this trace — a concrete first guess beats "to taste".
const UNSIZED_DENSITY = 8;

// Sampling density only ever needs to be a round, memorable number — the target
// is itself approximate. Snap to a power of two in [1, 64]; 1 means the preset
// default already lands near the target, so no flag is needed.
function niceDensity(raw: number): number {
  if (!(raw > 1.5)) return 1;
  const pow = Math.round(Math.log2(Math.min(64, raw)));
  return Math.min(64, Math.max(2, 2 ** pow));
}

export interface FocusSuggestion {
  // Suggested --sample-density (1 = preset default is enough). Always >= 1.
  readonly density: number;
  // Estimated samples the rerun would capture at the DEFAULT density, and at the
  // suggested density. null when no cache-miss counter was recorded (can't size
  // the rerun from this trace). estScaled / estDefault == density, by
  // construction, so the suggested multiplier reconciles for a reader.
  readonly estDefault: number | null;
  readonly estScaled: number | null;
}

export async function loadFocusSuggestion(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<FocusSuggestion> {
  // Only the role totals are needed; ask for the smallest per-function set.
  const mc = await loadMicroarchCounters(engine, priv, 1);
  const misses = mc.state === 'ok' ? (mc.roles.get('cache-miss') ?? null) : null;
  if (misses === null || misses <= 0) {
    return {density: UNSIZED_DENSITY, estDefault: null, estScaled: null};
  }
  const estDefault = misses / DEFAULT_CACHE_PERIOD;
  const density = niceDensity(TARGET_FOCUS_SAMPLES / estDefault);
  return {density, estDefault, estScaled: estDefault * density};
}

function rerunCmd(density: number): string {
  const densityFlag = density > 1 ? ` --sample-density ${density}` : '';
  return `sismo record --focus cache${densityFlag} -- <your command>`;
}

// The sizing note under the command: justify the suggested density by comparing
// what the default vs the scaled run would capture (sample counts, not the raw
// miss total — those reconcile against the multiplier, the miss total doesn't).
function sizingNote(s: FocusSuggestion): string {
  if (s.estDefault === null || s.estScaled === null) {
    return (
      'No cache-miss counter was recorded, so this is a starting point — ' +
      `raise --sample-density past ${s.density} if the rerun captures too few ` +
      'samples, lower it if it captures too many.'
    );
  }
  if (s.density === 1) {
    return (
      `At the default density this run yields ~${fmtMetric(s.estScaled)} ` +
      'samples — plenty without oversampling.'
    );
  }
  return (
    `At the default density this run yields only ~${fmtMetric(s.estDefault)} ` +
    `samples; --sample-density ${s.density} raises that to ~${fmtMetric(s.estScaled)}.`
  );
}

// One self-contained box — a quiet bordered callout with an icon, a one-line
// lead, the copyable rerun command, and the sizing note. Used verbatim wherever a
// cache figure is shown sampled-on-time (the cache flamegraph weighting, the
// function Microarchitecture pane), so the "approximate here, exact via focus"
// affordance reads the same everywhere.
export function renderCacheFocusSuggestion(s: FocusSuggestion): m.Children {
  return m(
    '.pf-sismo-focus',
    m(Icon, {icon: 'center_focus_strong', className: 'pf-sismo-focus__icon'}),
    m(
      '.pf-sismo-focus__text',
      m(
        '.pf-sismo-focus__lead',
        'Sampled on time, so these are approximate. Re-record focused on cache ' +
          'misses to pin each to its exact source line and data address:',
      ),
      m('code.pf-sismo-focus__cmd', rerunCmd(s.density)),
      m(
        '.pf-sismo-focus__note',
        'Swap ',
        m('code', '<your command>'),
        ' for however you launch the workload. ',
        sizingNote(s),
      ),
    ),
  );
}
