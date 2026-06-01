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

// Routing for the Sismo page. The page has a domain selector (CPU / Latency /
// Memory) above a row of view-tabs; only CPU has multiple views today. Modeled
// on com.android.HeapDumpExplorer's nav_state: a small state object that maps
// to/from the page subpage so every domain+view is linkable and survives
// reload / back-forward.

export type SismoDomain = 'cpu' | 'latency' | 'memory';

// Views within the CPU domain, in funnel order matching the Overview blocks:
// overview → where your code spent time, as a Flamegraph and an expandable
// Calltree (the Overview's lead deep-dive) → Activity (the time-quantized zoom
// step toward the Timeline) → the remaining lens tabs, who → hardware → why.
// Latency/Memory have a single view today (their `view` is always 'overview').
// Non-'overview' keys are legacy-only routing: unreachable from CpuFeedView,
// kept solely because views/legacy/ still calls renderSeeAllLink with these
// literals. Collapse to 'overview' once views/legacy/ is excluded from the build.
export type CpuView =
  | 'overview'
  | 'flamegraph'
  | 'calltree'
  | 'activity'
  | 'threads'
  | 'cores'
  | 'bottleneck';

export interface SismoNav {
  readonly domain: SismoDomain;
  // Only meaningful for the CPU domain; latency/memory ignore it.
  readonly view: CpuView;
}

const DEFAULT_NAV: SismoNav = {domain: 'cpu', view: 'overview'};

export const CPU_VIEWS: ReadonlyArray<{key: CpuView; title: string}> = [
  {key: 'overview', title: 'Overview'},
  {key: 'flamegraph', title: 'Flamegraph'},
  {key: 'calltree', title: 'Calltree'},
  {key: 'activity', title: 'Activity'},
  {key: 'threads', title: 'Threads'},
  {key: 'cores', title: 'Cores'},
  {key: 'bottleneck', title: 'Bottleneck'},
];

interface DomainSpec {
  readonly key: SismoDomain;
  readonly title: string;
  readonly icon: string;
  // Parked while we focus on CPU; selectable but not actively developed.
  readonly deferred: boolean;
}

export const DOMAINS: ReadonlyArray<DomainSpec> = [
  {key: 'cpu', title: 'CPU', icon: 'memory', deferred: false},
  {key: 'latency', title: 'Latency', icon: 'speed', deferred: true},
  {key: 'memory', title: 'Memory', icon: 'memory_alt', deferred: true},
];

const CPU_VIEW_KEYS = new Set<string>(CPU_VIEWS.map((v) => v.key));

function isCpuView(s: string): s is CpuView {
  return CPU_VIEW_KEYS.has(s);
}

// Encodes nav as the page subpage (the part after `#!/sismo`). The CPU overview
// is the default and maps to the empty subpage so `#!/sismo` lands there.
function navToSubpage(nav: SismoNav): string {
  switch (nav.domain) {
    case 'cpu':
      return nav.view === 'overview' ? '' : `cpu/${nav.view}`;
    case 'latency':
      return 'latency';
    case 'memory':
      return 'memory';
  }
}

export function navToHash(nav: SismoNav): string {
  const sub = navToSubpage(nav);
  return sub ? `#!/sismo/${sub}` : '#!/sismo';
}

// Parses a page subpage back into nav. `subpage` may arrive with a leading
// slash (e.g. '/cpu/flamegraph'); unknown values fall back to the default.
export function subpageToNav(subpage: string | undefined): SismoNav {
  if (!subpage) return DEFAULT_NAV;
  const path = subpage.startsWith('/') ? subpage.slice(1) : subpage;
  if (path === '' || path === 'cpu' || path === 'cpu/overview') {
    return DEFAULT_NAV;
  }
  if (path === 'latency') return {domain: 'latency', view: 'overview'};
  if (path === 'memory') return {domain: 'memory', view: 'overview'};
  // CPU views, with or without the 'cpu/' prefix.
  let bare = path.startsWith('cpu/') ? path.slice('cpu/'.length) : path;
  // Back-compat: the pre-merge view names still resolve to their new homes so
  // old links keep working.
  const aliases: Record<string, CpuView> = {
    code: 'flamegraph',
    functions: 'calltree',
    microarch: 'bottleneck',
    efficiency: 'bottleneck',
    consumers: 'threads',
  };
  if (bare in aliases) bare = aliases[bare];
  if (isCpuView(bare)) return {domain: 'cpu', view: bare};
  return DEFAULT_NAV;
}
