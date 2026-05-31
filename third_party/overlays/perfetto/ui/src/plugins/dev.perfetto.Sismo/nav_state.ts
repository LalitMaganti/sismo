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

// Views within the CPU domain, in display order. Latency/Memory have a single
// view today (their `view` is always 'overview').
export type CpuView =
  | 'overview'
  | 'flamegraph'
  | 'functions'
  | 'microarch'
  | 'cores'
  | 'consumers';

export interface SismoNav {
  readonly domain: SismoDomain;
  // Only meaningful for the CPU domain; latency/memory ignore it.
  readonly view: CpuView;
}

export const DEFAULT_NAV: SismoNav = {domain: 'cpu', view: 'overview'};

export const CPU_VIEWS: ReadonlyArray<{key: CpuView; title: string}> = [
  {key: 'overview', title: 'Overview'},
  {key: 'flamegraph', title: 'Flamegraph'},
  {key: 'functions', title: 'Functions'},
  {key: 'microarch', title: 'Microarchitecture'},
  {key: 'cores', title: 'Cores'},
  {key: 'consumers', title: 'Consumers'},
];

export interface DomainSpec {
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
export function navToSubpage(nav: SismoNav): string {
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
  const bare = path.startsWith('cpu/') ? path.slice('cpu/'.length) : path;
  if (isCpuView(bare)) return {domain: 'cpu', view: bare};
  return DEFAULT_NAV;
}
