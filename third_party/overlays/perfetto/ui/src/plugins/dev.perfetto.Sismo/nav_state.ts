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
// Memory, with a collapsed Focus-modes group under CPU) above a row of
// view-tabs; only CPU has multiple views today. Modeled on
// com.android.HeapDumpExplorer's nav_state: a small state object that maps
// to/from the page subpage so every domain+view is linkable and survives
// reload / back-forward.

import type {FocusPreset, TraceCapabilities} from './capabilities';

export type SismoDomain = 'cpu' | 'latency' | 'memory';

// The focus sub-domains are CPU-microarchitecture lenses, not top-level peers,
// so they ride on the 'cpu' domain with a `focus` discriminator rather than
// extending SismoDomain. The key set matches the recording presets.
export type FocusKey = FocusPreset;

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
  // Set ⇒ a CPU focus sub-domain (Cache/Branch/…); `view` is ignored then.
  readonly focus?: FocusKey;
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

// What to show when a (sub-)domain isn't available on the trace: the headline,
// a copyable `sismo record …` line that enables it, and — for focus modes — the
// mutual-exclusion cost (enabling one swaps the timebase and removes the rest).
export interface UnavailableInfo {
  readonly headline: string;
  readonly enableCmd: string;
  readonly cost?: string;
}

// A selectable leaf in the domain tree: where it routes, how it's labelled, and
// the capability predicate + refusal copy that decide whether it's live.
export interface DomainNode {
  readonly nav: SismoNav;
  readonly title: string;
  readonly icon: string;
  // Parked while we focus on CPU; selectable but not actively developed.
  readonly deferred?: boolean;
  readonly isAvailable: (caps: TraceCapabilities) => boolean;
  readonly unavailable: UnavailableInfo;
}

// A group in the selector tree. A top-level group (the CPU section) renders
// inline under a section header; a nested group (the focus lenses under CPU)
// renders as a collapsed submenu so the lenses don't clutter the default view.
export interface DomainGroup {
  readonly title: string;
  readonly icon: string;
  readonly children: ReadonlyArray<DomainTreeItem>;
}

export type DomainTreeItem = DomainNode | DomainGroup;

export function isGroup(item: DomainTreeItem): item is DomainGroup {
  return (item as DomainGroup).children !== undefined;
}

// One focus leaf. Available iff the trace was recorded under this preset; its
// refusal copy carries the mutual-exclusion warning since a focus recording
// samples on an event, not a timer.
function focusNode(
  key: FocusKey,
  title: string,
  icon: string,
  samplesOn: string,
): DomainNode {
  return {
    nav: {domain: 'cpu', view: 'overview', focus: key},
    title,
    icon,
    isAvailable: (c) => c.focusPreset === key,
    unavailable: {
      headline: `${title} focus — not available on this trace`,
      enableCmd: `sismo record --focus ${key} --pid <PID> -- ./workload`,
      cost:
        `A focus recording ${samplesOn}, so the CPU time profile, Latency ` +
        'and Memory views are unavailable on that trace.',
    },
  };
}

// The cause-specific CPU focus lenses — each samples *precisely* (PEBS) on a
// retirement event. (No "stalls" or "backend" lens: both are TMA counter
// buckets, not sampleable events. "Make the survey precise" is a property of the
// default overview; "backend-bound" is a slots formula whose memory half is the
// Cache lens and whose core-bound half has no precise event.)
const FOCUS_NODES: ReadonlyArray<DomainNode> = [
  focusNode('cache', 'Cache', 'memory', 'samples on L3/LLC load misses'),
  focusNode('branch', 'Branch', 'call_split', 'samples on retired branch mispredicts'),
  focusNode('frontend', 'Frontend', 'input', 'samples on frontend resteers / iTLB misses'),
];

// The general CPU view (survey): the broad profile built from timer-sampled
// stacks AND scheduling, the counter set, etc. — not just a time histogram.
// Available only on a *timer* timebase, so a focus trace correctly refuses it
// (and vice-versa). Sits as the first child of the CPU group, above the lenses.
const CPU_SURVEY_NODE: DomainNode = {
  nav: {domain: 'cpu', view: 'overview'},
  title: 'Overview',
  icon: 'analytics',
  isAvailable: (c) => c.hasTimerTimebase,
  unavailable: {
    headline: 'CPU overview — not available on this trace',
    enableCmd: 'sismo record -- ./workload',
    cost:
      'This trace samples on an event, not a timer, so its samples count ' +
      'events rather than time. Record a survey trace for the general profile.',
  },
};

// The whole selector tree. The CPU section nests the time profile and the focus
// lenses (Cache/Branch/…) together — they're all CPU views, the survey by timer
// and the focuses by event. Latency and Memory are parked ("(soon)") but still
// capability-gated.
// The focus lenses, collapsed into a submenu under CPU so the default view shows
// just the time profile.
const FOCUS_GROUP: DomainGroup = {
  title: 'Focus lenses',
  icon: 'center_focus_strong',
  children: FOCUS_NODES,
};

export const DOMAIN_TREE: ReadonlyArray<DomainTreeItem> = [
  {title: 'CPU', icon: 'memory', children: [CPU_SURVEY_NODE, FOCUS_GROUP]},
  {
    nav: {domain: 'latency', view: 'overview'},
    title: 'Latency',
    icon: 'speed',
    deferred: true,
    // Needs sched AND a survey trace: v1 is strictly one-mode, so a focus trace
    // (which carries sched too) still refuses the generic domains.
    isAvailable: (c) => c.hasSched && c.focusPreset === null,
    unavailable: {
      headline: 'Latency — not available on this trace',
      enableCmd: 'sismo record -- ./workload',
    },
  },
  {
    nav: {domain: 'memory', view: 'overview'},
    title: 'Memory',
    icon: 'memory_alt',
    deferred: true,
    isAvailable: (c) => c.hasHeap && c.focusPreset === null,
    unavailable: {
      headline: 'Memory — not available on this trace',
      enableCmd: 'sismo record --heap -- ./workload',
    },
  },
];

// Flattened leaves (recursively, through nested groups), for routing/lookup
// that doesn't care about grouping.
function flattenNodes(
  items: ReadonlyArray<DomainTreeItem>,
): ReadonlyArray<DomainNode> {
  return items.flatMap((item) =>
    isGroup(item) ? flattenNodes(item.children) : [item],
  );
}
export const DOMAIN_NODES: ReadonlyArray<DomainNode> = flattenNodes(DOMAIN_TREE);

export function navEquals(a: SismoNav, b: SismoNav): boolean {
  return a.domain === b.domain && a.view === b.view && a.focus === b.focus;
}

// The tree leaf a nav points at (the active node), or undefined for a nav no
// leaf claims (treated as the default CPU node by callers).
export function findNode(nav: SismoNav): DomainNode | undefined {
  return DOMAIN_NODES.find((n) => navEquals(n.nav, nav));
}

const CPU_VIEW_KEYS = new Set<string>(CPU_VIEWS.map((v) => v.key));

function isCpuView(s: string): s is CpuView {
  return CPU_VIEW_KEYS.has(s);
}

const FOCUS_KEYS: ReadonlySet<string> = new Set<FocusKey>([
  'cache',
  'branch',
  'frontend',
]);

// Encodes nav as the page subpage (the part after `#!/sismo`). The CPU overview
// is the default and maps to the empty subpage so `#!/sismo` lands there.
function navToSubpage(nav: SismoNav): string {
  switch (nav.domain) {
    case 'cpu':
      if (nav.focus) return `cpu/focus/${nav.focus}`;
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
  // Focus sub-domains: cpu/focus/<key>.
  if (bare.startsWith('focus/')) {
    const key = bare.slice('focus/'.length);
    if (FOCUS_KEYS.has(key)) {
      return {domain: 'cpu', view: 'overview', focus: key as FocusKey};
    }
    return DEFAULT_NAV;
  }
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
