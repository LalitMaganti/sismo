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

// Shared chrome + linking helpers for the Sismo detail pages (CPU, Latency, …).

import m from 'mithril';
import type {Trace} from '../../public/trace';
import {Anchor} from '../../widgets/anchor';
import {Button, ButtonVariant} from '../../widgets/button';
import {Card} from '../../widgets/card';
import {EmptyState} from '../../widgets/empty_state';
import {Icon} from '../../widgets/icon';
import {Intent} from '../../widgets/common';
import {Section} from '../../widgets/section';
import {Spinner} from '../../widgets/spinner';
import {Tooltip} from '../../widgets/tooltip';
import {Time} from '../../base/time';
import {LONG_NULL} from '../../trace_processor/query_result';
import {getThreadOrProcUri} from '../../public/utils';
import {navToHash, type CpuView, type SismoDomain} from './nav_state';
import type {PrivilegedSet} from './privileged_set';

// A navigable summary target: the time window and/or entities a stat was
// derived from. Carrying provenance is the whole point — any aggregate that
// knows where it came from can hand it here to open the timeline on it.
interface TimelineTarget {
  readonly timeRange?: {readonly start: bigint; readonly end: bigint};
  readonly upids?: ReadonlyArray<number>;
  readonly utids?: ReadonlyArray<number>;
  readonly cpus?: ReadonlyArray<number>;
}

// Opens the timeline focused on `target`: a time range + tracks makes an area
// selection over them; a range alone frames the window; tracks alone scroll the
// first into view.
export function revealInTimeline(trace: Trace, target: TimelineTarget): void {
  trace.navigate('#!/viewer');
  const uris = resolveTrackUris(trace, target);
  const {timeRange} = target;
  if (timeRange !== undefined) {
    const start = Time.fromRaw(timeRange.start);
    const end = Time.fromRaw(timeRange.end);
    if (uris.length > 0) {
      trace.selection.selectArea(
        {start, end, trackUris: uris},
        {scrollToSelection: true},
      );
    } else {
      trace.scrollTo({time: {start, end, behavior: 'focus'}});
    }
    return;
  }
  if (uris.length > 0) {
    trace.scrollTo({track: {uri: uris[0], expandGroup: true}});
  }
}

// Processes/threads resolve to their well-known URIs; CPUs are found by their
// track tag.
function resolveTrackUris(trace: Trace, target: TimelineTarget): string[] {
  const uris: string[] = [];
  for (const upid of target.upids ?? []) {
    uris.push(getThreadOrProcUri(upid, null));
  }
  for (const utid of target.utids ?? []) {
    uris.push(getThreadOrProcUri(null, utid));
  }
  for (const cpu of target.cpus ?? []) {
    const track = trace.tracks.findTrack((t) => t.tags?.cpu === cpu);
    if (track !== undefined) uris.push(track.uri);
  }
  return uris;
}

export function goToTimeline(
  trace: Trace,
  target?: {upid?: number; utid?: number},
): void {
  if (target === undefined) {
    trace.navigate('#!/viewer');
    return;
  }
  revealInTimeline(trace, {
    upids: target.upid !== undefined ? [target.upid] : undefined,
    utids: target.utid !== undefined ? [target.utid] : undefined,
  });
}

// The active span of a thread/process: the window of the trace where it was
// actually on-CPU or sampled. This is the "region of importance" a link should
// frame — dumping the user on a track at the current zoom hides where the work
// happened. Returns undefined when the entity has no sched/sample rows.
async function queryEntitySpan(
  trace: Trace,
  target: {upid?: number; utid?: number},
): Promise<{start: bigint; end: bigint} | undefined> {
  const utidClause =
    target.utid !== undefined
      ? `utid = ${target.utid}`
      : target.upid !== undefined
        ? `utid IN (SELECT utid FROM thread WHERE upid = ${target.upid})`
        : undefined;
  if (utidClause === undefined) return undefined;

  // sched gives the on-CPU span; perf_sample covers sample-only threads with no
  // scheduling data. Either source may be absent, so each is queried softly and
  // the union taken.
  const spanFrom = async (sql: string) => {
    try {
      const row = (await trace.engine.query(sql)).firstRow({
        lo: LONG_NULL,
        hi: LONG_NULL,
      });
      if (row.lo === null || row.hi === null || row.hi <= row.lo) {
        return undefined;
      }
      return {lo: row.lo, hi: row.hi};
    } catch {
      return undefined;
    }
  };
  const spans = [
    await spanFrom(
      `SELECT min(ts) AS lo, max(ts + dur) AS hi FROM sched WHERE ${utidClause}`,
    ),
    await spanFrom(
      `SELECT min(ts) AS lo, max(ts) AS hi FROM perf_sample WHERE ${utidClause}`,
    ),
  ].filter((s): s is {lo: bigint; hi: bigint} => s !== undefined);
  if (spans.length === 0) return undefined;
  const start = spans.reduce((a, s) => (s.lo < a ? s.lo : a), spans[0].lo);
  const end = spans.reduce((a, s) => (s.hi > a ? s.hi : a), spans[0].hi);
  return {start, end};
}

// Reveal a thread/process AND frame the window where it was active, so the link
// lands you on the region that matters rather than the current viewport. Falls
// back to a plain track reveal if the span can't be determined.
export function revealEntityWindow(
  trace: Trace,
  target: {upid?: number; utid?: number},
): void {
  const tracks = {
    upids: target.upid !== undefined ? [target.upid] : undefined,
    utids: target.utid !== undefined ? [target.utid] : undefined,
  };
  queryEntitySpan(trace, target)
    .then((span) => revealInTimeline(trace, {...tracks, timeRange: span}))
    .catch(() => revealInTimeline(trace, tracks));
}

// Switches the Sismo page to another domain, mirroring the in-page domain
// selector. Lets the triage block hand off to the Latency domain.
export function goToSismoDomain(trace: Trace, domain: SismoDomain): void {
  trace.navigate(navToHash({domain, view: 'overview'}));
}

// Switches to another CPU lens tab — the "see all →" jump from an Overview
// question block down into the full view that answers it.
function goToCpuView(trace: Trace, view: CpuView): void {
  trace.navigate(navToHash({domain: 'cpu', view}));
}

// A link-styled button that fires an in-app action on click — switch lens tab,
// open a detail tab, reveal on the timeline. Reads as a link, but the behaviour
// is a callback, not a URL navigation.
export function actionLink(
  label: string,
  icon: string,
  onclick: () => void,
): m.Children {
  return m(
    Anchor,
    {
      href: '#',
      icon,
      onclick: (e: Event) => {
        e.preventDefault();
        onclick();
      },
    },
    label,
  );
}

// A prominent call-to-action button for navigating between pages — the loud
// version of actionLink, for footers that send the user to a whole other view.
// `primary` is the filled accent button; `secondary` is outlined.
export function ctaButton(
  label: string,
  icon: string,
  onclick: () => void,
  variant: 'primary' | 'secondary' = 'primary',
): m.Children {
  return m(Button, {
    label,
    icon,
    variant:
      variant === 'primary' ? ButtonVariant.Filled : ButtonVariant.Outlined,
    intent: variant === 'primary' ? Intent.Primary : Intent.None,
    onclick,
  });
}

// "See all →" footer link into a lens tab.
export function renderSeeAllLink(
  trace: Trace,
  label: string,
  view: CpuView,
): m.Children {
  return m(
    Anchor,
    {
      href: navToHash({domain: 'cpu', view}),
      icon: 'arrow_forward',
      onclick: (e: Event) => {
        e.preventDefault();
        goToCpuView(trace, view);
      },
    },
    label,
  );
}

export function renderPrivilegedBanner(priv: PrivilegedSet): m.Children {
  if (priv.pids.length === 0) {
    return m(
      '.pf-sismo-page__priv-banner.pf-sismo-page__priv-banner--empty',
      m(Icon, {icon: 'info'}),
      " No profiled processes detected — sections below show the system undifferentiated. Record with `sismo record` to tag the processes you're profiling.",
    );
  }
  // Prefer process names; fall back to pids when names didn't resolve.
  const label =
    priv.labels.length > 0
      ? priv.labels.join(', ')
      : priv.pids.map((p) => `pid ${p}`).join(', ');
  return m(
    '.pf-sismo-page__priv-banner',
    m(Icon, {icon: 'star', filled: true}),
    ` Profiling ${label}`,
    priv.upids.length < priv.pids.length &&
      m(
        'span.pf-sismo-page__muted',
        ` (${priv.pids.length - priv.upids.length} not found in this trace)`,
      ),
  );
}

export function renderProcessLink(
  trace: Trace,
  name: string,
  pid: number | null,
  upid: number,
): m.Children {
  return m(
    Anchor,
    {
      href: '#!/viewer',
      onclick: (e: Event) => {
        e.preventDefault();
        revealEntityWindow(trace, {upid});
      },
    },
    name,
    pid !== null && m('span.pf-sismo-page__muted', ` (pid ${pid})`),
  );
}

export function renderThreadLink(
  trace: Trace,
  threadName: string,
  tid: number | null,
  utid: number,
): m.Children {
  return m(
    Anchor,
    {
      href: '#!/viewer',
      onclick: (e: Event) => {
        e.preventDefault();
        revealEntityWindow(trace, {utid});
      },
    },
    threadName,
    tid !== null && m('span.pf-sismo-page__muted', ` (tid ${tid})`),
  );
}

// A 0..1 proportion bar reusing the breakdown cell-bar styles, with an optional
// trailing label. Shared by the detail-page tables (splits, butterfly edges).
export function renderBar(frac: number, label?: string): m.Children {
  return m(
    '.pf-sismo-cellbar',
    m(
      '.pf-sismo-cellbar__track',
      m('.pf-sismo-cellbar__fill', {
        style: `width:${Math.min(100, Math.max(0, frac) * 100).toFixed(1)}%`,
      }),
    ),
    label !== undefined && m('span.pf-sismo-cellbar__pct', label),
  );
}

// A spinner-over-EmptyState placeholder used while a detail pane's query runs.
export function loadingBody(title: string): m.Children {
  return m(
    EmptyState,
    {icon: 'hourglass_empty', title},
    m(Spinner, {easing: true}),
  );
}

// One labelled number, with the metric's meaning behind a help tooltip. The
// scorecard primitive the Overview is built from.
export interface StatCard {
  readonly label: string;
  readonly value: string;
  readonly help?: string;
}

export function renderStatCard({label, value, help}: StatCard): m.Children {
  return m(
    Card,
    {className: 'pf-sismo-page__stat-card'},
    m(
      '.pf-sismo-page__stat-label',
      label,
      help !== undefined &&
        m(
          Tooltip,
          {
            trigger: m(Icon, {
              icon: 'help_outline',
              className: 'pf-sismo-page__help-icon',
            }),
          },
          help,
        ),
    ),
    m('.pf-sismo-page__stat-value', value),
  );
}

// An Overview "question block": the user's question as the heading, a one-line
// motivation, the evidence that answers it, and an optional footer of drill
// links. The whole page is a stack of these — the question is the unit, not the
// widget.
export function renderQuestionBlock(
  attrs: {
    readonly question: string;
    readonly why: string;
    readonly footer?: m.Children;
  },
  ...body: m.Children[]
): m.Children {
  return m(
    Section,
    {title: attrs.question, subtitle: attrs.why},
    body,
    attrs.footer !== undefined &&
      m('.pf-sismo-page__question-footer', attrs.footer),
  );
}
