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

import m from 'mithril';
import type {Trace} from '../../public/trace';
import {TrackNode} from '../../public/workspace';
import {SliceTrack} from '../../components/tracks/slice_track';
import {SourceDataset} from '../../trace_processor/dataset';
import {LONG, NUM, STR_NULL} from '../../trace_processor/query_result';
import type {Engine} from '../../trace_processor/engine';
import {materialColorScheme} from '../../components/colorizer';
import {Time} from '../../base/time';
import type {time} from '../../base/time';
import type {TimeScale} from '../../base/time_scale';
import {frameNameExpr} from './cpu_data/sql';
import type {
  TrackRenderContext,
  TrackRenderer,
  TrackMouseEvent,
  SnapPoint,
} from '../../public/track';
import type {
  AreaSelection,
  TrackEventDetails,
  TrackEventSelection,
} from '../../public/selection';
import {areaSelectionsEqual} from '../../public/selection';
import type {TrackEventDetailsPanel} from '../../public/details_panel';
import type {VerticalBounds} from '../../base/geom';
import type {SourceDataset as SourceDatasetType} from '../../trace_processor/dataset';
import {FlamegraphPanel} from '../../components/flamegraph_panel';
import type {QueryFlamegraphMetric} from '../../components/query_flamegraph';
import {Flamegraph, type FlamegraphState} from '../../widgets/flamegraph';
import type {PrivilegedSet} from './privileged_set';

const STACK_TABLE = 'sismo_priv_stack_slices';
const TICKS_TABLE = 'sismo_priv_sample_ticks';

const SISMO_STACK_TRACK_KIND = 'SismoStackTimeline';

const STACK_SLICE_SCHEMA = {
  id: NUM,
  ts: LONG,
  dur: LONG,
  utid: NUM,
  depth: NUM,
  name: STR_NULL,
  mapping_name: STR_NULL,
  rel_pc: LONG,
} as const;

// Display label for a stack frame. Symbolised frames use their name; for
// unsymbolised frames (no debug info — common for stripped binaries) fall back
// to `binary+0xoffset` rather than rendering an unreadable blank slice.
function frameLabel(row: {
  name: string | null;
  mapping_name: string | null;
  rel_pc: bigint;
}): string {
  if (row.name) return row.name;
  const off = `0x${row.rel_pc.toString(16)}`;
  const base = row.mapping_name?.split('/').pop();
  return base ? `${base}+${off}` : off;
}

async function userTableExists(trace: Trace, name: string): Promise<boolean> {
  // CREATE PERFETTO TABLE registers in sqlite_master, not perfetto_tables —
  // verified by issuing CREATE PERFETTO TABLE foo and querying both catalogs.
  const res = await trace.engine.query(
    `SELECT name FROM sqlite_master WHERE name = '${name}'`,
  );
  return res.numRows() > 0;
}

export async function setupStackTimelineTables(
  trace: Trace,
  priv: PrivilegedSet,
): Promise<void> {
  if (priv.upids.length === 0) return;
  const upidList = priv.upids.join(',');

  if (!(await userTableExists(trace, STACK_TABLE))) {
    await createStackTable(trace, upidList);
  }
  if (!(await userTableExists(trace, TICKS_TABLE))) {
    await createTicksTable(trace, upidList);
  }
}

async function createStackTable(trace: Trace, upidList: string): Promise<void> {
  await trace.engine.query(`
    CREATE PERFETTO TABLE ${STACK_TABLE} AS
    WITH RECURSIVE
      priv_samples AS (
        SELECT
          s.id, s.ts, s.utid, s.callsite_id,
          row_number() OVER (PARTITION BY s.utid ORDER BY s.ts) AS sample_idx,
          lead(s.ts) OVER (PARTITION BY s.utid ORDER BY s.ts) AS slot_end
        FROM perf_sample s
        JOIN thread USING (utid)
        WHERE thread.upid IN (${upidList})
          AND s.callsite_id IS NOT NULL
      ),
      leaves AS (SELECT DISTINCT callsite_id AS leaf FROM priv_samples),
      ancestors(leaf, current, depth_from_leaf) AS (
        SELECT leaf, leaf, 0 FROM leaves
        UNION ALL
        SELECT a.leaf, c.parent_id, a.depth_from_leaf + 1
        FROM ancestors a
        JOIN stack_profile_callsite c ON c.id = a.current
        WHERE c.parent_id IS NOT NULL
      ),
      max_per_leaf AS (
        SELECT leaf, max(depth_from_leaf) AS md
        FROM ancestors GROUP BY leaf
      ),
      frames AS (
        SELECT
          a.leaf,
          m.md - a.depth_from_leaf AS depth,
          a.current AS callsite_at_depth,
          c.frame_id
        FROM ancestors a
        JOIN max_per_leaf m ON a.leaf = m.leaf
        JOIN stack_profile_callsite c ON c.id = a.current
      ),
      per_sample_frame AS (
        SELECT
          s.ts AS ts,
          s.utid AS utid,
          s.sample_idx AS sample_idx,
          s.slot_end AS slot_end,
          f.depth AS depth,
          f.callsite_at_depth AS callsite_at_depth,
          f.frame_id AS frame_id,
          ${frameNameExpr('spf', null)} AS frame_name,
          spf.mapping AS mapping_id,
          spf.rel_pc AS rel_pc,
          spm.name AS mapping_name
        FROM priv_samples s
        JOIN frames f ON f.leaf = s.callsite_id
        JOIN stack_profile_frame spf ON spf.id = f.frame_id
        LEFT JOIN stack_profile_mapping spm ON spm.id = spf.mapping
      ),
      with_neighbors AS (
        SELECT *,
          lag(callsite_at_depth) OVER (
            PARTITION BY utid, depth ORDER BY sample_idx
          ) AS prev_callsite,
          lag(sample_idx) OVER (
            PARTITION BY utid, depth ORDER BY sample_idx
          ) AS prev_sample_idx
        FROM per_sample_frame
      ),
      flagged AS (
        SELECT *,
          CASE
            WHEN prev_callsite IS NULL THEN 1
            WHEN callsite_at_depth != prev_callsite THEN 1
            WHEN sample_idx - prev_sample_idx != 1 THEN 1
            ELSE 0
          END AS is_new_run
        FROM with_neighbors
      ),
      grouped AS (
        SELECT *,
          sum(is_new_run) OVER (
            PARTITION BY utid, depth ORDER BY sample_idx
          ) AS run_id
        FROM flagged
      )
    SELECT
      row_number() OVER (ORDER BY utid, ts, depth) AS id,
      min(ts) AS ts,
      CASE
        WHEN count(*) > count(slot_end) THEN -1
        ELSE max(slot_end) - min(ts)
      END AS dur,
      utid,
      depth,
      min(frame_name) AS name,
      min(frame_id) AS frame_id,
      min(mapping_id) AS mapping_id,
      coalesce(min(rel_pc), 0) AS rel_pc,
      min(mapping_name) AS mapping_name
    FROM grouped
    GROUP BY utid, depth, run_id
    ORDER BY utid, ts, depth;
  `);
}

async function createTicksTable(trace: Trace, upidList: string): Promise<void> {
  await trace.engine.query(`
    CREATE PERFETTO TABLE ${TICKS_TABLE} AS
    SELECT s.ts AS ts, s.utid AS utid
    FROM perf_sample s
    JOIN thread USING (utid)
    WHERE thread.upid IN (${upidList})
      AND s.callsite_id IS NOT NULL
    ORDER BY s.utid, s.ts;
  `);
}

// Wraps a SliceTrack and overlays per-sample tick marks at the bottom of the
// row. The wrapper draws ticks _after_ delegating to the inner SliceTrack,
// using the same trackCtx — ctx is already translated to track-local coords
// by the framework's pushTransform (see WebGLRenderer.pushTransform which
// translates both WebGL state and the Canvas2D context).
class StackTimelineRenderer implements TrackRenderer {
  private readonly inner: SliceTrack<typeof STACK_SLICE_SCHEMA>;
  private readonly ticks: bigint[];
  readonly rootTableName?: string;

  constructor(
    inner: SliceTrack<typeof STACK_SLICE_SCHEMA>,
    ticks: bigint[],
  ) {
    this.inner = inner;
    this.ticks = ticks;
    this.rootTableName = inner.rootTableName;
  }

  render(trackCtx: TrackRenderContext): void {
    this.inner.render(trackCtx);
    if (this.ticks.length === 0) return;

    const {ctx, size, timescale, visibleWindow} = trackCtx;
    const startNs = visibleWindow.start.toTime();
    const endNs = visibleWindow.end.toTime();

    const tickHeight = 6;
    const yTop = Math.max(0, size.height - tickHeight - 1);

    // Strip background gives a clear visual band that says "this is where the
    // sample marks live"; without it the dark ticks blend into whatever the
    // bottommost slice happens to be.
    ctx.save();
    ctx.fillStyle = 'rgba(255, 255, 255, 0.75)';
    ctx.fillRect(0, yTop, size.width, tickHeight + 1);

    ctx.fillStyle = 'rgba(20, 20, 20, 0.95)';

    let lo = 0;
    let hi = this.ticks.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (this.ticks[mid] < startNs) lo = mid + 1;
      else hi = mid;
    }
    for (let i = lo; i < this.ticks.length; i++) {
      const ts = this.ticks[i];
      if (ts > endNs) break;
      const px = timescale.timeToPx(Time.fromRaw(ts));
      ctx.fillRect(Math.floor(px), yTop, 2, tickHeight);
    }
    ctx.restore();
  }

  getHeight(): number {
    return this.inner.getHeight();
  }

  getSliceVerticalBounds(depth: number): VerticalBounds | undefined {
    return this.inner.getSliceVerticalBounds(depth);
  }

  getTrackShellButtons(): m.Children {
    return this.inner.getTrackShellButtons();
  }

  onMouseMove(e: TrackMouseEvent): void {
    this.inner.onMouseMove(e);
  }

  onMouseClick(e: TrackMouseEvent): boolean {
    return this.inner.onMouseClick(e);
  }

  onMouseOut(): void {
    this.inner.onMouseOut();
  }

  getDataset(): SourceDatasetType | undefined {
    return this.inner.getDataset?.();
  }

  async getSelectionDetails(
    eventId: number,
  ): Promise<TrackEventDetails | undefined> {
    return this.inner.getSelectionDetails?.(eventId);
  }

  detailsPanel(sel: TrackEventSelection): TrackEventDetailsPanel | undefined {
    return this.inner.detailsPanel?.(sel);
  }

  renderTooltip(): m.Children {
    return this.inner.renderTooltip?.();
  }

  getSnapPoint(
    targetTime: time,
    thresholdPx: number,
    timescale: TimeScale,
  ): SnapPoint | undefined {
    return this.inner.getSnapPoint?.(targetTime, thresholdPx, timescale);
  }
}

async function loadTicks(trace: Trace, utid: number): Promise<bigint[]> {
  const res = await trace.engine.query(
    `SELECT ts FROM ${TICKS_TABLE} WHERE utid = ${utid} ORDER BY ts`,
  );
  const out: bigint[] = [];
  for (const it = res.iter({ts: LONG}); it.valid(); it.next()) {
    out.push(it.ts);
  }
  return out;
}

export async function registerStackTimelineForThread(
  trace: Trace,
  group: TrackNode,
  utid: number,
  threadName: string,
  tid: bigint | null,
): Promise<void> {
  const tidLabel = tid !== null ? ` (tid ${tid})` : '';

  const uri = `dev.perfetto.Sismo#priv_stack_utid_${utid}`;
  const ticks = await loadTicks(trace, utid);
  const inner = SliceTrack.create({
    trace,
    uri,
    rootTableName: STACK_TABLE,
    dataset: () =>
      new SourceDataset({
        src: STACK_TABLE,
        schema: STACK_SLICE_SCHEMA,
        filter: {col: 'utid', eq: utid},
      }),
    sliceName: (row) => frameLabel(row),
    colorizer: (row) => materialColorScheme(frameLabel(row)),
  });
  trace.tracks.registerTrack({
    uri,
    tags: {
      kinds: [SISMO_STACK_TRACK_KIND],
      utid,
    },
    renderer: new StackTimelineRenderer(inner, ticks),
    description: () =>
      m(
        '',
        `Call stack over time for ${threadName}${tidLabel}. Root at the top, ` +
          'leaf at the bottom. Tick marks on the bottom row are the raw ' +
          'sample timestamps; the colored bars are interpolated between them.',
      ),
  });
  group.addChildLast(
    new TrackNode({
      uri,
      name: `${threadName} — stacks${tidLabel}`,
      removable: false,
    }),
  );
}

// Area-selection tab that builds a flamegraph from perf_sample over the
// brushed range, scoped to whichever Sismo stack tracks are in the selection.
// Self-contained — does not rely on the upstream LinuxPerf plugin.
export function registerSismoFlamegraphTab(trace: Trace): void {
  let cachedSelection: AreaSelection | undefined;
  let cachedMetrics: ReadonlyArray<QueryFlamegraphMetric> | undefined;
  let flamegraphState: FlamegraphState | undefined;

  trace.selection.registerAreaSelectionTab({
    id: 'sismo_stack_flamegraph',
    name: 'Sample flamegraph',
    render: (selection: AreaSelection) => {
      const utids: number[] = [];
      const seen = new Set<number>();
      for (const t of selection.tracks) {
        const tagUtid = t.tags?.utid;
        if (
          t.tags?.kinds?.includes(SISMO_STACK_TRACK_KIND) &&
          typeof tagUtid === 'number' &&
          !seen.has(tagUtid)
        ) {
          seen.add(tagUtid);
          utids.push(tagUtid);
        }
      }
      if (utids.length === 0) return undefined;

      if (
        cachedSelection === undefined ||
        !areaSelectionsEqual(cachedSelection, selection)
      ) {
        cachedSelection = selection;
        cachedMetrics = buildSampleFlamegraphMetrics([
          `p.utid in (${utids.join(',')})`,
          `p.ts >= ${selection.start}`,
          `p.ts <= ${selection.end}`,
        ]);
        flamegraphState = Flamegraph.updateState(flamegraphState, cachedMetrics);
      }

      return {
        isLoading: false,
        content: m(FlamegraphPanel, {
          trace,
          metrics: cachedMetrics,
          state: flamegraphState,
          onStateChange: (s) => {
            flamegraphState = s;
          },
        }),
      };
    },
  });
}

// How the flamegraph's top level is split. 'none' is the plain call tree;
// 'thread'/'process' insert one synthetic root per thread/process above the call
// tree; 'process_thread' nests both — a process root, its threads beneath it,
// then each thread's call tree (the "breakdown dimension").
export type BreakdownKind = 'none' | 'thread' | 'process' | 'process_thread';

// `mapping_name LIKE` test for the kernel mapping. trace_processor renders the
// kernel mapping as `/[kernel.kallsyms]` (it prepends '/' per path component),
// so match the substring rather than the bare canonical name.
const KERNEL_CODE_TYPE =
  `case when mapping_name like '%[kernel.kallsyms]%' ` +
  `then 'Kernel' else 'User' end as code_type`;

// The plain call tree: the `_callstacks_for_callsites` stdlib macro (handles
// inlined frames) over the scoped samples.
function flatStatement(where: string): string {
  return `
    select
      id,
      parent_id as parentId,
      name,
      mapping_name,
      ${KERNEL_CODE_TYPE},
      source_file || ':' || line_number as source_location,
      self_count as value
    from _callstacks_for_callsites!((
      select p.callsite_id
      from perf_sample p
      where ${where}
    ))
  `;
}

// The SQL that identifies a breakdown group and labels it. `grp` is the integer
// the call tree is split on (utid / upid) and `label` names its synthetic root.
// `pgrp`/`plabel` are an optional PARENT group nested above it (process above
// thread); they are SQL `null` literals when the breakdown is single-level.
// `joins` brings in the thread (and, when a process is involved, process) rows
// the expressions need. `p` is the per-sample relation the stream selects from.
interface BreakdownGroup {
  readonly grp: string;
  readonly label: string;
  readonly pgrp: string;
  readonly plabel: string;
  readonly joins: string;
}

const THREAD_LABEL = `coalesce(th.name, 'utid ' || th.utid) || ' (tid ' || th.tid || ')'`;
const PROCESS_LABEL = `coalesce(pr.name, 'upid ' || th.upid) || ' (pid ' || pr.pid || ')'`;
const THREAD_JOIN = 'join thread th on th.utid = p.utid';
const PROCESS_JOIN =
  'join thread th on th.utid = p.utid\n' +
  '      join process pr on pr.upid = th.upid';
const NO_PARENT = {pgrp: 'cast(null as int)', plabel: 'cast(null as text)'};

function breakdownGroupCols(
  kind: 'thread' | 'process' | 'process_thread',
): BreakdownGroup {
  if (kind === 'thread') {
    return {grp: 'th.utid', label: THREAD_LABEL, ...NO_PARENT, joins: THREAD_JOIN};
  }
  if (kind === 'process') {
    return {
      grp: 'th.upid',
      label: PROCESS_LABEL,
      ...NO_PARENT,
      joins: PROCESS_JOIN,
    };
  }
  // process_thread: each thread's call tree nested under its process.
  return {
    grp: 'th.utid',
    label: THREAD_LABEL,
    pgrp: 'th.upid',
    plabel: PROCESS_LABEL,
    joins: PROCESS_JOIN,
  };
}

// A "sample stream" yields one row per sample as (grp, label, pgrp, plabel, cs,
// w): which breakdown group it belongs to, that group's label, its optional
// parent group + label, the leaf callsite, and the self-weight to credit. This is
// the only metric-specific part of a breakdown — breakdownTreeStatement turns any
// such stream into the per-group call tree.

// Plain sample count: every sample weighs 1.
function sampleCountStream(where: string, g: BreakdownGroup): string {
  return `
    select ${g.grp} as grp, ${g.label} as label,
      ${g.pgrp} as pgrp, ${g.plabel} as plabel,
      p.callsite_id as cs, 1 as w
    from perf_sample p
    ${g.joins}
    where ${where}
  `;
}

// Counter-weighted: credit each sample the per-interval delta of a hardware
// counter (its reading minus the prior sample on the same thread+track), clamped
// at 0. Same approximate sampling attribution as counterWeightedStatement.
function counterStream(
  where: string,
  g: BreakdownGroup,
  counterName: string,
): string {
  return `
    select grp, label, pgrp, plabel, cs,
      case when dv > 0 then dv else 0 end as w
    from (
      select ${g.grp} as grp, ${g.label} as label,
        ${g.pgrp} as pgrp, ${g.plabel} as plabel,
        p.callsite_id as cs,
        p.counter_value - lag(p.counter_value) over (
          partition by p.utid, p.track_id order by p.ts
        ) as dv
      from linux_perf_sample_with_counters p
      ${g.joins}
      join track t on t.id = p.track_id
      where ${where}
        and t.name = '${counterName}'
    )
  `;
}

// Backend-bound slots: weigh by slots − retired − frontend per sample (the L1
// Backend numerator), clamped at 0. Pivots the three Top-Down slot counters per
// sample, same as backendSlotsStatement.
function backendSlotsStream(where: string, g: BreakdownGroup): string {
  return `
    select grp, label, cs,
      case
        when slots is not null and retired is not null and fetch_bubbles is not null
          and slots - retired - fetch_bubbles > 0
        then slots - retired - fetch_bubbles
        else 0
      end as w
    from (
      select grp, label, pgrp, plabel, max(callsite_id) as cs,
        max(case when cname = 'slots' then dv end) as slots,
        max(case when cname = 'topdown-slots-retired' then dv end) as retired,
        max(case when cname = 'topdown-fetch-bubbles' then dv end) as fetch_bubbles
      from (
        select ${g.grp} as grp, ${g.label} as label,
          ${g.pgrp} as pgrp, ${g.plabel} as plabel,
          p.sample_id as sample_id,
          p.callsite_id as callsite_id, t.name as cname,
          p.counter_value - lag(p.counter_value) over (
            partition by p.utid, p.track_id order by p.ts
          ) as dv
        from linux_perf_sample_with_counters p
        ${g.joins}
        join track t on t.id = p.track_id
        where ${where}
          and t.name in ('slots', 'topdown-slots-retired', 'topdown-fetch-bubbles')
      )
      group by grp, sample_id, callsite_id
    )
  `;
}

// The call tree split by group: one synthetic root per group, with that group's
// callsite subtree hung beneath it, self-value = the stream's summed weight per
// (group, callsite). When the stream carries a parent group (process above
// thread), a second tier of roots is inserted above the group roots. Built by
// hand (rather than the stdlib macro) because weights must be per-group; the
// group's root callsites are reparented onto the synthetic root. Inlined frames
// collapse to their callsite frame here (the macro's inline expansion isn't
// available per-group) — an accepted fidelity trade for the breakdown view.
//
// Ids must be DENSE and non-negative: the flamegraph's graph aggregation
// (__intrinsic_graph_agg / NodeAgg) casts each id to uint32 and `resize`s a
// vector to max_id+1, indexing by id. A negative id wraps to ~4e9 (OOM crash)
// and sparse ids (group_index * BIG + callsite_id) inflate that vector. So pack
// the ids into three dense contiguous ranges: callsite nodes 1..N, then group
// roots N+1..N+T, then parent roots N+T+1..N+T+P.
function breakdownTreeStatement(stream: string): string {
  return `
    with recursive
      base as (${stream}),
      -- Inner groups (e.g. threads), each carrying its optional parent group.
      grp_idx as (
        select grp, row_number() over (order by grp) as gidx, label, pgrp
        from (select distinct grp, label, pgrp from base)
      ),
      -- Parent groups (e.g. processes); empty for a single-level breakdown.
      pgrp_idx as (
        select pgrp, row_number() over (order by pgrp) as pidx, plabel
        from (select distinct pgrp, plabel from base where pgrp is not null)
      ),
      self_counts as (select grp, cs, sum(w) as n from base group by grp, cs),
      walk(grp, cur) as (
        select grp, cs from self_counts
        union all
        select w.grp, c.parent_id
        from walk w
        join stack_profile_callsite c on c.id = w.cur
        where c.parent_id is not null
      ),
      reach as (select distinct grp, cur as cs from walk),
      -- Dense 1..N id per reachable (group, callsite).
      node_ids as (
        select grp, cs, row_number() over (order by grp, cs) as nid from reach
      ),
      node_count as (select count(*) as n from node_ids),
      grp_count as (select count(*) as n from grp_idx)
    -- Parent (process) roots: ids N+T+1..N+T+P, no parent.
    select
      (select n from node_count) + (select n from grp_count) + pi.pidx as id,
      cast(null as int) as parentId,
      pi.plabel as name,
      cast(null as text) as mapping_name,
      cast(null as text) as code_type,
      cast(null as text) as source_location,
      0 as value
    from pgrp_idx pi
    union all
    -- Group (thread) roots: ids N+1..N+T, parented to their parent root (or no
    -- parent for a single-level breakdown).
    select
      (select n from node_count) + gi.gidx as id,
      case
        when gi.pgrp is null then cast(null as int)
        else (select n from node_count) + (select n from grp_count) + pi.pidx
      end as parentId,
      gi.label as name,
      cast(null as text) as mapping_name,
      cast(null as text) as code_type,
      cast(null as text) as source_location,
      0 as value
    from grp_idx gi
    left join pgrp_idx pi on pi.pgrp = gi.pgrp
    union all
    -- Call-tree nodes, root callsites reparented onto their group root.
    select
      ni.nid as id,
      case
        when c.parent_id is null then (select n from node_count) + gi.gidx
        else pn.nid
      end as parentId,
      ${frameNameExpr('f')} as name,
      spm.name as mapping_name,
      ${KERNEL_CODE_TYPE.replace('mapping_name', 'spm.name')},
      cast(null as text) as source_location,
      coalesce(sc.n, 0) as value
    from node_ids ni
    join grp_idx gi on gi.grp = ni.grp
    join stack_profile_callsite c on c.id = ni.cs
    join stack_profile_frame f on f.id = c.frame_id
    left join stack_profile_mapping spm on spm.id = f.mapping
    left join node_ids pn on pn.grp = ni.grp and pn.cs = c.parent_id
    left join self_counts sc on sc.grp = ni.grp and sc.cs = ni.cs
  `;
}

// A counter-weighted flat call tree: instead of counting samples, credit each
// sample the per-interval delta of a hardware counter (its cumulative reading
// minus the prior sample on the same thread+track) and sum it up the stack via
// the stdlib weighted-callsites macro. So "weight by cache-misses" shows which
// subtree the misses concentrate in, not just where wall-time went.
//
// APPROXIMATE — the same sampling attribution the sample-count tree makes, just
// weighted: the interval's delta is credited to the stack caught at the tick
// (timer-sampled, not PEBS), and negative deltas (counter reset / multiplexing)
// are clamped to zero. `p` aliases the sample×counter view so the caller's
// `p.`-qualified scope predicates bind unchanged.
function counterWeightedStatement(where: string, counterName: string): string {
  return `
    with deltas as (
      select
        p.callsite_id as callsite_id,
        p.counter_value - lag(p.counter_value) over (
          partition by p.utid, p.track_id order by p.ts
        ) as dv
      from linux_perf_sample_with_counters p
      join track t on t.id = p.track_id
      where ${where}
        and t.name = '${counterName}'
    )
    select
      id,
      parent_id as parentId,
      name,
      mapping_name,
      ${KERNEL_CODE_TYPE},
      source_file || ':' || line_number as source_location,
      self_value as value
    from _callstacks_for_callsites_weighted!((
      select callsite_id, case when dv > 0 then dv else 0 end as value
      from deltas
    ))
  `;
}

// Counter-weighted flamegraph views offered alongside "Sample count" (flat tree
// only). Limited to the counters present in essentially every sismo recording;
// a counter absent from a trace just yields an empty tree for that metric.
const COUNTER_WEIGHTS: ReadonlyArray<{counter: string; label: string}> = [
  {counter: 'cpu-cycles', label: 'CPU cycles (approx)'},
  {counter: 'cache-misses', label: 'Cache misses (approx)'},
  {counter: 'branch-misses', label: 'Branch misses (approx)'},
];

// The Top-Down slot counters the backend-bound view needs (slots = the
// denominator, retired + fetch-bubbles = the Retiring/Frontend numerators).
const BACKEND_SLOT_COUNTERS = [
  'slots',
  'topdown-slots-retired',
  'topdown-fetch-bubbles',
];

// Weights the flame by BACKEND-BOUND slots per sample = slots − retiring −
// frontend (the L1 Backend numerator), so it points straight at where the
// pipeline stalled on the back end (cache/memory/execution) rather than where
// wall-time went. Needs all three Top-Down slot counters; pivots them per sample
// (each is a separate track), takes each one's per-interval delta, and clamps
// the remainder at 0. Same approximate sampling attribution as the other
// counter-weighted views.
function backendSlotsStatement(where: string): string {
  return `
    with per_counter as (
      select
        p.sample_id as sample_id,
        p.callsite_id as callsite_id,
        t.name as cname,
        p.counter_value - lag(p.counter_value) over (
          partition by p.utid, p.track_id order by p.ts
        ) as dv
      from linux_perf_sample_with_counters p
      join track t on t.id = p.track_id
      where ${where}
        and t.name in ('slots', 'topdown-slots-retired', 'topdown-fetch-bubbles')
    ),
    per_sample as (
      select
        sample_id,
        max(callsite_id) as callsite_id,
        max(case when cname = 'slots' then dv end) as slots,
        max(case when cname = 'topdown-slots-retired' then dv end) as retired,
        max(case when cname = 'topdown-fetch-bubbles' then dv end) as fetch_bubbles
      from per_counter
      group by sample_id
    )
    select
      id,
      parent_id as parentId,
      name,
      mapping_name,
      ${KERNEL_CODE_TYPE},
      source_file || ':' || line_number as source_location,
      self_value as value
    from _callstacks_for_callsites_weighted!((
      select
        callsite_id,
        case
          when slots is not null and retired is not null and fetch_bubbles is not null
            and slots - retired - fetch_bubbles > 0
          then slots - retired - fetch_bubbles
          else 0
        end as value
      from per_sample
    ))
  `;
}

// Which perf counters this trace actually carries (by track name), scoped the
// same way the flamegraph is. Lets the builder offer only the counter-weighted
// views the data supports — empty set (or any error) ⇒ Sample count only.
export async function loadPerfCounterNames(
  engine: Engine,
  scope: ReadonlyArray<string>,
): Promise<ReadonlySet<string>> {
  const out = new Set<string>();
  try {
    await engine.query('include perfetto module linux.perf.counters;');
    const whereClause = scope.length > 0 ? `where ${scope.join(' and ')}` : '';
    const res = await engine.query(`
      select distinct t.name as name
      from linux_perf_sample_with_counters p
      join track t on t.id = p.track_id
      ${whereClause}
    `);
    for (const it = res.iter({name: STR_NULL}); it.valid(); it.next()) {
      if (it.name !== null) out.add(it.name);
    }
  } catch {
    // No counters / table absent — leave empty.
  }
  return out;
}

// perf_sample (alias `p`) predicates scoping the sample flamegraph metrics to
// the profiled set. Empty when there's no privileged set, so the views show the
// whole workload rather than nothing. The metric SQL aliases perf_sample as `p`.
export function sampleScopePredicates(priv: PrivilegedSet): string[] {
  if (priv.upids.length === 0) return [];
  return [
    `p.utid in (SELECT utid FROM thread WHERE upid IN ` +
      `(${priv.upids.join(',')}))`,
  ];
}

// Builds the sismo sample flamegraph metrics. `wherePredicates` are extra SQL
// fragments ANDed onto the perf_sample selection (utid/time scoping); the
// `callsite_id IS NOT NULL` guard is always applied. Pass `breakdownBy` (even
// 'none') to declare the "Break down by" control; 'thread'/'process' reshape
// EVERY metric — sample count and each counter weighting — into the per-group
// tree. Omit it for plain flat trees with no control.
export function buildSampleFlamegraphMetrics(
  wherePredicates: ReadonlyArray<string>,
  breakdownBy?: BreakdownKind,
  // Counter track names present in this trace. When omitted, the common
  // single-counter views are offered unconditionally (they almost always exist)
  // and the backend-bound view — which needs the optional Top-Down counters — is
  // withheld, so it never shows for a trace that can't support it.
  availableCounters?: ReadonlySet<string>,
): QueryFlamegraphMetric[] {
  const where = ['p.callsite_id is not null', ...wherePredicates].join(
    '\n            and ',
  );
  // `broken` reshapes every metric into the per-group tree; `g` carries the
  // group/label SQL. When breakdownBy is supplied at all (even 'none') the metrics
  // declare the "Break down by" control, so the user can switch into a breakdown.
  const broken =
    breakdownBy === 'thread' ||
    breakdownBy === 'process' ||
    breakdownBy === 'process_thread';
  const g = broken ? breakdownGroupCols(breakdownBy) : undefined;
  const breakdownDimensions =
    breakdownBy === undefined
      ? undefined
      : [
          {key: 'none', label: 'None'},
          {key: 'thread', label: 'Thread'},
          {key: 'process', label: 'Process'},
          {key: 'process_thread', label: 'Process › Thread'},
        ];
  // Shared across all metrics (sample count + counter-weighted).
  const unaggregatableProperties = [
    {name: 'mapping_name', displayName: 'Mapping'},
    // Kernel vs user, derived from the mapping. Powers "Color by → Code type"
    // and a one-click hide-kernel filter. Functionally dependent on
    // mapping_name, so it adds no extra node merging.
    {name: 'code_type', displayName: 'Code type'},
  ];
  const aggregatableProperties = [
    {
      name: 'source_location',
      displayName: 'Source location',
      mergeAggregation: 'ONE_OR_SUMMARY' as const,
    },
  ];
  const metrics: QueryFlamegraphMetric[] = [
    {
      name: 'Sample count',
      unit: '',
      nameColumnLabel: 'Symbol',
      dependencySql: 'include perfetto module linux.perf.samples;',
      statement: broken
        ? breakdownTreeStatement(sampleCountStream(where, g!))
        : flatStatement(where),
      breakdownDimensions,
      unaggregatableProperties,
      aggregatableProperties,
    },
  ];
  // Counter-weighted views weight the same tree by a hardware counter instead of
  // sample count — including under a breakdown, where each group's subtree carries
  // its own counter weights. A counter missing from the trace just yields an empty
  // tree for that metric.
  const present = (n: string) =>
    availableCounters === undefined || availableCounters.has(n);
  const counterDeps =
    'include perfetto module linux.perf.samples;\n' +
    'include perfetto module linux.perf.counters;';
  for (const w of COUNTER_WEIGHTS) {
    if (!present(w.counter)) continue;
    metrics.push({
      name: w.label,
      unit: '',
      nameColumnLabel: 'Symbol',
      dependencySql: counterDeps,
      statement: broken
        ? breakdownTreeStatement(counterStream(where, g!, w.counter))
        : counterWeightedStatement(where, w.counter),
      breakdownDimensions,
      unaggregatableProperties,
      aggregatableProperties,
    });
  }
  // Backend-bound slots only when we've confirmed all three Top-Down counters
  // are present (withheld under the undefined "unknown" case).
  if (
    availableCounters !== undefined &&
    BACKEND_SLOT_COUNTERS.every((c) => availableCounters.has(c))
  ) {
    metrics.push({
      name: 'Backend-bound slots (approx)',
      unit: '',
      nameColumnLabel: 'Symbol',
      dependencySql: counterDeps,
      statement: broken
        ? breakdownTreeStatement(backendSlotsStream(where, g!))
        : backendSlotsStatement(where),
      breakdownDimensions,
      unaggregatableProperties,
      aggregatableProperties,
    });
  }
  return metrics;
}
