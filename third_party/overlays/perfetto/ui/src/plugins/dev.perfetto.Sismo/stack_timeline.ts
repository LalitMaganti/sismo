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
import {materialColorScheme} from '../../components/colorizer';
import {Time} from '../../base/time';
import type {time} from '../../base/time';
import type {TimeScale} from '../../base/time_scale';
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
import {type QueryFlamegraphMetric} from '../../components/query_flamegraph';
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
          spf.name AS frame_name,
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

// Builds the sismo sample flamegraph metric. `wherePredicates` are extra SQL
// fragments ANDed onto the perf_sample selection (utid/time scoping); the
// `callsite_id IS NOT NULL` guard is always applied.
export function buildSampleFlamegraphMetrics(
  wherePredicates: ReadonlyArray<string>,
): QueryFlamegraphMetric[] {
  const where = ['p.callsite_id is not null', ...wherePredicates].join(
    '\n            and ',
  );
  return [
    {
      name: 'Sample count',
      unit: '',
      nameColumnLabel: 'Symbol',
      dependencySql: 'include perfetto module linux.perf.samples;',
      statement: `
        select
          id,
          parent_id as parentId,
          name,
          mapping_name,
          source_file || ':' || line_number as source_location,
          self_count as value
        from _callstacks_for_callsites!((
          select p.callsite_id
          from perf_sample p
          where ${where}
        ))
      `,
      unaggregatableProperties: [
        {name: 'mapping_name', displayName: 'Mapping'},
      ],
      aggregatableProperties: [
        {
          name: 'source_location',
          displayName: 'Source location',
          mergeAggregation: 'ONE_OR_SUMMARY' as const,
        },
      ],
    },
  ];
}
