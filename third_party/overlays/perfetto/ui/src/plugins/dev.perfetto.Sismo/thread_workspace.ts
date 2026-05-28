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
import {CounterTrack} from '../../components/tracks/counter_track';
import {LONG, LONG_NULL, NUM, STR_NULL} from '../../trace_processor/query_result';
import {createThreadStateTrack} from '../dev.perfetto.Sched/thread_state_track';
import type {PrivilegedSet} from './privileged_set';
import {registerSystemConcurrencyTrack} from './cpu_workspace';
import {
  registerStackTimelineForThread,
  setupStackTimelineTables,
} from './stack_timeline';

const PRIV_USAGE_TABLE = 'sismo_priv_usage';

export async function setupByThreadWorkspace(
  trace: Trace,
  priv: PrivilegedSet,
): Promise<void> {
  if (priv.upids.length === 0) return;
  const upidList = priv.upids.join(',');

  await setupStackTimelineTables(trace, priv);

  // Threads with their owning process, ordered so the busiest process (and
  // within it the busiest thread) comes first — mirrors how Instruments lists
  // process groups top-down by activity.
  const threadsRes = await trace.engine.query(`
    WITH per_thread AS (
      SELECT
        thread.utid AS utid,
        thread.upid AS upid,
        coalesce(thread.name, '[utid ' || thread.utid || ']') AS thread_name,
        thread.tid AS tid,
        coalesce(
          (SELECT sum(sched.dur) FROM sched
             WHERE sched.utid = thread.utid AND sched.dur > 0),
          0
        ) AS runtime_ns
      FROM thread
      WHERE thread.upid IN (${upidList})
    ),
    per_process AS (
      SELECT upid, sum(runtime_ns) AS proc_runtime FROM per_thread GROUP BY upid
    )
    SELECT
      per_thread.utid AS utid,
      per_thread.upid AS upid,
      per_thread.thread_name AS thread_name,
      per_thread.tid AS tid,
      coalesce(process.name, '[upid ' || per_thread.upid || ']') AS process_name,
      process.pid AS pid
    FROM per_thread
    JOIN per_process USING (upid)
    LEFT JOIN process ON process.upid = per_thread.upid
    ORDER BY per_process.proc_runtime DESC, per_thread.runtime_ns DESC
  `);

  const ws = trace.workspaces.createEmptyWorkspace('Threads (by process)');

  const usageUri = 'dev.perfetto.Sismo#priv_cpu_usage_for_thread_ws';
  const usageTrack = new (class extends CounterTrack {
    constructor() {
      super({
        trace,
        uri: usageUri,
        sqlSource: `SELECT ts, value FROM ${PRIV_USAGE_TABLE}`,
        yRangeRounding: 'strict',
        yRange: 'all',
        unit: '%',
        yOverrideMinimum: 0,
        yOverrideMaximum: 100,
      });
    }
  })();
  trace.tracks.registerTrack({
    uri: usageUri,
    renderer: usageTrack,
    description: () =>
      m(
        '',
        'Average share of total CPU capacity used by your processes each ' +
          'second. Same metric as in the per-CPU view.',
      ),
  });
  ws.addChildLast(
    new TrackNode({
      uri: usageUri,
      name: 'Your CPU usage (% of total capacity)',
      sortOrder: -100,
      removable: false,
    }),
  );

  // Mirror the per-cpu workspace: include the system-wide concurrency track
  // so the same trace-time-series cycle-budget context shows up here too.
  const sysUri = await registerSystemConcurrencyTrack(trace);
  ws.addChildLast(
    new TrackNode({
      uri: sysUri,
      name: 'System concurrency (cores in use)',
      sortOrder: -90,
      removable: false,
    }),
  );

  // Instruments-style: one collapsible group per process, threads nested
  // inside, each thread showing its state lane + stack-samples lane.
  let order = -50;
  const groupByUpid = new Map<number, TrackNode>();
  for (
    const it = threadsRes.iter({
      utid: NUM,
      upid: NUM,
      thread_name: STR_NULL,
      tid: LONG,
      process_name: STR_NULL,
      pid: LONG_NULL,
    });
    it.valid();
    it.next()
  ) {
    let group = groupByUpid.get(it.upid);
    if (group === undefined) {
      const procName = it.process_name ?? `[upid ${it.upid}]`;
      const pidLabel = it.pid !== null ? ` (pid ${it.pid})` : '';
      group = new TrackNode({
        name: `${procName}${pidLabel}`,
        isSummary: true,
        collapsed: false,
        sortOrder: order++,
        removable: false,
      });
      groupByUpid.set(it.upid, group);
      ws.addChildLast(group);
    }

    const utid = it.utid;
    const name = it.thread_name ?? `[utid ${utid}]`;
    const tid = it.tid;
    const uri = `dev.perfetto.Sismo#priv_thread_state_utid_${utid}`;
    const renderer = createThreadStateTrack(trace, uri, utid);
    trace.tracks.registerTrack({
      uri,
      renderer,
      description: () =>
        m(
          '',
          `What ${name} (tid ${tid}) was doing at each moment — running, ` +
            'waiting for a CPU, or sleeping. Click a slice for details.',
        ),
    });
    group.addChildLast(
      new TrackNode({
        uri,
        name: `${name} (tid ${tid})`,
        removable: false,
      }),
    );
    await registerStackTimelineForThread(trace, group, utid, name, tid);
  }

  trace.workspaces.switchWorkspace(ws);
}
