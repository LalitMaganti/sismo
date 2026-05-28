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
import {LONG, NUM, STR_NULL} from '../../trace_processor/query_result';
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

  const threadsRes = await trace.engine.query(`
    WITH per_thread AS (
      SELECT
        thread.utid AS utid,
        coalesce(thread.name, '[utid ' || thread.utid || ']') AS thread_name,
        thread.tid AS tid,
        (SELECT sum(sched.dur) FROM sched
           WHERE sched.utid = thread.utid AND sched.dur > 0
        ) AS runtime_ns
      FROM thread
      WHERE thread.upid IN (${upidList})
    )
    SELECT utid, thread_name, tid
    FROM per_thread
    ORDER BY coalesce(runtime_ns, 0) DESC
  `);

  const ws = trace.workspaces.createEmptyWorkspace('CPU usage by thread');

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

  const threadGroup = new TrackNode({
    name: 'Your threads (state over time)',
    isSummary: true,
    collapsed: false,
    sortOrder: -50,
    removable: false,
  });
  for (
    const it = threadsRes.iter({utid: NUM, thread_name: STR_NULL, tid: LONG});
    it.valid();
    it.next()
  ) {
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
    threadGroup.addChildLast(
      new TrackNode({
        uri,
        name: `${name} (tid ${tid})`,
        removable: false,
      }),
    );
    await registerStackTimelineForThread(trace, threadGroup, utid, name, tid);
  }
  ws.addChildLast(threadGroup);

  trace.workspaces.switchWorkspace(ws);
}
