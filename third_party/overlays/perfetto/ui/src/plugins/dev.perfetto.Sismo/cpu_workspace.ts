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
import {LONG_NULL, NUM, STR_NULL} from '../../trace_processor/query_result';
import {createCpuSliceTrack} from '../dev.perfetto.Sched/cpu_slice_track';
import type {ThreadDesc, ThreadMap} from '../dev.perfetto.Thread/threads';
import type {PrivilegedSet} from './privileged_set';

const PRIV_SCHED_TABLE = 'sismo_priv_sched';
const PRIV_USAGE_TABLE = 'sismo_priv_usage';
const SYS_SCHED_TABLE = 'sismo_sys_sched';
const SYS_CONCURRENCY_TABLE = 'sismo_sys_concurrency';

// Same shape as PRIV_SCHED_TABLE but no upid filter — the input to the
// utilization macro for the "System concurrency" counter track.
async function createSystemSchedTable(trace: Trace): Promise<void> {
  await trace.engine.query(`
    CREATE PERFETTO TABLE ${SYS_SCHED_TABLE} AS
    SELECT
      sched.id AS id,
      sched.ts AS ts,
      sched.dur AS dur,
      sched.ts + sched.dur AS ts_end,
      sched.utid AS utid,
      IFNULL(process.pid, 0) AS pid,
      IFNULL(sched.priority, 120) AS priority,
      sched.ucpu AS ucpu,
      0 AS depth
    FROM sched
    LEFT JOIN thread USING (utid)
    LEFT JOIN process USING (upid)
    WHERE sched.dur > 0
      AND NOT (sched.utid IN (SELECT utid FROM thread WHERE is_idle));
  `);
}

// Idempotent: PerfettoSQL has no `CREATE TABLE IF NOT EXISTS`, so we gate on
// a perfetto_tables lookup instead.
export async function setupSismoSharedTables(
  trace: Trace,
  priv: PrivilegedSet,
): Promise<void> {
  if (priv.upids.length === 0) return;
  const upidList = priv.upids.join(',');

  const existing = await trace.engine.query(
    `SELECT name FROM perfetto_tables WHERE name = '${PRIV_SCHED_TABLE}'`,
  );
  if (existing.numRows() > 0) return;

  // createThreadStateTrack pulls in sched_state_io_to_human_readable_string,
  // which the Sched plugin normally INCLUDEs on activation.
  await trace.engine.query(`INCLUDE PERFETTO MODULE sched.states;`);
  await trace.engine.query(`INCLUDE PERFETTO MODULE time.conversion;`);
  await trace.engine.query(
    `INCLUDE PERFETTO MODULE linux.cpu.utilization.general;`,
  );

  // ts_end is required by _interval_partitions inside the utilization macro
  // below. Other columns match createCpuSliceTrack's expected schema.
  await trace.engine.query(`
    CREATE PERFETTO TABLE ${PRIV_SCHED_TABLE} AS
    SELECT
      sched.id AS id,
      sched.ts AS ts,
      sched.dur AS dur,
      sched.ts + sched.dur AS ts_end,
      sched.utid AS utid,
      IFNULL(process.pid, 0) AS pid,
      IFNULL(sched.priority, 120) AS priority,
      sched.ucpu AS ucpu,
      0 AS depth
    FROM sched
    JOIN thread USING (utid)
    LEFT JOIN process USING (upid)
    WHERE thread.upid IN (${upidList})
      AND sched.dur > 0
      AND NOT (sched.utid IN (SELECT utid FROM thread WHERE is_idle));
  `);

  await trace.engine.query(`
    CREATE PERFETTO TABLE ${PRIV_USAGE_TABLE} AS
    SELECT ts, 100.0 * utilization AS value
    FROM _cpu_avg_utilization_per_period!(time_from_s(1), ${PRIV_SCHED_TABLE});
  `);

  // System-wide "cores in use" track: time-series sibling of the page's
  // "Concurrency" meter. utilization here is 0..1 (fraction of total core
  // capacity used); × numCpus turns it into "avg cores in use" in raw cores,
  // which is what the meter displays.
  await createSystemSchedTable(trace);
  await trace.engine.query(`
    CREATE PERFETTO TABLE ${SYS_CONCURRENCY_TABLE} AS
    SELECT
      ts,
      utilization * (SELECT count() FROM cpu) AS value
    FROM _cpu_avg_utilization_per_period!(time_from_s(1), ${SYS_SCHED_TABLE});
  `);
}

// Builds + registers the shared "System concurrency (cores in use)" counter
// track. Called from each workspace setup so the same track URI appears in
// both the per-CPU and per-thread workspaces; getTrack guards the second call.
export async function registerSystemConcurrencyTrack(
  trace: Trace,
): Promise<string> {
  const uri = 'dev.perfetto.Sismo#sys_concurrency';
  if (trace.tracks.getTrack(uri) !== undefined) return uri;

  const cpuCountRes = await trace.engine.query(
    `SELECT count() AS n FROM cpu`,
  );
  const numCpus = cpuCountRes.firstRow({n: NUM}).n || 1;

  const sysTrack = new (class extends CounterTrack {
    constructor() {
      super({
        trace,
        uri,
        sqlSource: `SELECT ts, value FROM ${SYS_CONCURRENCY_TABLE}`,
        yRangeRounding: 'strict',
        yRange: 'all',
        unit: ' cores',
        yOverrideMinimum: 0,
        yOverrideMaximum: numCpus,
      });
    }
  })();
  trace.tracks.registerTrack({
    uri,
    renderer: sysTrack,
    description: () =>
      m(
        '',
        'Average number of cores busy across the entire system each second. ' +
          'A value of N means N cores were fully busy on average; this is ' +
          'the system-wide version of the "Concurrency" meter on the CPU ' +
          'usage page.',
      ),
  });
  return uri;
}

async function loadPrivThreadMap(
  trace: Trace,
  upidList: string,
): Promise<ThreadMap> {
  const res = await trace.engine.query(`
    SELECT
      thread.utid AS utid,
      thread.tid AS tid,
      coalesce(thread.name, '[utid ' || thread.utid || ']') AS thread_name,
      process.pid AS pid,
      process.name AS proc_name
    FROM thread
    LEFT JOIN process USING (upid)
    WHERE thread.upid IN (${upidList})
  `);
  const map = new Map<number, ThreadDesc>();
  for (
    const it = res.iter({
      utid: NUM,
      tid: LONG_NULL,
      thread_name: STR_NULL,
      pid: LONG_NULL,
      proc_name: STR_NULL,
    });
    it.valid();
    it.next()
  ) {
    map.set(it.utid, {
      utid: it.utid,
      tid: it.tid ?? 0n,
      threadName: it.thread_name ?? '<unknown>',
      pid: it.pid ?? undefined,
      procName: it.proc_name ?? undefined,
    });
  }
  return map;
}

export async function setupByCpuWorkspace(
  trace: Trace,
  priv: PrivilegedSet,
): Promise<void> {
  if (priv.upids.length === 0) return;
  const upidList = priv.upids.join(',');

  const cpuRes = await trace.engine.query(`
    SELECT cpu.cpu AS cpu, cpu.ucpu AS ucpu
    FROM cpu
    WHERE cpu.ucpu IN (SELECT DISTINCT ucpu FROM ${PRIV_SCHED_TABLE})
    ORDER BY cpu.cpu
  `);
  const threads = await loadPrivThreadMap(trace, upidList);

  const ws = trace.workspaces.createEmptyWorkspace('CPU usage per CPU');

  const usageUri = 'dev.perfetto.Sismo#priv_cpu_usage';
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
          'second. 100% means every core was fully busy running your work; ' +
          '25% on a 4-core machine means one core fully busy (or two cores ' +
          'half-busy, etc.).',
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

  // System-wide concurrency: time-series of the page's "Concurrency" meter.
  const sysUri = await registerSystemConcurrencyTrack(trace);
  ws.addChildLast(
    new TrackNode({
      uri: sysUri,
      name: 'System concurrency (cores in use)',
      sortOrder: -90,
      removable: false,
    }),
  );

  const cpuGroup = new TrackNode({
    name: 'Your scheduling per CPU',
    isSummary: true,
    collapsed: false,
    sortOrder: -50,
    removable: false,
  });
  for (
    const it = cpuRes.iter({cpu: NUM, ucpu: NUM});
    it.valid();
    it.next()
  ) {
    const cpu = it.cpu;
    const ucpu = it.ucpu;
    const uri = `dev.perfetto.Sismo#priv_sched_ucpu_${ucpu}`;
    const track = createCpuSliceTrack(trace, uri, PRIV_SCHED_TABLE, ucpu, threads);
    trace.tracks.registerTrack({
      uri,
      renderer: track,
      description: () =>
        m(
          '',
          `When your threads ran on CPU ${cpu}. Other processes that also ` +
            'ran on this core are not shown — switch to the combined ' +
            'timeline workspace to see them.',
        ),
    });
    cpuGroup.addChildInOrder(
      new TrackNode({
        uri,
        name: `CPU ${cpu} (yours only)`,
        removable: false,
      }),
    );
  }
  ws.addChildLast(cpuGroup);
}
