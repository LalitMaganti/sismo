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

import type {Engine} from '../../../trace_processor/engine';
import {LONG_NULL} from '../../../trace_processor/query_result';
import type {PrivilegedSet} from '../privileged_set';

// Whole-trace thread-state split for the scoped set, the input to Overview's
// triage question. Same state buckets as loadThreadStates but summed across all
// threads (no per-thread grouping): of the time the set wanted a CPU (running +
// runnable), how much it actually got tells you whether this is a CPU-usage
// problem or a scheduling-latency one.
export interface CpuTriage {
  hasData: boolean;
  // On a CPU, executing (state Running).
  runningNs: bigint;
  // Ready to run but no core was free (R / R+) — scheduling latency.
  runnableNs: bigint;
  // Blocked uninterruptibly, usually on I/O (D).
  uninterruptibleNs: bigint;
  // Voluntarily asleep, not trying to run (S).
  sleepingNs: bigint;
  otherNs: bigint;
}

export async function loadCpuTriage(
  engine: Engine,
  priv: PrivilegedSet,
): Promise<CpuTriage> {
  const upidFilter =
    priv.upids.length > 0 ? `AND th.upid IN (${priv.upids.join(',')})` : '';
  const res = await engine.query(`
    SELECT
      sum(CASE WHEN ts.state = 'Running' THEN ts.dur ELSE 0 END) AS running,
      sum(CASE WHEN ts.state IN ('R', 'R+') THEN ts.dur ELSE 0 END) AS runnable,
      sum(CASE WHEN ts.state = 'D' THEN ts.dur ELSE 0 END) AS uninterruptible,
      sum(CASE WHEN ts.state = 'S' THEN ts.dur ELSE 0 END) AS sleeping,
      sum(CASE WHEN ts.state NOT IN ('Running', 'R', 'R+', 'D', 'S')
               THEN ts.dur ELSE 0 END) AS other
    FROM thread_state ts
    JOIN thread th USING (utid)
    WHERE ts.dur > 0 AND th.is_idle = 0
      ${upidFilter}
  `);
  const r = res.firstRow({
    running: LONG_NULL,
    runnable: LONG_NULL,
    uninterruptible: LONG_NULL,
    sleeping: LONG_NULL,
    other: LONG_NULL,
  });
  const running = r.running ?? 0n;
  const runnable = r.runnable ?? 0n;
  const uninterruptible = r.uninterruptible ?? 0n;
  const sleeping = r.sleeping ?? 0n;
  const other = r.other ?? 0n;
  return {
    hasData: running + runnable + uninterruptible + sleeping + other > 0n,
    runningNs: running,
    runnableNs: runnable,
    uninterruptibleNs: uninterruptible,
    sleepingNs: sleeping,
    otherNs: other,
  };
}
