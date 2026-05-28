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

import type {Trace} from '../../public/trace';
import {NUM, NUM_NULL} from '../../trace_processor/query_result';

// The processes Sismo is profiling, as picked at record time by `sismo
// record`. Everything else in the trace is "context".
export interface PrivilegedSet {
  readonly pids: ReadonlyArray<number>;
  readonly upids: ReadonlyArray<number>;
}

export const EMPTY_PRIVILEGED_SET: PrivilegedSet = {pids: [], upids: []};

// TODO: replace with a real JSON-in-zip sidecar. The marker-event mechanism
// this reads is a deliberate hack — see the matching emit site in
// src/cmd_record.zig. Do not extend this pattern; when the sidecar lands,
// both this reader and the emitter get deleted.
const MARKER_SLICE_NAME = 'sismo_temporary_privileged_pid_marker';

export async function loadPrivilegedSet(trace: Trace): Promise<PrivilegedSet> {
  const pids = await readMarkerPids(trace);
  if (pids.length === 0) return EMPTY_PRIVILEGED_SET;
  const upids = await resolveUpids(trace, pids);
  return {pids, upids};
}

async function readMarkerPids(trace: Trace): Promise<number[]> {
  // trace_processor namespaces TrackEvent debug_annotations under `debug.`;
  // accept the bare `pid` too as a fallback.
  const res = await trace.engine.query(`
    SELECT DISTINCT CAST(args.int_value AS INTEGER) AS pid
    FROM slice
    JOIN args USING (arg_set_id)
    WHERE slice.name = '${MARKER_SLICE_NAME}'
      AND (args.key = 'debug.pid' OR args.key = 'pid')
      AND args.int_value IS NOT NULL
  `);
  const pids: number[] = [];
  for (const it = res.iter({pid: NUM_NULL}); it.valid(); it.next()) {
    if (it.pid !== null) pids.push(it.pid);
  }
  return pids;
}

async function resolveUpids(
  trace: Trace,
  pids: ReadonlyArray<number>,
): Promise<number[]> {
  if (pids.length === 0) return [];
  const pidList = pids.join(',');
  const res = await trace.engine.query(`
    SELECT upid FROM process WHERE pid IN (${pidList})
  `);
  const upids: number[] = [];
  for (const it = res.iter({upid: NUM}); it.valid(); it.next()) {
    upids.push(it.upid);
  }
  return upids;
}
