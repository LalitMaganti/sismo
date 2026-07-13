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

// Sismo's latency SQL package: stdlib-style modules the latency loaders INCLUDE.
// Registered once per trace on the engine (see the plugin's onTraceLoad); the
// module system makes INCLUDE idempotent, so the heavy occupancy table is built
// at most once, on the first latency query — no work on page load, no existence
// guard, shared by every latency view. Both modules read the profiled set from
// the record-time marker slice, so they need no runtime parameters.
//
// Perfetto resolves the package from a module name's first dotted segment, so
// the package is `sismo` and every module is `sismo.*`.

// `_sismo_priv` — utids of the profiled processes (a flat join off the marker).
const LATENCY_BASE = `
CREATE PERFETTO TABLE _sismo_priv AS
SELECT DISTINCT t.utid AS utid, t.upid AS upid
FROM slice s
JOIN args a ON a.arg_set_id = s.arg_set_id AND a.key = 'debug.pid'
JOIN process p ON p.pid = CAST(a.int_value AS INT)
JOIN thread t ON t.upid = p.upid
WHERE s.name = 'sismo_temporary_privileged_pid_marker';
`;

// `_sismo_runnable_occ` — exact per-thread occupancy of the cores during the
// profiled threads' runnable-but-not-scheduled windows (the ~1s
// interval_intersect), cached so the landing block and the "Who it waited on"
// tab share one computation.
const LATENCY_CONTENTION = `
INCLUDE PERFETTO MODULE sismo.latency;
INCLUDE PERFETTO MODULE intervals.intersect;

CREATE PERFETTO TABLE _sismo_runnable_occ AS
WITH pr AS (
  SELECT ts.id, ts.ts, ts.dur
  FROM thread_state ts
  JOIN _sismo_priv p ON p.utid = ts.utid
  WHERE ts.state IN ('R', 'R+') AND ts.dur > 0
),
running AS (
  SELECT s.id, s.ts, s.dur, s.utid AS utid,
    iif(pv.utid IS NOT NULL, 1, 0) AS is_self
  FROM sched s
  JOIN thread t ON t.utid = s.utid AND t.is_idle = 0
  LEFT JOIN _sismo_priv pv ON pv.utid = s.utid
  WHERE s.dur > 0
),
isect AS (
  SELECT r.is_self, r.utid, ii.dur
  FROM _interval_intersect!((pr, running), ()) ii
  JOIN running r ON r.id = ii.id_1
)
SELECT is_self, utid, sum(dur) AS occ
FROM isect
GROUP BY is_self, utid;
`;

// `_sismo_offcpu_trim` — maps each off-CPU leaf callsite to the callsite that
// CALLED the scheduler (the parent of the shallowest schedule/preempt_schedule
// frame). Re-rooting the blocking stacks there drops the bpf/sched_switch/
// __schedule tail so the leaf becomes the real blocking call (do_nanosleep,
// futex_do_wait, anon_pipe_read, …) instead of the scheduler. Cheap: the walk is
// over the few hundred distinct off-CPU callsites.
const OFFCPU_TRIM = `
CREATE PERFETTO TABLE _sismo_offcpu_trim AS
WITH RECURSIVE
roots AS (
  SELECT DISTINCT p.callsite_id AS cs
  FROM perf_sample p
  JOIN thread_counter_track tct
    ON tct.utid = p.utid AND tct.name = 'off-cpu-ns'
  JOIN counter c ON c.track_id = tct.id AND c.ts = p.ts
  WHERE p.callsite_id IS NOT NULL
),
chain(leaf, cur, depth) AS (
  SELECT cs, cs, 0 FROM roots
  UNION ALL
  SELECT ch.leaf, sc.parent_id, ch.depth + 1
  FROM chain ch
  JOIN stack_profile_callsite sc ON sc.id = ch.cur
  WHERE sc.parent_id IS NOT NULL
),
sched_hit AS (
  SELECT ch.leaf AS leaf, sc.parent_id AS trimmed,
    row_number() OVER (PARTITION BY ch.leaf ORDER BY ch.depth DESC) AS rn
  FROM chain ch
  JOIN stack_profile_callsite sc ON sc.id = ch.cur
  JOIN stack_profile_frame f ON f.id = sc.frame_id
  WHERE f.name GLOB 'schedule' OR f.name GLOB '__schedule'
     OR f.name GLOB 'preempt_schedule*'
)
SELECT
  h.leaf AS leaf_cs,
  h.trimmed AS trimmed_cs,
  -- The trimmed leaf (the caller of schedule) tells voluntary from involuntary:
  -- a real wait (futex_do_wait, do_nanosleep, …) vs a preemption return path.
  CASE
    WHEN tf.name GLOB '*_interrupt' OR tf.name GLOB 'irqentry_exit*'
      OR tf.name GLOB 'exit_to_user_mode*' OR tf.name GLOB 'preempt_schedule*'
    THEN 'involuntary' ELSE 'voluntary'
  END AS kind
FROM sched_hit h
JOIN stack_profile_callsite tc ON tc.id = h.trimmed
JOIN stack_profile_frame tf ON tf.id = tc.frame_id
WHERE h.rn = 1 AND h.trimmed IS NOT NULL;
`;

// `_sismo_locks` — per-lock contention for the profiled processes, keyed by the
// futex uaddr the BPF collector stamps onto every off-CPU futex wait (rides in
// perf_sample.data_address). Every contended pthread / Go / JVM lock funnels
// through futex(), so the uaddr clusters waits by lock INSTANCE regardless of
// language — two locks acquired at the same code site stay distinct, which a
// stack-only view can't do. Each lock carries its total wait, wait count,
// distinct waiter threads, and dominant contention site (the caller of the lock
// primitive). Built once per trace, read by the Locks tab.
const LOCKS = `
INCLUDE PERFETTO MODULE sismo.latency;

CREATE PERFETTO TABLE _sismo_lock_cs AS
SELECT c.id AS cs, c.parent_id AS parent,
       coalesce(sym.name, f.name, '?') AS name,
       (f.mapping NOT IN (
          SELECT id FROM stack_profile_mapping
          WHERE name GLOB '*kernel*' OR name = '[kernel.kallsyms]')) AS is_user
FROM stack_profile_callsite c
JOIN stack_profile_frame f ON f.id = c.frame_id
LEFT JOIN stack_profile_symbol sym ON sym.symbol_set_id = f.symbol_set_id;

-- Contention site = the caller of the lock primitive (the parent of the deepest
-- user frame) for each off-CPU futex-wait leaf callsite. The leaf's user stack
-- bottoms out in __lll_lock_wait / pthread_mutex_lock; its caller is where the
-- lock is taken.
CREATE PERFETTO TABLE _sismo_lock_site AS
WITH RECURSIVE
roots AS (
  SELECT DISTINCT p.callsite_id AS cs
  FROM perf_sample p
  JOIN thread_counter_track tct ON tct.utid = p.utid AND tct.name = 'off-cpu-ns'
  JOIN counter c ON c.track_id = tct.id AND c.ts = p.ts
  -- Locks only: positive futex uaddrs. Network peers set bit 63 (negative).
  WHERE p.data_address > 0 AND p.callsite_id IS NOT NULL
),
chain(leaf, cur, depth) AS (
  SELECT cs, cs, 0 FROM roots
  UNION ALL
  SELECT ch.leaf, ci.parent, ch.depth + 1
  FROM chain ch JOIN _sismo_lock_cs ci ON ci.cs = ch.cur
  WHERE ci.parent IS NOT NULL
),
prim AS (
  SELECT ch.leaf, ci.parent AS site_cs,
    row_number() OVER (PARTITION BY ch.leaf ORDER BY ch.depth) AS rn
  FROM chain ch JOIN _sismo_lock_cs ci ON ci.cs = ch.cur
  WHERE ci.is_user = 1
)
SELECT p.leaf AS leaf_cs, coalesce(s.name, '?') AS site
FROM prim p LEFT JOIN _sismo_lock_cs s ON s.cs = p.site_cs
WHERE p.rn = 1;

-- Per-sample weighted lock waits for the profiled processes, cached so the lock
-- list and each lock's detail drill read one table. wait = delta of the
-- cumulative per-thread off-cpu-ns counter (a double); the first sample on a
-- thread has no predecessor (lag NULL) → coalesce to 0.
CREATE PERFETTO TABLE _sismo_lock_waits AS
SELECT p.utid AS utid, p.ts AS ts, p.callsite_id AS cs, p.data_address AS lock,
  max(0, coalesce(
    c.value - lag(c.value) OVER (PARTITION BY p.utid ORDER BY p.ts), 0)) AS w
FROM perf_sample p
JOIN _sismo_priv pv ON pv.utid = p.utid
JOIN thread_counter_track tct ON tct.utid = p.utid AND tct.name = 'off-cpu-ns'
JOIN counter c ON c.track_id = tct.id AND c.ts = p.ts
-- Locks only: positive futex uaddrs. Network peers set bit 63 (negative).
WHERE p.data_address > 0;

CREATE PERFETTO TABLE _sismo_locks AS
WITH offw AS (
  SELECT utid, cs, lock, w FROM _sismo_lock_waits
),
tot AS (
  -- The off-cpu-ns counter is a double; cast the summed wait back to integer ns.
  SELECT lock, CAST(sum(w) AS INT) AS wait_ns, count(*) AS waits,
         count(DISTINCT utid) AS threads
  FROM offw GROUP BY lock
),
dom AS (
  -- Dominant contention site per lock + how many distinct sites take it.
  SELECT lock, site,
    row_number() OVER (PARTITION BY lock ORDER BY sw DESC) AS rn,
    count(*) OVER (PARTITION BY lock) AS nsites
  FROM (
    SELECT o.lock, coalesce(s.site, '?') AS site, sum(o.w) AS sw
    FROM offw o LEFT JOIN _sismo_lock_site s ON s.leaf_cs = o.cs
    GROUP BY o.lock, coalesce(s.site, '?')
  )
)
SELECT t.lock AS lock_addr, d.site AS site, d.nsites AS site_count,
       t.wait_ns AS wait_ns, t.waits AS waits, t.threads AS threads
FROM tot t JOIN dom d ON d.lock = t.lock AND d.rn = 1
-- HEURISTIC (prototype): keep only locks we could attribute to a real
-- acquisition site. When the only name above the block is the wait primitive
-- itself (a bare futex/cond/lll frame), it's a condvar/join wait, not an
-- actionable app lock — drop it rather than show unactionable noise.
WHERE d.site != '?'
  AND d.site NOT GLOB '*futex*'
  AND d.site NOT GLOB '*__lll_*'
  AND d.site NOT GLOB '*cond*wait*';
`;

// `_sismo_wait` — every off-CPU sample of the profiled threads tagged with WHAT
// it was waiting for (the wait-type axis: lock / signaling / disk / network /
// pipe / sleep / poll / memory / other), weighted by the off-cpu-ns delta. The
// type comes from the trimmed kernel wait primitive (the caller of schedule,
// from sismo.offcpu), except futex waits, which the uaddr splits into real
// mutex contention (in _sismo_locks) vs condvar/signaling. Involuntary
// preemption (runnable, not a wait-for) is bucketed 'scheduling' so the blocked
// breakdown can exclude it. Powers the Summary's kind-of-wait breakdown and the
// flamegraph type lens. GLOBs are best-effort kernel-name matches.
const WAIT_TYPES = `
INCLUDE PERFETTO MODULE sismo.latency;
INCLUDE PERFETTO MODULE sismo.offcpu;
INCLUDE PERFETTO MODULE sismo.locks;

CREATE PERFETTO TABLE _sismo_offcpu_waits AS
SELECT p.utid AS utid, p.callsite_id AS leaf_cs, p.data_address AS lock,
  max(0, coalesce(
    c.value - lag(c.value) OVER (PARTITION BY p.utid ORDER BY p.ts), 0)) AS w
FROM perf_sample p
JOIN _sismo_priv pv ON pv.utid = p.utid
JOIN thread_counter_track tct ON tct.utid = p.utid AND tct.name = 'off-cpu-ns'
JOIN counter c ON c.track_id = tct.id AND c.ts = p.ts;

CREATE PERFETTO TABLE _sismo_wait AS
SELECT ow.utid AS utid, ow.leaf_cs AS leaf_cs, ow.w AS w,
  CASE
    WHEN tr.kind = 'involuntary' THEN 'scheduling'
    -- A block_id with bit 63 set is a TCP peer (stamped by the tcp_recvmsg
    -- kprobe), stored as a negative int64 — a definitive network signal that
    -- beats the schedule_timeout kernel primitive (which else reads as 'sleep').
    WHEN ow.lock < 0 THEN 'network'
    WHEN ow.lock != 0 AND ow.lock IN (SELECT lock_addr FROM _sismo_locks)
      THEN 'lock'
    WHEN ow.lock != 0 THEN 'signaling'
    WHEN pf.name GLOB '*nanosleep*' OR pf.name GLOB '*schedule_timeout*'
      OR pf.name GLOB 'hrtimer*' THEN 'sleep'
    WHEN pf.name GLOB 'pipe_*' OR pf.name GLOB '*anon_pipe*' THEN 'pipe'
    WHEN pf.name GLOB 'sk_wait*' OR pf.name GLOB 'tcp_*'
      OR pf.name GLOB 'unix_stream*' OR pf.name GLOB 'inet_*' THEN 'network'
    WHEN pf.name GLOB 'io_schedule*' OR pf.name GLOB '*wait_on_page*'
      OR pf.name GLOB 'folio_wait*' OR pf.name GLOB '*blk_*' THEN 'disk'
    WHEN pf.name GLOB '*epoll*' OR pf.name GLOB 'do_select'
      OR pf.name GLOB 'do_poll' THEN 'poll'
    WHEN pf.name GLOB '*swap_page*' OR pf.name GLOB '*_reclaim*' THEN 'memory'
    ELSE 'other'
  END AS wait_type
FROM _sismo_offcpu_waits ow
LEFT JOIN _sismo_offcpu_trim tr ON tr.leaf_cs = ow.leaf_cs
LEFT JOIN _sismo_lock_cs pf ON pf.cs = tr.trimmed_cs;

-- Per-peer network waits (bit-63-tagged block_id = a TCP peer). Cluster the
-- profiled threads' blocking recvs by the remote they wait on: the network
-- analog of _sismo_locks. addr is the low 32 bits (be32, so octet1 = &0xff),
-- port is bits 32..47. Keyed by the raw peer id for the drill.
CREATE PERFETTO TABLE _sismo_net AS
SELECT ow.lock AS peer_id,
  printf('%d.%d.%d.%d',
    (ow.lock & 0xff), ((ow.lock >> 8) & 0xff),
    ((ow.lock >> 16) & 0xff), ((ow.lock >> 24) & 0xff)) AS addr,
  ((ow.lock >> 32) & 0xffff) AS port,
  CAST(sum(ow.w) AS INT) AS wait_ns,
  count(*) AS blocks,
  count(DISTINCT ow.utid) AS threads
FROM _sismo_offcpu_waits ow
WHERE ow.lock < 0
GROUP BY ow.lock;

-- Dominant wait type per off-CPU leaf callsite (by weight), derived from the
-- one _sismo_wait classifier — so the flamegraph type filter narrows by
-- callsite_id against a few-hundred-row table (fast) with no duplicated rules.
CREATE PERFETTO TABLE _sismo_wait_leaf AS
SELECT leaf_cs, wait_type FROM (
  SELECT leaf_cs, wait_type,
    row_number() OVER (PARTITION BY leaf_cs ORDER BY sum(w) DESC) AS rn
  FROM _sismo_wait
  WHERE leaf_cs IS NOT NULL
  GROUP BY leaf_cs, wait_type
)
WHERE rn = 1;
`;

export const LATENCY_MODULE_BASE = 'sismo.latency';
export const LATENCY_MODULE_CONTENTION = 'sismo.latency_contention';
export const LATENCY_MODULE_OFFCPU = 'sismo.offcpu';
export const LATENCY_MODULE_LOCKS = 'sismo.locks';
export const LATENCY_MODULE_WAIT_TYPES = 'sismo.wait_types';

// The package to register on the engine in the plugin's onTraceLoad.
export const LATENCY_SQL_PACKAGE = {
  name: 'sismo',
  modules: [
    {name: LATENCY_MODULE_BASE, sql: LATENCY_BASE},
    {name: LATENCY_MODULE_CONTENTION, sql: LATENCY_CONTENTION},
    {name: LATENCY_MODULE_OFFCPU, sql: OFFCPU_TRIM},
    {name: LATENCY_MODULE_LOCKS, sql: LOCKS},
    {name: LATENCY_MODULE_WAIT_TYPES, sql: WAIT_TYPES},
  ],
};
