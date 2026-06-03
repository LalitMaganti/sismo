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

// Lane assignment for the disassembly's branch-arrow gutter (objdump
// --visualize-jumps / IDA style). Each local jump becomes an arc from its
// instruction to its target; arcs are packed into lanes so overlapping ones
// never collide, with tight loops drawn innermost.

import type {AnnInsn} from '../cpu_data';

export interface Arc {
  // Row indices into the rendered instruction list.
  readonly fromIdx: number;
  readonly toIdx: number;
  // Lane 0 sits closest to the code; higher lanes nest further left.
  readonly lane: number;
  // Target at or before the branch — a loop back-edge, styled distinctly.
  readonly backEdge: boolean;
}

export interface ArcLayout {
  readonly arcs: ReadonlyArray<Arc>;
  readonly laneCount: number;
}

const EMPTY: ArcLayout = {arcs: [], laneCount: 0};

// Resolve each instruction's branch target to a row index and pack the arcs into
// non-overlapping lanes. Shortest spans are placed first so an inner loop gets a
// lower lane than the outer control flow that encloses it.
export function layoutArcs(insns: ReadonlyArray<AnnInsn>): ArcLayout {
  if (insns.length === 0) return EMPTY;
  const idxByRel = new Map<bigint, number>();
  insns.forEach((insn, i) => idxByRel.set(insn.relPc, i));

  const pending: Array<Omit<Arc, 'lane'>> = [];
  insns.forEach((insn, i) => {
    const target = insn.branchTargetRelPc;
    if (target === undefined || target === null) return;
    const toIdx = idxByRel.get(target);
    if (toIdx === undefined || toIdx === i) return;
    pending.push({fromIdx: i, toIdx, backEdge: toIdx <= i});
  });
  if (pending.length === 0) return EMPTY;

  pending.sort((a, b) => span(a) - span(b));

  // Per lane, the [lo, hi] row intervals already occupied. A new arc takes the
  // lowest lane whose intervals don't overlap its own span.
  const laneIntervals: Array<Array<readonly [number, number]>> = [];
  const arcs: Arc[] = [];
  for (const p of pending) {
    const lo = Math.min(p.fromIdx, p.toIdx);
    const hi = Math.max(p.fromIdx, p.toIdx);
    let lane = 0;
    for (;;) {
      const occ = (laneIntervals[lane] ??= []);
      if (occ.every(([a, b]) => hi < a || lo > b)) {
        occ.push([lo, hi]);
        break;
      }
      lane++;
    }
    arcs.push({...p, lane});
  }
  return {arcs, laneCount: laneIntervals.length};
}

function span(a: Omit<Arc, 'lane'>): number {
  return Math.abs(a.fromIdx - a.toIdx);
}
