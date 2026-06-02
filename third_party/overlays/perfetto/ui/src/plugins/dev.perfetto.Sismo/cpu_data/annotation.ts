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

// Data for the Source/Assembly view — VTune's annotated source + disassembly.
//
// Two parts that meet here:
//   1. COUNTS (always available, computed from the trace): how many timer
//      samples landed on each instruction address (rel_pc) and, via the symbol
//      table, each source line. These are self-time leaf counts.
//   2. TEXT (bundled by `sismo record`, optional): the source file contents and
//      a disassembly listing, carried over the deliberately-ugly track-event /
//      args sidecar channel (see sismo_privileged_marker.zig). Absent on traces
//      recorded before the producer shipped, or for stripped binaries — the view
//      degrades to counts-only.
//
// HONESTY: counts attribute a sample to the instruction pointer caught at the
// tick. Without PEBS/LBR the IP can skid a few instructions past the one that
// actually stalled, so a hot line is a neighbourhood, not a precise culprit.

import type {Engine} from '../../../trace_processor/engine';
import {LONG, NUM, NUM_NULL, STR_NULL} from '../../../trace_processor/query_result';
import type {PrivilegedSet} from '../privileged_set';
import {frameNameExpr, sampleScopePredicate} from './sql';

// One disassembled instruction with its sample count.
export interface AnnInsn {
  readonly relPc: bigint;
  // Lowercase hex of the raw bytes, or '' when no disasm was bundled.
  readonly bytes: string;
  // Mnemonic + operands, or a synthetic `0x…` label when no disasm was bundled.
  readonly text: string;
  readonly samples: number;
}

// One source line: its text (when bundled), the self samples summed over the
// instructions on it, and those instructions (for the interleaved asm view).
export interface AnnRow {
  readonly line: number | null;
  readonly text: string;
  readonly samples: number;
  readonly insns: ReadonlyArray<AnnInsn>;
}

export interface SourceAsm {
  readonly name: string;
  readonly file: string | null;
  // Sum of self samples across the function (the per-line share denominator).
  readonly totalSelf: number;
  readonly maxLineSamples: number;
  readonly rows: ReadonlyArray<AnnRow>;
  readonly hasSource: boolean;
  readonly hasDisasm: boolean;
  // The flat per-instruction counts — the honest floor, always present even when
  // neither source nor disasm was bundled (rel_pc comes from the frame table).
  readonly insnCounts: ReadonlyArray<AnnInsn>;
}

// The sidecar track name the collector appends to (kept identical here and in
// perf_symbolize.zig). Records are distinguished by the slice (TrackEvent) name
// 'sismo_src' / 'sismo_asm'.
const SIDECAR_SRC = 'sismo_src';
const SIDECAR_ASM = 'sismo_asm';

// Cap how many source lines we render as a contiguous body around the sampled
// region; beyond this we fall back to the referenced lines only, to avoid
// rendering an enormous file when inlining scatters line numbers.
const MAX_BODY_LINES = 4000;

interface RelPcCount {
  relPc: bigint;
  line: number | null;
  sourceFile: string | null;
  samples: number;
}

export async function loadSourceAsm(
  engine: Engine,
  priv: PrivilegedSet,
  name: string,
): Promise<SourceAsm> {
  const counts = await loadRelPcCounts(engine, priv, name);
  const totalSelf = counts.reduce((a, r) => a + r.samples, 0);

  // The function's source file = the file most of its samples resolve to.
  const file = dominantFile(counts);

  const sampleByRelPc = new Map<bigint, number>();
  for (const r of counts) sampleByRelPc.set(r.relPc, r.samples);

  const disasm = file !== null || counts.length > 0
    ? await loadDisasm(engine, name)
    : null;
  const source = file !== null ? await loadSourceText(engine, file) : null;

  // Per-line self-sample totals (only lines belonging to the chosen file).
  const lineSamples = new Map<number, number>();
  for (const r of counts) {
    if (r.line === null) continue;
    if (file !== null && r.sourceFile !== null && r.sourceFile !== file) continue;
    lineSamples.set(r.line, (lineSamples.get(r.line) ?? 0) + r.samples);
  }

  // Instructions grouped by source line (from the bundled disasm's addr→line).
  const insnsByLine = new Map<number, AnnInsn[]>();
  const insnCounts: AnnInsn[] = [];
  if (disasm !== null) {
    for (const di of disasm) {
      const insn: AnnInsn = {
        relPc: di.relPc,
        bytes: di.bytes,
        text: di.text,
        samples: sampleByRelPc.get(di.relPc) ?? 0,
      };
      insnCounts.push(insn);
      if (di.line !== null && di.line > 0) {
        const arr = insnsByLine.get(di.line);
        if (arr) arr.push(insn);
        else insnsByLine.set(di.line, [insn]);
      }
    }
  } else {
    // No disasm: the honest floor is the per-rel_pc histogram with synthetic
    // labels, ordered by address.
    for (const r of [...counts].sort((a, b) => Number(a.relPc - b.relPc))) {
      insnCounts.push({
        relPc: r.relPc,
        bytes: '',
        text: `0x${r.relPc.toString(16)}`,
        samples: r.samples,
      });
    }
  }

  const rows = buildRows(file, source, lineSamples, insnsByLine, counts);
  const maxLineSamples = rows.reduce((a, r) => Math.max(a, r.samples), 0);

  return {
    name,
    file,
    totalSelf,
    maxLineSamples,
    rows,
    hasSource: source !== null,
    hasDisasm: disasm !== null,
    insnCounts,
  };
}

// Per-rel_pc self-sample counts for the function, with the innermost symbol's
// source file + line (the same innermost-row selection frameNameExpr uses).
async function loadRelPcCounts(
  engine: Engine,
  priv: PrivilegedSet,
  name: string,
): Promise<RelPcCount[]> {
  const scope = sampleScopePredicate(priv);
  const esc = name.replace(/'/g, "''");
  const nameExpr = frameNameExpr('f', null);
  const inner = (col: string) => `(
    SELECT sps.${col} FROM stack_profile_symbol sps
    WHERE sps.symbol_set_id = f.symbol_set_id ORDER BY sps.id LIMIT 1
  )`;
  const res = await engine.query(`
    SELECT
      f.rel_pc AS rel_pc,
      ${inner('source_file')} AS source_file,
      ${inner('line_number')} AS line_number,
      count(*) AS samples
    FROM perf_sample s
    JOIN stack_profile_callsite c ON c.id = s.callsite_id
    JOIN stack_profile_frame f ON f.id = c.frame_id
    WHERE s.callsite_id IS NOT NULL AND ${nameExpr} = '${esc}' ${scope}
    GROUP BY f.rel_pc
    ORDER BY f.rel_pc
  `);
  const out: RelPcCount[] = [];
  for (
    const it = res.iter({
      rel_pc: LONG,
      source_file: STR_NULL,
      line_number: NUM_NULL,
      samples: NUM,
    });
    it.valid();
    it.next()
  ) {
    out.push({
      relPc: it.rel_pc,
      line: it.line_number,
      sourceFile: it.source_file,
      samples: it.samples,
    });
  }
  return out;
}

function dominantFile(counts: ReadonlyArray<RelPcCount>): string | null {
  const byFile = new Map<string, number>();
  for (const r of counts) {
    if (r.sourceFile === null) continue;
    byFile.set(r.sourceFile, (byFile.get(r.sourceFile) ?? 0) + r.samples);
  }
  let best: string | null = null;
  let bestN = 0;
  for (const [f, n] of byFile) {
    if (n > bestN) {
      best = f;
      bestN = n;
    }
  }
  return best;
}

// Assemble the rendered rows. With source text: the contiguous body from the
// first to the last sampled line (so the function reads as real code), each line
// carrying its counts and instructions. Without source: one row per sampled (or
// disassembled) line, sparse.
function buildRows(
  file: string | null,
  source: ReadonlyArray<string> | null,
  lineSamples: ReadonlyMap<number, number>,
  insnsByLine: ReadonlyMap<number, AnnInsn[]>,
  counts: ReadonlyArray<RelPcCount>,
): AnnRow[] {
  const referenced = new Set<number>([
    ...lineSamples.keys(),
    ...insnsByLine.keys(),
  ]);
  if (referenced.size === 0) return [];
  const minLine = Math.min(...referenced);
  const maxLine = Math.max(...referenced);

  const mk = (line: number): AnnRow => ({
    line,
    text: source !== null ? (source[line - 1] ?? '') : '',
    samples: lineSamples.get(line) ?? 0,
    insns: insnsByLine.get(line) ?? [],
  });

  if (source !== null && maxLine - minLine + 1 <= MAX_BODY_LINES) {
    const rows: AnnRow[] = [];
    for (let line = minLine; line <= maxLine; line++) rows.push(mk(line));
    return rows;
  }

  // Sparse: just the referenced lines, in order.
  void file;
  void counts;
  return [...referenced].sort((a, b) => a - b).map(mk);
}

// ---- Bundled-text seam ----------------------------------------------------
//
// These read the track-event/args sidecar `sismo record` appends. They return
// null on traces with no sidecar (today's traces), so the view degrades to
// counts-only with no UI change once the producer lands.

interface DisasmInsn {
  relPc: bigint;
  bytes: string;
  text: string;
  line: number | null;
}

// Source file text, split into lines, or null when the file wasn't bundled.
async function loadSourceText(
  engine: Engine,
  path: string,
): Promise<string[] | null> {
  const esc = path.replace(/'/g, "''");
  const text = await readChunked(engine, SIDECAR_SRC, 'debug.path', esc);
  return text === null ? null : text.split('\n');
}

// The disassembly listing for one function, or null when not bundled.
async function loadDisasm(
  engine: Engine,
  name: string,
): Promise<DisasmInsn[] | null> {
  const esc = name.replace(/'/g, "''");
  const json = await readChunked(engine, SIDECAR_ASM, 'debug.func', esc);
  if (json === null) return null;
  try {
    const arr = JSON.parse(json) as Array<{
      a: string;
      b?: string;
      t?: string;
      l?: number;
    }>;
    return arr.map((e) => ({
      relPc: BigInt(e.a),
      bytes: e.b ?? '',
      text: e.t ?? '',
      line: e.l != null && e.l > 0 ? e.l : null,
    }));
  } catch {
    return null;
  }
}

// Read a sidecar record's payload, reassembling chunks. A record is a set of
// `slice`s named `sliceName` whose `keyArg` (a debug.* arg) equals `keyVal`;
// each carries `debug.text` and an optional `debug.chunk` ordinal. Returns the
// concatenated text, or null when no such record exists.
async function readChunked(
  engine: Engine,
  sliceName: string,
  keyArg: string,
  keyVal: string,
): Promise<string | null> {
  const res = await engine.query(`
    SELECT
      coalesce((
        SELECT a.int_value FROM args a
        WHERE a.arg_set_id = sl.arg_set_id AND a.key = 'debug.chunk'
      ), 0) AS chunk,
      (
        SELECT a.string_value FROM args a
        WHERE a.arg_set_id = sl.arg_set_id AND a.key = 'debug.text'
      ) AS text
    FROM slice sl
    WHERE sl.name = '${sliceName}'
      AND sl.arg_set_id IN (
        SELECT a.arg_set_id FROM args a
        WHERE a.key = '${keyArg}' AND a.string_value = '${keyVal}'
      )
    ORDER BY chunk
  `);
  const parts: string[] = [];
  for (
    const it = res.iter({chunk: NUM_NULL, text: STR_NULL});
    it.valid();
    it.next()
  ) {
    if (it.text !== null) parts.push(it.text);
  }
  return parts.length === 0 ? null : parts.join('');
}
