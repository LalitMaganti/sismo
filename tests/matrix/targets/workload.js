// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.
//
// Node port of the canonical matrix workload (see workload.c for the
// shape). JIT frames are a known sismo gap; this target pins down what a
// Node user sees today. sismo_wl_block uses Atomics.wait for a real
// futex-style block (off-CPU), not a timer yield.
//
// The hot path uses 32-bit Number arithmetic (Math.imul + |0), not BigInt.
// BigInt operators run inside node's own C++ (no anonymous JIT code), so the
// hot leaf never showed up as a residual JIT frame. With Number arithmetic
// V8 tiers sismo_wl_leaf/mid/outer up into anonymous executable pages, which
// sismo's residual classifier surfaces as [jit:node].

"use strict";

function sismo_wl_leaf(x) {
  for (let i = 0; i < 4096; i++) {
    x = (Math.imul(x, 2654435761) + i) | 0;
  }
  return x;
}

function sismo_wl_mid(x) {
  for (let i = 0; i < 8; i++) {
    x = sismo_wl_leaf(x ^ i);
  }
  return x;
}

function sismo_wl_outer(x) {
  for (let i = 0; i < 4; i++) {
    x = sismo_wl_mid((x + i) | 0);
  }
  return x;
}

const blockBuf = new Int32Array(new SharedArrayBuffer(4));
function sismo_wl_block() {
  Atomics.wait(blockBuf, 0, 0, 2);
}

function main() {
  const durationMs = process.argv.length > 2 ? parseInt(process.argv[2], 10) : 3000;
  const end = Date.now() + durationMs;
  let x = 1;
  let iters = 0;
  while (Date.now() < end) {
    x = sismo_wl_outer(x);
    iters++;
    if (iters % 8 === 0) sismo_wl_block();
  }
  console.log(`sismo-workload iters=${iters}`);
}

main();
