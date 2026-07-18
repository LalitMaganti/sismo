// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.
//
// Node port of the canonical matrix workload (see workload.c for the
// shape). JIT frames are a known sismo gap; this target pins down what a
// Node user sees today. sismo_wl_block uses Atomics.wait for a real
// futex-style block (off-CPU), not a timer yield.

"use strict";

function sismo_wl_leaf(x) {
  for (let i = 0n; i < 4096n; i++) {
    x = (x * 2654435761n + i) & 0xffffffffffffffffn;
  }
  return x;
}

function sismo_wl_mid(x) {
  for (let i = 0n; i < 8n; i++) {
    x = sismo_wl_leaf(x ^ i);
  }
  return x;
}

function sismo_wl_outer(x) {
  for (let i = 0n; i < 4n; i++) {
    x = sismo_wl_mid(x + i);
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
  let x = 1n;
  let iters = 0;
  while (Date.now() < end) {
    x = sismo_wl_outer(x);
    iters++;
    if (iters % 8 === 0) sismo_wl_block();
  }
  console.log(`sismo-workload iters=${iters}`);
}

main();
