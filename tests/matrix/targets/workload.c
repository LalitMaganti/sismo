// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.
//
// Canonical matrix workload. Every language port must keep the same shape:
//   sismo_wl_outer -> sismo_wl_mid -> sismo_wl_leaf   (hot, noinline chain)
//   sismo_wl_block                                    (2 ms sleep, off-CPU)
// argv[1] = duration in ms (default 3000). Prints "sismo-workload iters=N"
// on exit so the bench harness can compute throughput.
//
// Also compiled as C++ by the harness (g++ -x c++) to exercise mangling.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define NOINLINE __attribute__((noinline))

static volatile uint64_t sink;

NOINLINE uint64_t sismo_wl_leaf(uint64_t x) {
  for (uint64_t i = 0; i < 4096; i++) x = x * 2654435761u + i;
  return x;
}

NOINLINE uint64_t sismo_wl_mid(uint64_t x) {
  for (uint64_t i = 0; i < 8; i++) x = sismo_wl_leaf(x ^ i);
  return x;
}

NOINLINE uint64_t sismo_wl_outer(uint64_t x) {
  for (uint64_t i = 0; i < 4; i++) x = sismo_wl_mid(x + i);
  return x;
}

NOINLINE void sismo_wl_block(void) {
  struct timespec ts = {0, 2000000};
  nanosleep(&ts, NULL);
}

static uint64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

int main(int argc, char **argv) {
  uint64_t duration_ms = argc > 1 ? strtoull(argv[1], NULL, 10) : 3000;
  uint64_t end = now_ms() + duration_ms;
  uint64_t x = 1, iters = 0;
  while (now_ms() < end) {
    x = sismo_wl_outer(x);
    iters++;
    if (iters % 32 == 0) sismo_wl_block();
  }
  sink = x;
  printf("sismo-workload iters=%llu\n", (unsigned long long)iters);
  return 0;
}
