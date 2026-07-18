// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.
//
// dlopen matrix workload: runs the normal hot chain for ~1/4 of the
// duration, then dlopens the plugin (argv[2]) and spends the rest inside
// sismo_plugin_outer. Exercises the late-mapping path — modules that
// appear after recording starts.

#include <dlfcn.h>
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

NOINLINE uint64_t sismo_wl_outer(uint64_t x) {
  for (uint64_t i = 0; i < 32; i++) x = sismo_wl_leaf(x + i);
  return x;
}

static uint64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

int main(int argc, char **argv) {
  uint64_t duration_ms = argc > 1 ? strtoull(argv[1], NULL, 10) : 3000;
  const char *plugin_path = argc > 2 ? argv[2] : "workload_plugin.so";

  uint64_t x = 1, iters = 0;
  uint64_t phase1_end = now_ms() + duration_ms / 4;
  while (now_ms() < phase1_end) {
    x = sismo_wl_outer(x);
    iters++;
  }

  void *h = dlopen(plugin_path, RTLD_NOW);
  if (!h) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 1;
  }
  uint64_t (*plugin_outer)(uint64_t) =
      (uint64_t (*)(uint64_t))dlsym(h, "sismo_plugin_outer");
  if (!plugin_outer) {
    fprintf(stderr, "dlsym failed: %s\n", dlerror());
    return 1;
  }

  uint64_t phase2_end = now_ms() + (duration_ms * 3) / 4;
  while (now_ms() < phase2_end) {
    x = plugin_outer(x);
    iters++;
  }

  sink = x;
  printf("sismo-workload iters=%llu\n", (unsigned long long)iters);
  return 0;
}
