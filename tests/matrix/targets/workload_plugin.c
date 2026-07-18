// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.
//
// Plugin shared object for workload_dlopen.c. Loaded mid-recording.

#include <stdint.h>

#define NOINLINE __attribute__((noinline))

NOINLINE uint64_t sismo_plugin_leaf(uint64_t x) {
  for (uint64_t i = 0; i < 4096; i++) x = x * 2654435761u + i;
  return x;
}

NOINLINE uint64_t sismo_plugin_outer(uint64_t x) {
  for (uint64_t i = 0; i < 32; i++) x = sismo_plugin_leaf(x + i);
  return x;
}
