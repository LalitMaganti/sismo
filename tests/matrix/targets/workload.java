// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.
//
// JVM port of the canonical matrix workload (see workload.c for the shape).
// Java/Kotlin methods running on HotSpot are a known sismo gap: the native
// samples land in libjvm and anonymous JITed code, so the sismo_wl_* methods
// are unnamed. This target pins down what a Java user sees today — only native
// VM frames, plus the DIA-5 "JVM detected" diagnostic. sismo_wl_block sleeps
// for a real futex-style block (off-CPU), not a busy spin.
//
// The class is package-private so the file name (workload.java) need not match
// the class name.

class Workload {
  static long sismo_wl_leaf(long x) {
    for (int i = 0; i < 4096; i++) {
      x = x * 2654435761L + i;
    }
    return x;
  }

  static long sismo_wl_mid(long x) {
    for (int i = 0; i < 8; i++) {
      x = sismo_wl_leaf(x ^ i);
    }
    return x;
  }

  static long sismo_wl_outer(long x) {
    for (int i = 0; i < 4; i++) {
      x = sismo_wl_mid(x + i);
    }
    return x;
  }

  static void sismo_wl_block() {
    try {
      Thread.sleep(2);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  public static void main(String[] args) {
    long durationMs = args.length > 0 ? Long.parseLong(args[0]) : 3000;
    long end = System.currentTimeMillis() + durationMs;
    long x = 1;
    long iters = 0;
    while (System.currentTimeMillis() < end) {
      x = sismo_wl_outer(x);
      iters++;
      if (iters % 8 == 0) {
        sismo_wl_block();
      }
    }
    System.out.println("sismo-workload iters=" + iters + " x=" + x);
  }
}
