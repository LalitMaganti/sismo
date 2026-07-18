# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.
#
# Python port of the canonical matrix workload (see workload.c for the
# shape). Interpreter frames are a known sismo gap; this target exists to
# pin down what a Python user sees today.

import sys
import time


def sismo_wl_leaf(x):
    for i in range(4096):
        x = (x * 2654435761 + i) & 0xFFFFFFFFFFFFFFFF
    return x


def sismo_wl_mid(x):
    for i in range(8):
        x = sismo_wl_leaf(x ^ i)
    return x


def sismo_wl_outer(x):
    for i in range(4):
        x = sismo_wl_mid(x + i)
    return x


def sismo_wl_block():
    time.sleep(0.002)


def main():
    duration_ms = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    end = time.monotonic() + duration_ms / 1000.0
    x = 1
    iters = 0
    while time.monotonic() < end:
        x = sismo_wl_outer(x)
        iters += 1
        if iters % 4 == 0:
            sismo_wl_block()
    print(f"sismo-workload iters={iters}")


if __name__ == "__main__":
    main()
