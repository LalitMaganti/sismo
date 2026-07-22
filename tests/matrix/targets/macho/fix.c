// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.
//
// Canonical mach-o symbolization fixture (matrix-mac suite). Never executed:
// the suite reads marker addresses with nm and synthesizes a trace at them.
// Keep the sismo_fix_leaf/sismo_fix_mid/main marker chain — every language
// port of this fixture carries the same three markers.
//
// SISMO_FIX_REV changes the generated code (and therefore LC_UUID) so the
// replaced-binary case can rebuild "a different program" at the same path.

#ifndef SISMO_FIX_REV
#define SISMO_FIX_REV 1
#endif

__attribute__((noinline)) int sismo_fix_leaf(int x) {
    int acc = SISMO_FIX_REV;
    for (int i = 0; i < x; i++) acc += i * i;
    return acc;
}

__attribute__((noinline)) int sismo_fix_mid(int x) {
    return sismo_fix_leaf(x) + 1;
}

int main(void) {
    return sismo_fix_mid(100) & 0;
}
