// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.
//
// Inline-frame fidelity fixture: sismo_fix_leaf is force-inlined into
// sismo_fix_mid, so a PC inside the inlined body must symbolize as the
// leaf <- mid inline chain. The suite finds that PC in the dSYM's
// DW_TAG_inlined_subroutine range.

static inline __attribute__((always_inline)) int sismo_fix_leaf(int x) {
    int acc = 0;
    for (int i = 0; i < x; i++) acc += i * i;
    return acc;
}

__attribute__((noinline)) int sismo_fix_mid(int x) {
    return sismo_fix_leaf(x) + 1;
}

int main(void) {
    return sismo_fix_mid(100) & 0;
}
