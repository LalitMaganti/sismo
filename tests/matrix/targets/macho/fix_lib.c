// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.
//
// Static-archive fixture half: the markers live in libfix.a(fix_lib.o), so
// the executable's debug map records the archive(member) N_OSO spelling.

__attribute__((noinline)) int sismo_fix_leaf(int x) {
    int acc = 0;
    for (int i = 0; i < x; i++) acc += i * i;
    return acc;
}

__attribute__((noinline)) int sismo_fix_mid(int x) {
    return sismo_fix_leaf(x) + 1;
}
