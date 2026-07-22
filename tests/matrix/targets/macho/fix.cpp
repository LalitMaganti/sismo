// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.
//
// C++ port of fix.c: namespaced + template markers so the golden pins the
// exact Itanium-demangled names. Keep symbol names comma-free — the suite's
// trace_processor CSV parsing depends on it.

namespace sismo {

__attribute__((noinline)) int fix_leaf(int x) {
    int acc = 0;
    for (int i = 0; i < x; i++) acc += i * i;
    return acc;
}

template <typename T>
__attribute__((noinline)) T fix_mid(T x) {
    return fix_leaf(static_cast<int>(x)) + 1;
}

template int fix_mid<int>(int);

}  // namespace sismo

int main(void) {
    return sismo::fix_mid(100) & 0;
}
