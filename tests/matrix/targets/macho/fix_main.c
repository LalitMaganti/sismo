// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.
//
// Static-archive fixture half: main lives in its own .o and pulls the
// markers out of libfix.a.

extern int sismo_fix_mid(int x);

int main(void) {
    return sismo_fix_mid(100) & 0;
}
