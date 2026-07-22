// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.
//
// Swift port of fix.c. Built with -module-name fix, so the markers mangle
// deterministically ($s3fix12sismoFixLeafyS2iF etc. — no hash suffix).

@inline(never) func sismoFixLeaf(_ x: Int) -> Int {
    var acc = 0
    for i in 0..<x { acc += i &* i }
    return acc
}

@inline(never) func sismoFixMid(_ x: Int) -> Int {
    return sismoFixLeaf(x) + 1
}

print(sismoFixMid(100))
