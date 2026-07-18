// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.
//
// Go port of the canonical matrix workload (see workload.c for the shape).

package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

//go:noinline
func sismo_wl_leaf(x uint64) uint64 {
	for i := uint64(0); i < 4096; i++ {
		x = x*2654435761 + i
	}
	return x
}

//go:noinline
func sismo_wl_mid(x uint64) uint64 {
	for i := uint64(0); i < 8; i++ {
		x = sismo_wl_leaf(x ^ i)
	}
	return x
}

//go:noinline
func sismo_wl_outer(x uint64) uint64 {
	for i := uint64(0); i < 4; i++ {
		x = sismo_wl_mid(x + i)
	}
	return x
}

//go:noinline
func sismo_wl_block() {
	time.Sleep(2 * time.Millisecond)
}

func main() {
	durationMs := uint64(3000)
	if len(os.Args) > 1 {
		if v, err := strconv.ParseUint(os.Args[1], 10, 64); err == nil {
			durationMs = v
		}
	}
	end := time.Now().Add(time.Duration(durationMs) * time.Millisecond)
	x := uint64(1)
	iters := uint64(0)
	for time.Now().Before(end) {
		x = sismo_wl_outer(x)
		iters++
		if iters%32 == 0 {
			sismo_wl_block()
		}
	}
	_ = x
	fmt.Printf("sismo-workload iters=%d\n", iters)
}
