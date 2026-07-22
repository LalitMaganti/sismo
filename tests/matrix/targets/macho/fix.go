// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.
//
// Go port of fix.c: markers land in the symtab as main.sismoFixLeaf etc.,
// with line info carried by .gopclntab rather than a debug map.

package main

import "fmt"

//go:noinline
func sismoFixLeaf(x int) int {
	acc := 0
	for i := 0; i < x; i++ {
		acc += i * i
	}
	return acc
}

//go:noinline
func sismoFixMid(x int) int {
	return sismoFixLeaf(x) + 1
}

func main() {
	fmt.Println(sismoFixMid(100))
}
