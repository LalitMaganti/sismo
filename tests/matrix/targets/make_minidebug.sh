#!/usr/bin/env bash
# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.
#
# Rewrite $1 in place as a MiniDebugInfo binary: move its .symtab function
# symbols into an xz-compressed .gnu_debugdata section, then strip the real
# .symtab. This mirrors the Fedora/Arch stripped-library format, where a
# function name is recoverable only by decompressing .gnu_debugdata. Follows
# the recipe from the binutils/gdb MiniDebugInfo documentation.
set -euo pipefail
bin="$1"
w="$(mktemp -d)"
trap 'rm -rf "$w"' EXIT

nm -D "$bin" --format=posix --defined-only 2>/dev/null | awk '{print $1}' | sort > "$w/dyn"
nm "$bin" --format=posix --defined-only 2>/dev/null | awk '$2 ~ /^[TtDd]$/ {print $1}' | sort > "$w/fun"
comm -13 "$w/dyn" "$w/fun" > "$w/keep"

objcopy -S --remove-section .comment --keep-symbols="$w/keep" "$bin" "$w/mini"
xz -f "$w/mini"
objcopy --add-section .gnu_debugdata="$w/mini.xz" "$bin"
strip "$bin"
