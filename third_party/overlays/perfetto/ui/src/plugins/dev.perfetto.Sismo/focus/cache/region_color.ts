// Copyright (C) 2026 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Colour + table label per memory region, kept consistent across the cache
// views' stacked bars and legends. The well-known kinds get fixed, distinct
// hues and keep their names. Object/file regions (a mapped binary/library —
// names vary per trace and are long) all collapse to one shared "file" identity
// in the table; the exact filename is left to the per-segment hover tooltip.

const FIXED: ReadonlyMap<string, string> = new Map([
  ['[heap]', '#5b8ff9'],
  ['[anon]', '#f6bd16'],
  ['[stack]', '#5ad8a6'],
  ['[kernel]', '#e8684a'],
  ['[unmapped]', '#9aa3af'],
  ['[no data]', '#9aa3af'],
]);

const FILE_COLOR = '#945fb9';

// True for a file/object region (a mapped binary/library). The special kinds are
// bracketed ("[heap]" …); anything else is a file path's basename.
export function isFileRegion(region: string): boolean {
  return !region.startsWith('[');
}

export function regionColor(region: string): string {
  return FIXED.get(region) ?? FILE_COLOR;
}

// How a region reads in the table (bar annotation / legend): file/object
// regions collapse to "file" (the exact name lives in the tooltip); the special
// kinds keep their name.
export function regionLabel(region: string): string {
  return isFileRegion(region) ? 'file' : region;
}
