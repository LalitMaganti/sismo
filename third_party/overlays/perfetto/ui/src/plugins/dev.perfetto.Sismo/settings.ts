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

// Cross-trace Sismo UI settings. Perfetto's widgets are stateless across traces
// by design; carrying a user's choices — selected tab, flamegraph view, etc. —
// from one trace to the next is a Sismo concern, so it lives here. Everything is
// stored under one localStorage blob; each Setting owns one key within it and
// read-modify-writes the blob so independent settings don't clobber each other.

const STORAGE_KEY = 'dev.perfetto.Sismo.settings.v1';

function readStore(): Record<string, unknown> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw === null) return {};
    const parsed = JSON.parse(raw) as unknown;
    if (typeof parsed !== 'object' || parsed === null) return {};
    return parsed as Record<string, unknown>;
  } catch {
    return {};
  }
}

function writeStore(store: Record<string, unknown>): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
  } catch {
    // Storage unavailable or over quota — settings are best-effort.
  }
}

// One persisted value. `parse` validates the raw stored value (which may be
// stale, hand-edited, or from an older build) and returns undefined to fall back
// to `fallback`, so a poisoned entry can never break the UI.
export class Setting<T> {
  constructor(
    private readonly key: string,
    private readonly fallback: T,
    private readonly parse: (raw: unknown) => T | undefined,
  ) {}

  get(): T {
    return this.parse(readStore()[this.key]) ?? this.fallback;
  }

  set(value: T): void {
    const store = readStore();
    store[this.key] = value;
    writeStore(store);
  }
}

// `parse` for a value constrained to a fixed set of strings.
export function oneOf<T extends string>(
  values: ReadonlyArray<T>,
): (raw: unknown) => T | undefined {
  return (raw) =>
    typeof raw === 'string' && (values as ReadonlyArray<string>).includes(raw)
      ? (raw as T)
      : undefined;
}

export function str(raw: unknown): string | undefined {
  return typeof raw === 'string' ? raw : undefined;
}
