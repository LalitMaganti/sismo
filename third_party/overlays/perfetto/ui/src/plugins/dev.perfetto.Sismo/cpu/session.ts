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

// The CPU deep-dive session: which tab is active and which dynamic entity tabs
// are open. Modeled on com.android.HeapDumpExplorer's session — fixed view tabs
// are always present; drilling into an entity opens (or re-focuses) a closeable
// tab scoped to it. State only; no queries.

export type EntityKind = 'function' | 'thread' | 'process';

export interface EntityTab {
  // Stable, unique key, e.g. 'function:parse' — also the dedup identity.
  readonly key: string;
  readonly kind: EntityKind;
  // The entity identifier (function name, utid, upid as a string).
  readonly id: string;
  // Display title for the tab handle.
  readonly label: string;
}

// The key of the home/overview tab.
export const OVERVIEW_TAB = 'overview';

export class CpuSession {
  private readonly _tabs: EntityTab[] = [];
  private _active = OVERVIEW_TAB;

  get tabs(): ReadonlyArray<EntityTab> {
    return this._tabs;
  }

  get active(): string {
    return this._active;
  }

  setActive(key: string): void {
    this._active = key;
  }

  // Open a tab for an entity, or re-focus it if already open (dedup by key).
  openEntityTab(kind: EntityKind, id: string, label: string): void {
    const key = `${kind}:${id}`;
    if (!this._tabs.some((t) => t.key === key)) {
      this._tabs.push({key, kind, id, label});
    }
    this._active = key;
  }

  closeTab(key: string): void {
    const idx = this._tabs.findIndex((t) => t.key === key);
    if (idx < 0) return;
    this._tabs.splice(idx, 1);
    if (this._active === key) {
      this._active = OVERVIEW_TAB;
    }
  }
}
