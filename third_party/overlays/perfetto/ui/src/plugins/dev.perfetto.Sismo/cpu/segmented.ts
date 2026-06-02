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

// The segmented-button switcher every CPU tab uses to flip between its "pieces"
// (e.g. Where's flamegraph/calltree/functions, Efficiency's views, Where-it-ran's
// CPU/thread heatmaps). One control so a tab's sub-views read the same wherever
// you are. Built on the base RadioGroup (the same control as the flamegraph's
// Top-Down/Bottom-Up toggle).

import m from 'mithril';
import {RadioGroup} from '../../../widgets/radio_group';

export interface Segment<K extends string> {
  readonly key: K;
  readonly label: string;
  readonly icon?: string;
}

// Neutral (no `intent`) to match the flamegraph's Top-Down/Bottom-Up toggle —
// the selected segment reads via the default active styling, not a coloured fill.
export function segmentedSwitcher<K extends string>(
  segments: ReadonlyArray<Segment<K>>,
  active: K,
  onChange: (key: K) => void,
): m.Children {
  return m(
    RadioGroup,
    {
      selectedValue: active,
      onValueChange: (v: string) => onChange(v as K),
    },
    segments.map((s) =>
      m(RadioGroup.Button, {value: s.key, icon: s.icon}, s.label),
    ),
  );
}

