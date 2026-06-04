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

// The CPU focus sub-domain pages. Each focus mode is a curated layout for one
// problem class (you already know the question, so this isn't the survey's
// cost×surprise feed). Reached only when the trace's focus preset matches the
// requested key — availability is decided upstream in SismoPage against the
// capability predicate, so these renderers assume the data is present.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {EmptyState} from '../../../widgets/empty_state';
import type {PrivilegedSet} from '../privileged_set';
import type {TraceCapabilities} from '../capabilities';
import type {FocusKey} from '../nav_state';
import {CacheTabsView} from './cache/tabs';

// One-line "what this captures / how to read it" per preset, shown until the
// real curated page lands.
const FOCUS_BLURB: Record<FocusKey, string> = {
  cache:
    'Samples land on L3/LLC load misses, so the histogram over functions and ' +
    'lines is a direct map of where misses happen.',
  branch:
    'Samples land on retired branch mispredicts, so the histogram shows which ' +
    'branches mispredict and (with LBR) from where.',
  frontend:
    'Samples land on frontend resteers / iTLB misses, mapping where fetch ' +
    'stalls.',
};

const FOCUS_TITLE: Record<FocusKey, string> = {
  cache: 'Cache focus',
  branch: 'Branch focus',
  frontend: 'Frontend focus',
};

export function renderFocusPage(
  trace: Trace,
  key: FocusKey,
  _caps: TraceCapabilities,
  priv: PrivilegedSet,
): m.Children {
  // Cache has its bespoke page; the other lenses are placeholders until their
  // curated pages land.
  if (key === 'cache') {
    return m(CacheTabsView, {trace, priv});
  }
  return m(
    '.pf-sismo-page__body',
    m(
      EmptyState,
      {icon: 'center_focus_strong', title: `${FOCUS_TITLE[key]} — coming next`},
      m('p.pf-sismo-page__refusal', FOCUS_BLURB[key]),
    ),
  );
}
