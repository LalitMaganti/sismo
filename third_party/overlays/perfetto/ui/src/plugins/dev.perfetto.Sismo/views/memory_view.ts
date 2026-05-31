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

// Memory domain body. Parked while we focus on CPU; kept as a selectable domain
// so the page structure is in place for when memory analysis lands.

import m from 'mithril';
import {Section} from '../../../widgets/section';
import {Card} from '../../../widgets/card';
import {Icon} from '../../../widgets/icon';

export function renderMemoryView(): m.Children {
  return m(
    Section,
    {
      title: 'Memory (coming soon)',
      subtitle: 'Per-process RSS, swap, GPU mem, ION/dma-buf, OOM signals.',
    },
    m(
      Card,
      {className: 'pf-sismo-page__hero pf-sismo-page__hero--placeholder'},
      m(
        '.pf-sismo-page__hero-head',
        m(Icon, {
          icon: 'memory_alt',
          className: 'pf-sismo-page__hero-icon',
          filled: true,
        }),
        m(
          '.pf-sismo-page__hero-titlewrap',
          m('.pf-sismo-page__hero-title', 'Memory (coming soon)'),
          m(
            '.pf-sismo-page__hero-tagline',
            'Per-process RSS, swap, GPU mem, ION/dma-buf, OOM signals.',
          ),
        ),
      ),
    ),
  );
}
