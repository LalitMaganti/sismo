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

// The Sismo page: a persistent domain selector (CPU / Latency / Memory) above a
// row of view-tabs, modeled on com.android.HeapDumpExplorer. Only CPU has
// multiple views today; latency/memory are parked but kept selectable. The
// active domain+view is URL-synced (see nav_state) so views are linkable.

import m from 'mithril';
import type {Trace} from '../../public/trace';
import {Button, ButtonVariant} from '../../widgets/button';
import {MenuItem, PopupMenu} from '../../widgets/menu';
import {goToTimeline, renderPrivilegedBanner} from './page_common';
import {
  EMPTY_PRIVILEGED_SET,
  loadPrivilegedSet,
  type PrivilegedSet,
} from './privileged_set';
import {DOMAINS, navToHash, subpageToNav, type SismoNav} from './nav_state';
import {CpuLandingPage} from './cpu/landing';
import {LatencyView} from './views/latency_view';
import {renderMemoryView} from './views/memory_view';

interface SismoPageAttrs {
  readonly trace: Trace;
  readonly subpage: string | undefined;
}

export class SismoPage implements m.ClassComponent<SismoPageAttrs> {
  private privileged: PrivilegedSet = EMPTY_PRIVILEGED_SET;

  oninit({attrs}: m.CVnode<SismoPageAttrs>) {
    this.load(attrs.trace);
  }

  view({attrs}: m.CVnode<SismoPageAttrs>) {
    const nav = subpageToNav(attrs.subpage);
    return m(
      '.pf-sismo-page',
      m(
        '.pf-sismo-page__inner',
        m(
          '.pf-sismo-page__header',
          m(
            '.pf-sismo-page__header-row',
            this.renderDomainSelector(nav),
            m(Button, {
              label: 'Open timeline',
              icon: 'timeline',
              variant: ButtonVariant.Filled,
              onclick: () => goToTimeline(attrs.trace),
            }),
          ),
          renderPrivilegedBanner(this.privileged),
        ),
        this.renderDomain(attrs.trace, nav),
      ),
    );
  }

  // The "CPU ▾" picker that swaps which domain's views are shown, mirroring
  // HeapDumpExplorer's dump selector above its tab row.
  private renderDomainSelector(nav: SismoNav): m.Children {
    const active = DOMAINS.find((d) => d.key === nav.domain) ?? DOMAINS[0];
    return m(
      '.pf-sismo-page__domain-selector',
      m('span.pf-sismo-page__selector-label', 'Analysing'),
      m(
        PopupMenu,
        {
          trigger: m(Button, {
            label: active.title,
            icon: active.icon,
            rightIcon: 'arrow_drop_down',
            variant: ButtonVariant.Outlined,
            title: 'Switch analysis domain (CPU / Latency / Memory)',
          }),
        },
      DOMAINS.map((d) =>
        m(MenuItem, {
          label: d.deferred ? `${d.title} (soon)` : d.title,
          icon: d.icon,
          active: d.key === nav.domain,
          onclick: () => navigate({domain: d.key, view: 'overview'}),
        }),
      ),
      ),
    );
  }

  private renderDomain(trace: Trace, nav: SismoNav): m.Children {
    switch (nav.domain) {
      case 'cpu':
        return m(
          '.pf-sismo-page__body',
          m(CpuLandingPage, {trace, priv: this.privileged}),
        );
      case 'latency':
        return m(
          '.pf-sismo-page__body',
          m(LatencyView, {trace, privileged: this.privileged}),
        );
      case 'memory':
        return m('.pf-sismo-page__body', renderMemoryView());
    }
  }

  private async load(trace: Trace): Promise<void> {
    try {
      this.privileged = await loadPrivilegedSet(trace);
    } catch (e) {
      console.warn('Sismo: failed to load privileged set', e);
    }
    m.redraw();
  }
}

function navigate(nav: SismoNav): void {
  window.location.hash = navToHash(nav);
}
