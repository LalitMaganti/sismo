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
import {EmptyState} from '../../widgets/empty_state';
import {Callout} from '../../widgets/callout';
import {Intent} from '../../widgets/common';
import {Button, ButtonVariant} from '../../widgets/button';
import {MenuItem, PopupMenu} from '../../widgets/menu';
import {Tabs} from '../../widgets/tabs';
import {Section} from '../../widgets/section';
import {goToTimeline, renderPrivilegedBanner} from './page_common';
import {loadCpuDetail, type CpuDetail} from './cpu_data';
import {
  EMPTY_PRIVILEGED_SET,
  loadPrivilegedSet,
  type PrivilegedSet,
} from './privileged_set';
import {
  CPU_VIEWS,
  DOMAINS,
  navToHash,
  subpageToNav,
  type CpuView,
  type SismoNav,
} from './nav_state';
import {renderCpuOverview} from './views/cpu_overview_view';
import {CpuCoresView} from './views/cpu_cores_view';
import {CpuConsumersView} from './views/cpu_consumers_view';
import {CpuActivityView} from './views/cpu_activity_view';
import {CpuFlamegraphView} from './views/cpu_flamegraph_view';
import {CpuCalltreeView} from './views/cpu_calltree_view';
import {renderCpuFunctions} from './views/cpu_functions_view';
import {CpuBottleneckView} from './views/cpu_bottleneck_view';
import {LatencyView} from './views/latency_view';
import {renderMemoryView} from './views/memory_view';

interface SismoPageAttrs {
  readonly trace: Trace;
  readonly subpage: string | undefined;
}

export class SismoPage implements m.ClassComponent<SismoPageAttrs> {
  private privileged: PrivilegedSet = EMPTY_PRIVILEGED_SET;
  private cpuDetail?: CpuDetail;
  private cpuError?: string;

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
        return this.renderCpuTabs(trace, nav.view);
      case 'latency':
        return m(
          '.pf-sismo-page__body',
          m(LatencyView, {trace, privileged: this.privileged}),
        );
      case 'memory':
        return m('.pf-sismo-page__body', renderMemoryView());
    }
  }

  private renderCpuTabs(trace: Trace, view: CpuView): m.Children {
    if (this.cpuError !== undefined) {
      return m(
        '.pf-sismo-page__body',
        m(Callout, {icon: 'error', intent: Intent.Danger}, this.cpuError),
      );
    }
    if (this.cpuDetail === undefined) {
      return m(
        '.pf-sismo-page__body',
        m(EmptyState, {icon: 'hourglass_empty', title: 'Loading CPU details…'}),
      );
    }
    const d = this.cpuDetail;
    if (!d.summary.hasSched && !d.microarch.hasSamples) {
      return m(
        '.pf-sismo-page__body',
        m(
          Callout,
          {icon: 'info', intent: Intent.Primary},
          'This trace contains no scheduling data or CPU samples, so there is ' +
            'nothing to break down. Re-record with `sismo record` to enable ' +
            'CPU analysis.',
        ),
      );
    }
    return m(Tabs, {
      className: 'pf-sismo-page__tabs',
      activeTabKey: view,
      onTabChange: (key) =>
        navigate({domain: 'cpu', view: key as CpuView}),
      tabs: CPU_VIEWS.map((v) => ({
        key: v.key,
        title: v.title,
        // Wrap in __body so the shared section/padding styles apply, matching
        // the latency/memory bodies.
        content: m(
          '.pf-sismo-page__body',
          this.renderCpuView(trace, d, v.key, view),
        ),
      })),
    });
  }

  // Builds the active CPU view. The Code and Efficiency lenses run their own
  // queries (flamegraph / PMU counters), so they're only constructed when their
  // tab is active to keep page load light.
  private renderCpuView(
    trace: Trace,
    d: CpuDetail,
    view: CpuView,
    active: CpuView,
  ): m.Children {
    switch (view) {
      case 'overview':
        return renderCpuOverview(trace, d, this.privileged);
      case 'activity':
        // Runs its own bucketed query; only build when active.
        return active === 'activity'
          ? m(CpuActivityView, {trace, priv: this.privileged})
          : undefined;
      case 'threads':
        return m(CpuConsumersView, {trace, data: d, priv: this.privileged});
      case 'cores':
        return m(CpuCoresView, {
          trace,
          summary: d.summary,
          perCore: d.perCore,
        });
      case 'flamegraph':
        // Flamegraph + the flat hot-functions / hot-libraries breakdown. Heavy
        // query inside the panel, so only build when active.
        return active === 'flamegraph'
          ? [
              m(
                Section,
                {
                  title: 'Flamegraph',
                  subtitle:
                    'Your code as a sampled flamegraph — click to zoom into a ' +
                    'subtree. The flat breakdown is below; the expandable tree ' +
                    'is on the Calltree tab.',
                },
                m(CpuFlamegraphView, {
                  trace,
                  priv: this.privileged,
                  hasSamples: d.microarch.hasSamples,
                }),
              ),
              renderCpuFunctions(d.microarch),
            ]
          : undefined;
      case 'calltree':
        return active === 'calltree'
          ? m(CpuCalltreeView, {
              trace,
              priv: this.privileged,
              hasSamples: d.microarch.hasSamples,
            })
          : undefined;
      case 'bottleneck':
        return active === 'bottleneck'
          ? m(CpuBottleneckView, {trace, priv: this.privileged})
          : undefined;
    }
  }

  private async load(trace: Trace): Promise<void> {
    try {
      this.privileged = await loadPrivilegedSet(trace);
    } catch (e) {
      console.warn('Sismo: failed to load privileged set', e);
    }
    try {
      this.cpuDetail = await loadCpuDetail(trace.engine, this.privileged);
    } catch (e) {
      this.cpuError =
        e instanceof Error ? e.message : 'Failed to load CPU detail';
    }
    m.redraw();
  }
}

function navigate(nav: SismoNav): void {
  window.location.hash = navToHash(nav);
}
