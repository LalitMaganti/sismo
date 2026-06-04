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

// The Sismo page: a persistent domain selector (CPU / Latency / Memory, with a
// collapsed Focus-modes group under CPU) above a row of view-tabs. Each domain
// is recording-gated by a capability predicate; an unavailable one renders a
// refusal state that teaches how to enable it (and what it costs). The active
// domain+view is URL-synced (see nav_state) so views are linkable.

import m from 'mithril';
import type {Trace} from '../../public/trace';
import {QuerySlot} from '../../base/query_slot';
import {
  EMPTY_PRIVILEGED_SET,
  loadPrivilegedSet,
  type PrivilegedSet,
} from './privileged_set';
import {
  EMPTY_CAPABILITIES,
  loadCapabilities,
  type TraceCapabilities,
} from './capabilities';
import {DomainShell, renderUnavailable} from './domain_shell';
import {findNode, type SismoNav, subpageToNav} from './nav_state';
import {renderFocusPage} from './focus/focus_page';
import {loadingBody} from './page_common';
import {CpuTabsView} from './cpu/cpu_tabs';
import {LatencyView} from './views/latency_view';
import {renderMemoryView} from './views/memory_view';

interface SismoPageAttrs {
  readonly trace: Trace;
  readonly subpage: string | undefined;
}

// The nav to show before the user picks one. A focus trace lands directly on its
// focus lens once caps are known (rather than the CPU default, which a focus
// trace can't even serve) — so opening a cache trace opens the Cache page. A
// deep link in the URL still wins (only the bare default is overridden).
function defaultNav(
  subpage: string | undefined,
  caps: TraceCapabilities | undefined,
): SismoNav {
  const urlNav = subpageToNav(subpage);
  const urlIsBareDefault =
    urlNav.domain === 'cpu' &&
    urlNav.view === 'overview' &&
    urlNav.focus === undefined;
  if (caps?.focusPreset != null && urlIsBareDefault) {
    return {domain: 'cpu', view: 'overview', focus: caps.focusPreset};
  }
  return urlNav;
}

export class SismoPage implements m.ClassComponent<SismoPageAttrs> {
  // The profiled set is the bootstrap dependency every child reads; fetched once
  // and falling back to the empty set if it can't be resolved.
  private readonly privSlot = new QuerySlot<PrivilegedSet>();
  // What the recording captured — drives which domains are available.
  private readonly capsSlot = new QuerySlot<TraceCapabilities>();
  // The active (sub-)domain, held as component state. The URL subpage only seeds
  // it (deep links still work on load); switching domains thereafter is an ACTION
  // (onNavigate below) that mutates this and re-renders in place — no URL change,
  // which the router wasn't reliably feeding back as a new subpage.
  private nav?: SismoNav;

  onremove(): void {
    this.privSlot.dispose();
    this.capsSlot.dispose();
  }

  view({attrs}: m.CVnode<SismoPageAttrs>) {
    const privileged = this.loadPrivileged(attrs.trace);
    // `undefined` while the capability query is still in flight: don't gate (or
    // grey the selector) on what we don't yet know — show a spinner instead of
    // flashing a refusal state on every load.
    const caps = this.loadCaps(attrs.trace);
    // Active nav = the user's explicit choice if they've made one, else the
    // default derived from the trace. NOT cached into this.nav, because caps
    // arrive async: a focus trace should land on its focus lens once caps load,
    // not freeze on the pre-caps CPU default.
    const nav = this.nav ?? defaultNav(attrs.subpage, caps);
    const body =
      caps === undefined
        ? loadingBody('Reading trace capabilities…')
        : this.renderBody(attrs.trace, nav, caps, privileged);
    return m(DomainShell, {
      trace: attrs.trace,
      nav,
      caps,
      privileged,
      body,
      onNavigate: (n: SismoNav) => {
        this.nav = n;
      },
    });
  }

  // Gate the body on the active domain's capability predicate: an unavailable
  // domain renders the refusal state instead of its (data-less) view.
  private renderBody(
    trace: Trace,
    nav: SismoNav,
    caps: TraceCapabilities,
    privileged: PrivilegedSet,
  ): m.Children {
    const node = findNode(nav);
    if (node !== undefined && !node.isAvailable(caps)) {
      return renderUnavailable(node.unavailable);
    }
    return this.renderDomain(trace, nav, caps, privileged);
  }

  private renderDomain(
    trace: Trace,
    nav: SismoNav,
    caps: TraceCapabilities,
    privileged: PrivilegedSet,
  ): m.Children {
    if (nav.focus !== undefined) {
      // renderFocusPage owns its own framing (Stalls is the full-width CPU tab
      // strip; placeholders pad themselves), so don't wrap it here.
      return renderFocusPage(trace, nav.focus, caps, privileged);
    }
    switch (nav.domain) {
      case 'cpu':
        // Rendered full-width (no __body padding) so the tab bar sits flush
        // under the header divider; the tabs pad their own content.
        return m(CpuTabsView, {trace, priv: privileged});
      case 'latency':
        return m('.pf-sismo-page__body', m(LatencyView, {trace, privileged}));
      case 'memory':
        return m('.pf-sismo-page__body', renderMemoryView());
    }
  }

  private loadPrivileged(trace: Trace): PrivilegedSet {
    try {
      return (
        this.privSlot.use({
          key: {},
          queryFn: () => loadPrivilegedSet(trace),
        }).data ?? EMPTY_PRIVILEGED_SET
      );
    } catch (e) {
      console.warn('Sismo: failed to load privileged set', e);
      return EMPTY_PRIVILEGED_SET;
    }
  }

  // Returns undefined while the query is in flight; EMPTY on failure (logged).
  private loadCaps(trace: Trace): TraceCapabilities | undefined {
    try {
      return this.capsSlot.use({
        key: {},
        queryFn: () => loadCapabilities(trace),
      }).data;
    } catch (e) {
      console.warn('Sismo: failed to load capabilities', e);
      return EMPTY_CAPABILITIES;
    }
  }
}
