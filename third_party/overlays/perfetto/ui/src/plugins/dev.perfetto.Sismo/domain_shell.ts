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

// The shared Sismo domain-page shell: the header (domain selector · Open
// timeline · privileged banner) that frames every (sub-)domain, plus the
// capability-driven "not available on this trace — here's how to enable it (and
// what it costs)" refusal state. The body is whatever the active domain renders;
// the shell owns only the chrome so any domain (CPU, Latency, Memory, a focus
// mode) fills the same frame.

import m from 'mithril';
import type {Trace} from '../../public/trace';
import {Button, ButtonVariant} from '../../widgets/button';
import {Callout} from '../../widgets/callout';
import {Intent} from '../../widgets/common';
import {EmptyState} from '../../widgets/empty_state';
import {MenuDivider, MenuItem, MenuTitle, PopupMenu} from '../../widgets/menu';
import {goToTimeline, renderPrivilegedBanner} from './page_common';
import type {PrivilegedSet} from './privileged_set';
import type {TraceCapabilities} from './capabilities';
import {
  DOMAIN_NODES,
  DOMAIN_TREE,
  findNode,
  isGroup,
  navEquals,
  type DomainGroup,
  type DomainNode,
  type DomainTreeItem,
  type SismoNav,
  type UnavailableInfo,
} from './nav_state';

interface DomainShellAttrs {
  readonly trace: Trace;
  readonly nav: SismoNav;
  // undefined while capabilities are still loading — the selector then greys
  // nothing rather than guessing.
  readonly caps: TraceCapabilities | undefined;
  readonly privileged: PrivilegedSet;
  // The resolved domain body — either the domain's view or renderUnavailable().
  readonly body: m.Children;
  // Switch the active (sub-)domain. An ACTION (in-component state), not a URL
  // change — the page owns the active nav, so selecting a domain re-renders in
  // place rather than round-tripping through the router (which dropped clicks).
  readonly onNavigate: (nav: SismoNav) => void;
}

export class DomainShell implements m.ClassComponent<DomainShellAttrs> {
  view({attrs}: m.CVnode<DomainShellAttrs>): m.Children {
    return m(
      '.pf-sismo-page',
      m(
        '.pf-sismo-page__inner',
        m(
          '.pf-sismo-page__header',
          m(
            '.pf-sismo-page__header-row',
            m(
              '.pf-sismo-page__header-selectors',
              renderDomainSelector(attrs.nav, attrs.caps, attrs.onNavigate),
              renderRegionSelector(),
            ),
            m(Button, {
              label: 'Open timeline',
              icon: 'timeline',
              variant: ButtonVariant.Filled,
              onclick: () => goToTimeline(attrs.trace),
            }),
          ),
          renderPrivilegedBanner(attrs.privileged),
        ),
        attrs.body,
      ),
    );
  }
}

// The region of interest every analysis is scoped to. A framing device for now:
// only "Full trace" exists, so the concept is visible and everything reads as
// "…in this region". Later this grows a brushed time range and, once flows are
// captured, a selected operation (an RPC/frame span).
function renderRegionSelector(): m.Children {
  return m(
    '.pf-sismo-page__domain-selector',
    m('span.pf-sismo-page__selector-label', 'Region of interest'),
    m(
      PopupMenu,
      {
        trigger: m(Button, {
          label: 'Full trace',
          icon: 'crop_free',
          rightIcon: 'arrow_drop_down',
          variant: ButtonVariant.Outlined,
          title: 'Scope the analysis to a region (full trace only, for now)',
        }),
      },
      m(MenuItem, {
        label: 'Full trace',
        icon: 'check',
        // The only region today; selecting it is a no-op.
        onclick: () => {},
      }),
    ),
  );
}

// The "CPU ▾" picker. Renders the WHOLE tree — available, parked, and
// recording-unavailable — so someone opening an unfamiliar trace can see every
// lens that exists and why an empty one is empty. A group (the CPU section: time
// profile + focus lenses) renders inline under a section header, not as a pop-out
// submenu. Unavailable entries stay navigable (a click lands on the refusal page,
// which carries the copyable enable command) but are marked.
function renderDomainSelector(
  nav: SismoNav,
  caps: TraceCapabilities | undefined,
  onNavigate: (nav: SismoNav) => void,
): m.Children {
  const active = findNode(nav) ?? DOMAIN_NODES[0];
  const items: m.Children[] = [];
  DOMAIN_TREE.forEach((item, i) => {
    if (i > 0) items.push(m(MenuDivider));
    if (isGroup(item)) {
      // A top-level group is a section: its header + children laid out inline.
      items.push(m(MenuTitle, {label: item.title}));
      for (const c of item.children) {
        items.push(renderTreeItem(c, nav, caps, onNavigate));
      }
    } else {
      items.push(renderTreeItem(item, nav, caps, onNavigate));
    }
  });
  return m(
    '.pf-sismo-page__domain-selector',
    m('span.pf-sismo-page__selector-label', 'Analysing'),
    m(
      PopupMenu,
      {
        trigger: m(Button, {
          label: activeLabel(active),
          icon: active.icon,
          rightIcon: 'arrow_drop_down',
          variant: ButtonVariant.Outlined,
          title: 'Switch analysis domain',
        }),
      },
      items,
    ),
  );
}

// A child of a section: a nested group becomes a collapsed submenu (the focus
// lenses, kept out of the default view), a leaf becomes a plain item.
function renderTreeItem(
  item: DomainTreeItem,
  nav: SismoNav,
  caps: TraceCapabilities | undefined,
  onNavigate: (nav: SismoNav) => void,
): m.Children {
  if (isGroup(item)) {
    return m(
      MenuItem,
      {label: item.title, icon: item.icon},
      item.children.map((c) => renderTreeItem(c, nav, caps, onNavigate)),
    );
  }
  // Unavailable entries are NOT greyed — every lens reads normally and stays
  // navigable; clicking an unavailable one lands on the refusal page that
  // teaches how to record it. We only annotate the ones this trace can't serve
  // with a small, subtle "not available" — available lenses say nothing.
  // (Skipped while caps are loading, to avoid flashing a wrong status.)
  const unavailable = caps !== undefined && !item.isAvailable(caps);
  const label = unavailable
    ? [item.title, m('span.pf-sismo-page__avail', 'not available')]
    : item.title;
  return m(MenuItem, {
    label,
    icon: item.icon,
    active: navEquals(item.nav, nav),
    onclick: () => onNavigate(item.nav),
  });
}

// Qualify a grouped node with its top-level section (e.g. "CPU · Cache") so the
// trigger reads as a CPU lens, not a bare "Cache".
function activeLabel(active: DomainNode): string {
  for (const item of DOMAIN_TREE) {
    if (isGroup(item) && groupContains(item, active)) {
      return `${item.title} · ${active.title}`;
    }
  }
  return active.title;
}

function groupContains(group: DomainGroup, node: DomainNode): boolean {
  return group.children.some((c) =>
    isGroup(c) ? groupContains(c, node) : c === node,
  );
}

// The refusal body: shown as the page when the active domain isn't available on
// this trace. Teaches what to record to enable it and (for focus modes) what
// that costs.
export function renderUnavailable(info: UnavailableInfo): m.Children {
  return m(
    '.pf-sismo-page__body',
    m(
      EmptyState,
      {icon: 'block', title: info.headline},
      m(
        '.pf-sismo-page__refusal',
        m('p', 'To enable it, record with:'),
        m('code.pf-sismo-page__refusal-cmd', info.enableCmd),
        info.cost !== undefined &&
          m(Callout, {icon: 'info', intent: Intent.Primary}, info.cost),
      ),
    ),
  );
}
