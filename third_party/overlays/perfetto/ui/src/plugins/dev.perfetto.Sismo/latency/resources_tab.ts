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

// "What you waited on" — the per-resource facets of the wait: which lock, which
// peer, which file your threads blocked on. One tab with a segmented switcher
// over Locks / Network / Disk, mirroring the CPU page's "How were cycles spent"
// (cache / branch / backend). Controlled: the parent owns the selected facet so
// the Summary's kind-of-wait block can deep-link straight to one.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {segmentedSwitcher, type Segment} from '../cpu/segmented';
import {LatencyLocksTab} from './locks_tab';
import {LatencyNetworkTab} from './network_tab';
import {LatencyDiskTab} from './disk_tab';
import type {PrivilegedSet} from '../privileged_set';

export const RESOURCE_FACETS = ['locks', 'network', 'disk'] as const;
export type ResourceFacet = (typeof RESOURCE_FACETS)[number];

interface ResourcesAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
  readonly facet: ResourceFacet;
  readonly onFacetChange: (f: ResourceFacet) => void;
  readonly onNavigate: (tab: string) => void;
}

const SEGMENTS: Segment<ResourceFacet>[] = [
  {key: 'locks', label: 'Locks', icon: 'lock'},
  {key: 'network', label: 'Network', icon: 'lan'},
  {key: 'disk', label: 'Disk', icon: 'hard_drive'},
];

export class LatencyResourcesTab implements m.ClassComponent<ResourcesAttrs> {
  view({attrs}: m.CVnode<ResourcesAttrs>): m.Children {
    return m(
      '.pf-sismo-tab',
      m(
        '.pf-sismo-tab__modebar',
        segmentedSwitcher<ResourceFacet>(
          SEGMENTS,
          attrs.facet,
          attrs.onFacetChange,
        ),
      ),
      this.renderFacet(attrs),
    );
  }

  private renderFacet(attrs: ResourcesAttrs): m.Children {
    const {trace, priv, onNavigate} = attrs;
    switch (attrs.facet) {
      case 'locks':
        return m(LatencyLocksTab, {trace, priv, onNavigate});
      case 'network':
        return m(LatencyNetworkTab, {trace, priv});
      case 'disk':
        return m(LatencyDiskTab, {trace, priv});
    }
  }
}
