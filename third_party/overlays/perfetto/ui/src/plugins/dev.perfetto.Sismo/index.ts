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

import './styles.scss';
import m from 'mithril';
import type {PerfettoPlugin} from '../../public/plugin';
import type {Trace} from '../../public/trace';
import SismoWidgets from '../dev.perfetto.SismoWidgets';
import SchedPlugin from '../dev.perfetto.Sched';
import ThreadPlugin from '../dev.perfetto.Thread';
import {SismoPage} from './sismo_page';
import {EMPTY_PRIVILEGED_SET, loadPrivilegedSet} from './privileged_set';
import {
  setupByCpuWorkspace,
  setupSismoSharedTables,
} from './cpu_workspace';
import {setupByThreadWorkspace} from './thread_workspace';
import {registerSismoFlamegraphTab} from './stack_timeline';
import {registerSismoDetailTab} from './detail_tab';

export default class implements PerfettoPlugin {
  static readonly id = 'dev.perfetto.Sismo';
  // Cross-plugin deps the UI import check requires us to declare: the shared
  // Meter widget (SismoWidgets) and the Sched/Thread track classes the
  // workspaces reuse.
  static readonly dependencies = [SismoWidgets, SchedPlugin, ThreadPlugin];

  async onTraceLoad(trace: Trace): Promise<void> {
    trace.pages.registerPage({
      route: '/sismo',
      render: (subpage) => m(SismoPage, {trace, subpage}),
    });
    trace.sidebar.addMenuItem({
      section: 'current_trace',
      text: 'Overview',
      href: '#!/sismo',
      icon: 'dashboard',
      sortOrder: 14,
    });

    // Land on the Sismo overview rather than the raw timeline when a trace
    // finishes loading — the overview is this build's purpose. High priority so
    // it beats any generic landing-page suggestion.
    trace.initialPage.suggest('/sismo', 100);

    trace.defaultWorkspace.title = 'Combined timeline (all data)';

    registerSismoFlamegraphTab(trace);

    let priv = EMPTY_PRIVILEGED_SET;
    try {
      priv = await loadPrivilegedSet(trace);
    } catch (e) {
      console.warn('Sismo: failed to load privileged set', e);
    }

    // The whole-trace detail pane only needs perf_sample / sched, so register
    // it independently of the timeline-workspace tables below — a failure
    // building those must not strip the detail panels.
    try {
      await registerSismoDetailTab(trace, priv);
    } catch (e) {
      console.warn('Sismo: failed to register detail tab', e);
    }

    // Non-fatal: the Sismo overview + CPU detail pages still work without
    // the timeline workspaces.
    try {
      await setupSismoSharedTables(trace, priv);
      await setupByCpuWorkspace(trace, priv);
      await setupByThreadWorkspace(trace, priv);
    } catch (e) {
      console.warn('Sismo: failed to build timeline workspaces', e);
    }
  }
}
