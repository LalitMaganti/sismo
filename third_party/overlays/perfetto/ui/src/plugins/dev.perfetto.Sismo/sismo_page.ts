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

import m from 'mithril';
import type {Trace} from '../../public/trace';
import {Section} from '../../widgets/section';
import {Card} from '../../widgets/card';
import {GridLayout} from '../../widgets/grid_layout';
import {EmptyState} from '../../widgets/empty_state';
import {Icon} from '../../widgets/icon';
import {Anchor} from '../../widgets/anchor';
import {Button, ButtonVariant} from '../../widgets/button';
import {Callout} from '../../widgets/callout';
import {Intent} from '../../widgets/common';
import {Tooltip} from '../../widgets/tooltip';
import {loadCpuSummary, type CpuSummary} from './cpu_data';
import {fmtCount, fmtDuration, fmtMegacycles, fmtPercent} from './format';
import {CpuDetailPage} from './cpu_detail_page';
import {LatencyDetailPage} from './latency_detail_page';
import {
  EMPTY_PRIVILEGED_SET,
  loadPrivilegedSet,
  type PrivilegedSet,
} from './privileged_set';

export interface SismoPageAttrs {
  readonly trace: Trace;
  readonly subpage: string | undefined;
}

// `subpage` arrives prefixed with '/' (e.g. '/cpu'); normalise to a bare key.
function subpageKey(subpage: string | undefined): string {
  if (!subpage) return '';
  return subpage.startsWith('/') ? subpage.slice(1) : subpage;
}

export class SismoPage implements m.ClassComponent<SismoPageAttrs> {
  private privileged: PrivilegedSet = EMPTY_PRIVILEGED_SET;
  private cpuSummary?: CpuSummary;
  private cpuSummaryError?: string;

  oninit({attrs}: m.CVnode<SismoPageAttrs>) {
    this.loadSummary(attrs.trace);
  }

  view({attrs}: m.CVnode<SismoPageAttrs>) {
    const key = subpageKey(attrs.subpage);
    if (key === 'cpu') {
      return m(CpuDetailPage, {trace: attrs.trace, privileged: this.privileged});
    }
    if (key === 'latency') {
      return m(LatencyDetailPage, {
        trace: attrs.trace,
        privileged: this.privileged,
      });
    }
    return this.renderOverview(attrs.trace);
  }

  private renderOverview(trace: Trace): m.Children {
    return m(
      '.pf-sismo-page',
      m(
        '.pf-sismo-page__inner',
        m(
          '.pf-sismo-page__header',
          m(
            '.pf-sismo-page__header-row',
            m('h1.pf-sismo-page__title', 'Sismo Overview'),
            m(Button, {
              label: 'Open timeline',
              icon: 'timeline',
              variant: ButtonVariant.Filled,
              onclick: () => trace.navigate('#!/viewer'),
            }),
          ),
          m(
            '.pf-sismo-page__subtitle',
            'Entry point to this trace. Click any section to dig deeper.',
          ),
          this.renderPrivilegedBanner(),
        ),
        m(
          '.pf-sismo-page__body',
          this.renderCpuSection(trace),
          this.renderLatencySection(),
          this.renderComingSoonSection(
            'Memory',
            'memory',
            'Per-process RSS, swap, GPU mem, ION/dma-buf, OOM signals.',
          ),
        ),
      ),
    );
  }

  private renderCpuSection(trace: Trace): m.Children {
    if (this.cpuSummaryError !== undefined) {
      return m(
        Section,
        {title: 'CPU', subtitle: 'Sched, frequency, idle states'},
        m(Callout, {icon: 'error', intent: Intent.Danger}, this.cpuSummaryError),
      );
    }
    if (this.cpuSummary === undefined) {
      return m(
        Section,
        {title: 'CPU', subtitle: 'Sched, frequency, idle states'},
        m(EmptyState, {icon: 'hourglass_empty', title: 'Loading CPU summary…'}),
      );
    }
    const s = this.cpuSummary;
    if (!s.hasSched) {
      return m(
        Section,
        {title: 'CPU', subtitle: 'Sched, frequency, idle states'},
        m(
          Callout,
          {icon: 'info', intent: Intent.Primary},
          'This trace contains no scheduling data — record with the ',
          m('code', 'linux.ftrace'),
          ' / ',
          m('code', 'sched'),
          ' data sources to enable CPU analysis.',
        ),
      );
    }

    const headline: HeadlineCard[] = [
      {
        label: 'CPU runtime',
        value: fmtDuration(trace, s.totalRuntimeNs),
        help: 'Total non-idle time summed across all cores.',
      },
      {
        label: 'Avg utilization',
        value: fmtPercent(s.avgUtilization),
        help: 'Runtime / (walltime * num cores). 100% means every core was busy for the whole trace.',
      },
      {
        label: 'Cores',
        value: s.numClusters > 1
          ? `${s.numCpus} (${s.numClusters} clusters)`
          : `${s.numCpus}`,
        help: 'Number of CPUs seen in the trace, and the number of distinct clusters (e.g. big/little).',
      },
      {
        label: 'CPU work',
        value: fmtMegacycles(s.megacycles),
        help: 'Total CPU cycles executed. Requires cpufreq data.',
      },
      {
        label: 'Processes on CPU',
        value: fmtCount(s.numProcesses),
        help: 'Distinct processes that were scheduled.',
      },
      {
        label: 'Threads on CPU',
        value: fmtCount(s.numThreads),
        help: 'Distinct non-idle threads that were scheduled.',
      },
    ];

    return m(
      Section,
      {
        title: 'CPU',
        subtitle: 'Sched, frequency, idle states',
      },
      m(
        Card,
        {
          className: 'pf-sismo-page__hero pf-sismo-page__hero--clickable',
          interactive: true,
          onclick: () => {
            window.location.hash = '#!/sismo/cpu';
          },
        },
        m(
          '.pf-sismo-page__hero-head',
          m(Icon, {
            icon: 'memory',
            className: 'pf-sismo-page__hero-icon',
            filled: true,
          }),
          m(
            '.pf-sismo-page__hero-titlewrap',
            m('.pf-sismo-page__hero-title', 'CPU usage'),
            m(
              '.pf-sismo-page__hero-tagline',
              this.buildCpuTagline(trace, s),
            ),
          ),
          m(
            Anchor,
            {
              href: '#!/sismo/cpu',
              icon: 'arrow_forward',
              className: 'pf-sismo-page__hero-cta',
            },
            'Drill in',
          ),
        ),
        m(
          GridLayout,
          headline.map((c) => renderHeadlineCard(c)),
        ),
      ),
    );
  }

  private buildCpuTagline(trace: Trace, s: CpuSummary): string {
    const cores = `${s.numCpus} core${s.numCpus === 1 ? '' : 's'}`;
    if (s.privilegedRuntimeNs !== null && s.totalRuntimeNs !== null) {
      const yours = fmtDuration(trace, s.privilegedRuntimeNs);
      const total = fmtDuration(trace, s.totalRuntimeNs);
      const share =
        s.totalRuntimeNs > 0n
          ? fmtPercent(Number(s.privilegedRuntimeNs) / Number(s.totalRuntimeNs))
          : '—';
      return `Your processes used ${yours} of ${total} CPU runtime (${share}) across ${cores}`;
    }
    const util = fmtPercent(s.avgUtilization);
    const runtime = fmtDuration(trace, s.totalRuntimeNs);
    return `${runtime} of CPU runtime across ${cores} (avg ${util})`;
  }

  private renderPrivilegedBanner(): m.Children {
    if (this.privileged.pids.length === 0) {
      return m(
        '.pf-sismo-page__priv-banner.pf-sismo-page__priv-banner--empty',
        m(Icon, {icon: 'info'}),
        " No profiled processes detected — record with `sismo record` to tag the processes you're profiling and see them broken out from the rest of the system.",
      );
    }
    const pidList = this.privileged.pids.map((p) => `pid ${p}`).join(', ');
    return m(
      '.pf-sismo-page__priv-banner',
      m(Icon, {icon: 'star', filled: true}),
      ` Profiling ${pidList}`,
      this.privileged.upids.length < this.privileged.pids.length &&
        m(
          'span.pf-sismo-page__muted',
          ` (${this.privileged.pids.length - this.privileged.upids.length} not found in this trace)`,
        ),
    );
  }

  private renderComingSoonSection(
    title: string,
    icon: string,
    blurb: string,
  ): m.Children {
    return m(
      Section,
      {title, subtitle: blurb},
      m(
        Card,
        {className: 'pf-sismo-page__hero pf-sismo-page__hero--placeholder'},
        m(
          '.pf-sismo-page__hero-head',
          m(Icon, {
            icon,
            className: 'pf-sismo-page__hero-icon',
            filled: true,
          }),
          m(
            '.pf-sismo-page__hero-titlewrap',
            m('.pf-sismo-page__hero-title', `${title} (coming soon)`),
            m('.pf-sismo-page__hero-tagline', blurb),
          ),
        ),
      ),
    );
  }

  private renderLatencySection(): m.Children {
    return m(
      Section,
      {
        title: 'Latency',
        subtitle: 'Scheduling delay, blocking waits, critical paths.',
      },
      m(
        Card,
        {
          className: 'pf-sismo-page__hero pf-sismo-page__hero--clickable',
          interactive: true,
          onclick: () => {
            window.location.hash = '#!/sismo/latency';
          },
        },
        m(
          '.pf-sismo-page__hero-head',
          m(Icon, {
            icon: 'speed',
            className: 'pf-sismo-page__hero-icon',
            filled: true,
          }),
          m(
            '.pf-sismo-page__hero-titlewrap',
            m('.pf-sismo-page__hero-title', 'Scheduling latency'),
            m(
              '.pf-sismo-page__hero-tagline',
              'What held the CPU while your threads were waiting to run.',
            ),
          ),
          m(
            Anchor,
            {
              href: '#!/sismo/latency',
              icon: 'arrow_forward',
              className: 'pf-sismo-page__hero-cta',
            },
            'Drill in',
          ),
        ),
      ),
    );
  }

  private async loadSummary(trace: Trace): Promise<void> {
    try {
      this.privileged = await loadPrivilegedSet(trace);
      this.cpuSummary = await loadCpuSummary(trace.engine, this.privileged);
    } catch (e) {
      this.cpuSummaryError =
        e instanceof Error ? e.message : 'Failed to load CPU summary';
    }
    m.redraw();
  }
}

interface HeadlineCard {
  readonly label: string;
  readonly value: string;
  readonly help?: string;
}

function renderHeadlineCard({label, value, help}: HeadlineCard): m.Children {
  return m(
    Card,
    {className: 'pf-sismo-page__stat-card'},
    m(
      '.pf-sismo-page__stat-label',
      label,
      help &&
        m(
          Tooltip,
          {
            trigger: m(Icon, {
              icon: 'help_outline',
              className: 'pf-sismo-page__help-icon',
            }),
          },
          help,
        ),
    ),
    m('.pf-sismo-page__stat-value', value),
  );
}
