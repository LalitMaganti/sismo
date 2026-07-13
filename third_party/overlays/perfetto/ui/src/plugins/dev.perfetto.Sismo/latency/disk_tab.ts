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

// "Disk" — the disk slice of the wait-type axis. When a file read parks off-CPU
// on the device (page-cache miss / direct I/O), the vfs_read interner tags it
// with the file's name, so this clusters blocking reads by file (the disk analog
// of the Locks / Network tabs): which file is your code stuck reading. Click a
// file to see the threads blocked on it.

import m from 'mithril';
import type {Trace} from '../../../public/trace';
import {QuerySlot, SerialTaskQueue} from '../../../base/query_slot';
import {Section} from '../../../widgets/section';
import {Card} from '../../../widgets/card';
import {Anchor} from '../../../widgets/anchor';
import {Grid, GridCell, GridHeaderCell} from '../../../widgets/grid';
import {EmptyState} from '../../../widgets/empty_state';
import {Callout} from '../../../widgets/callout';
import {Intent} from '../../../widgets/common';
import {
  loadDiskFiles,
  loadDiskFileDetail,
  type DiskFiles,
  type DiskFileRow,
  type DiskFileDetail,
} from '../cpu_data';
import {fmtDuration, fmtCount} from '../format';
import {loadingBody, renderBar} from '../page_common';
import type {PrivilegedSet} from '../privileged_set';

interface DiskTabAttrs {
  readonly trace: Trace;
  readonly priv: PrivilegedSet;
}

export class LatencyDiskTab implements m.ClassComponent<DiskTabAttrs> {
  private readonly queue = new SerialTaskQueue();
  private readonly slot = new QuerySlot<DiskFiles>(this.queue);
  private readonly detailSlot = new QuerySlot<DiskFileDetail>(this.queue);

  private selected?: DiskFileRow;

  onremove(): void {
    this.slot.dispose();
    this.detailSlot.dispose();
  }

  view({attrs}: m.CVnode<DiskTabAttrs>): m.Children {
    const {trace, priv} = attrs;
    const data = this.slot.use({
      key: {upids: [...priv.upids]},
      queryFn: () => loadDiskFiles(trace.engine, priv),
    }).data;
    if (data === undefined) return loadingBody('Clustering disk waits…');
    const body =
      this.selected !== undefined
        ? this.renderDetail(attrs, this.selected)
        : this.renderList(attrs, data);
    return m('.pf-sismo-tab__body', body);
  }

  private renderList(attrs: DiskTabAttrs, d: DiskFiles): m.Children {
    const title = 'Disk';
    const subtitle =
      'Every file your threads blocked reading, waiting on the device (a ' +
      'page-cache miss or direct I/O). Ranked by the wall-clock lost waiting. ' +
      'Click a file to drill in.';
    if (!d.hasPriv) {
      return m(
        Section,
        {title, subtitle},
        m(
          Callout,
          {icon: 'info', intent: Intent.Primary},
          'No profiled processes detected — record with `sismo record` to tag ' +
            'the processes you’re profiling.',
        ),
      );
    }
    if (d.files.length === 0) {
      return m(
        Section,
        {title, subtitle},
        m(EmptyState, {
          icon: 'hard_drive',
          title:
            'Your threads never blocked on a file read — reads were served from ' +
            'the page cache, or there was no file I/O.',
        }),
      );
    }
    return m(
      Section,
      {title, subtitle},
      this.renderLead(attrs.trace, d),
      this.renderTable(attrs.trace, d),
    );
  }

  private renderLead(trace: Trace, d: DiskFiles): m.Children {
    const top = d.files[0];
    const lead =
      `Your threads lost ${fmtDuration(trace, d.totalWaitNs)} blocked reading ` +
      `${fmtCount(d.files.length)} file${d.files.length === 1 ? '' : 's'}. The ` +
      `most-waited-on is ${top.name} — ${fmtDuration(trace, top.waitNs)} across ` +
      `${fmtCount(top.blocks)} reads (${avgLabel(top.waitNs, top.blocks)}).`;
    return m(Callout, {icon: 'insights', intent: Intent.Primary}, lead);
  }

  private renderTable(trace: Trace, d: DiskFiles): m.Children {
    const maxWait = Number(d.files[0].waitNs) || 1;
    const rows = d.files.map((f) => [
      m(
        GridCell,
        {wrap: true},
        m(
          Anchor,
          {
            onclick: (e: Event) => {
              e.preventDefault();
              this.selected = f;
            },
          },
          f.name,
        ),
      ),
      m(
        GridCell,
        renderBar(Number(f.waitNs) / maxWait, fmtDuration(trace, f.waitNs)),
      ),
      m(GridCell, {align: 'right'}, fmtCount(f.blocks)),
      m(GridCell, {align: 'right'}, avgLabel(f.waitNs, f.blocks)),
      m(GridCell, {align: 'right'}, fmtCount(f.threads)),
    ]);
    return m(
      Card,
      {className: 'pf-sismo-page__table-card'},
      m(Grid, {
        columns: [
          {key: 'file', header: m(GridHeaderCell, 'File')},
          {key: 'wait', header: m(GridHeaderCell, 'Wait total')},
          {key: 'reads', header: m(GridHeaderCell, 'Reads')},
          {key: 'avg', header: m(GridHeaderCell, 'Avg wait')},
          {key: 'threads', header: m(GridHeaderCell, 'Threads')},
        ],
        rowData: rows,
      }),
    );
  }

  private renderDetail(attrs: DiskTabAttrs, file: DiskFileRow): m.Children {
    const detail = this.detailSlot.use({
      key: {file: file.fileId.toString()},
      queryFn: () =>
        loadDiskFileDetail(attrs.trace.engine, file.fileId, file.name),
    }).data;
    const back = m(
      '.pf-sismo-tab__back',
      m(
        Anchor,
        {
          icon: 'arrow_back',
          onclick: (e: Event) => {
            e.preventDefault();
            this.selected = undefined;
          },
        },
        'All files',
      ),
    );
    if (detail === undefined) {
      return [back, m(Section, {title: file.name}, loadingBody('Reading file…'))];
    }
    const lead =
      `${fmtCount(detail.threads)} thread${detail.threads === 1 ? '' : 's'} ` +
      `blocked reading this file ${fmtCount(detail.blocks)} times for ` +
      `${fmtDuration(attrs.trace, detail.waitNs)} total — ` +
      `${avgLabel(detail.waitNs, detail.blocks)}.`;
    return [
      back,
      m(
        Section,
        {title: file.name, subtitle: 'Blocked in read, waiting on the device.'},
        m(Callout, {icon: 'insights', intent: Intent.Primary}, lead),
        m('.pf-sismo-page__tab-pane-label', 'Threads that blocked reading it'),
        renderReaders(attrs.trace, detail),
      ),
    ];
  }
}

function renderReaders(trace: Trace, d: DiskFileDetail): m.Children {
  const max = Number(d.readers[0]?.waitNs ?? 0n) || 1;
  const rows = d.readers.map((r) => [
    m(GridCell, {wrap: true}, r.threadName),
    m(GridCell, {align: 'right'}, fmtCount(r.threads)),
    m(GridCell, renderBar(Number(r.waitNs) / max, fmtDuration(trace, r.waitNs))),
    m(GridCell, {align: 'right'}, fmtCount(r.blocks)),
  ]);
  return m(
    Card,
    {className: 'pf-sismo-page__table-card'},
    m(Grid, {
      columns: [
        {key: 'thread', header: m(GridHeaderCell, 'Thread name')},
        {key: 'count', header: m(GridHeaderCell, 'Threads')},
        {key: 'wait', header: m(GridHeaderCell, 'Wait total')},
        {key: 'reads', header: m(GridHeaderCell, 'Reads')},
      ],
      rowData: rows,
    }),
  );
}

function avgLabel(waitNs: bigint, blocks: number): string {
  const us = Number(waitNs) / Math.max(1, blocks) / 1000;
  if (us >= 1000) return `${(us / 1000).toFixed(1)} ms/wait`;
  return `${us.toFixed(0)} µs/wait`;
}
