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

// Meter: a labelled card with a headline readout, one or more proportion bars,
// an optional swatch legend and a caption. Shared by every Sismo overview gauge
// (cycle budget / CPU usage / parallelism). Colours are by role, not by data
// source: `primary` is the thing in focus (your processes), `secondary` is
// everything else, `idle` is unused capacity.

import m from 'mithril';
import {Card} from '../../widgets/card';
import {Icon} from '../../widgets/icon';
import {Tooltip} from '../../widgets/tooltip';

export type MeterColor = 'primary' | 'secondary' | 'idle';

// One slice of a bar. `frac` is the width as a fraction of the bar (0..1);
// null renders as empty.
export interface MeterSegment {
  readonly color: MeterColor;
  readonly frac: number | null;
}

// A standalone labelled bar, for quantities that don't share a denominator and
// so can't stack into one bar (e.g. yours-vs-others parallelism).
export interface MeterTrack {
  readonly label: string;
  readonly color: MeterColor;
  readonly frac: number | null;
  readonly value: string;
}

export interface MeterLegendItem {
  readonly color: MeterColor;
  readonly label: string;
  readonly value: string;
}

export interface MeterAttrs {
  readonly label: string;
  readonly help?: string;
  // Headline readout. Build with meterReadout() for the standard
  // big-number + caption, or pass arbitrary children.
  readonly primary: m.Children;
  // A single stacked bar (segments laid end to end).
  readonly bar?: ReadonlyArray<MeterSegment>;
  // Independent labelled bars, rendered one per row.
  readonly tracks?: ReadonlyArray<MeterTrack>;
  // Swatch legend naming the bar segments.
  readonly legend?: ReadonlyArray<MeterLegendItem>;
  // Free-form caption under the bar(s).
  readonly sub?: m.Children;
}

export class Meter implements m.ClassComponent<MeterAttrs> {
  view({attrs}: m.CVnode<MeterAttrs>): m.Children {
    return m(
      Card,
      {className: 'pf-sismo-meter'},
      renderLabel(attrs.label, attrs.help),
      m('.pf-sismo-meter__primary', attrs.primary),
      attrs.bar && renderBar(attrs.bar),
      attrs.tracks?.map(renderTrack),
      attrs.legend && renderLegend(attrs.legend),
      attrs.sub !== undefined && m('.pf-sismo-meter__sub', attrs.sub),
    );
  }
}

// A bare stacked bar with no surrounding card — for inline use (e.g. a busy
// gauge inside a table cell). Same segment model and colours as the Meter's
// own bar.
export class MeterBar implements m.ClassComponent<{
  readonly segments: ReadonlyArray<MeterSegment>;
}> {
  view({attrs}: m.CVnode<{segments: ReadonlyArray<MeterSegment>}>): m.Children {
    return renderBar(attrs.segments);
  }
}

// The standard headline: a bold number with a muted trailing caption.
export function meterReadout(big: string, caption: string): m.Children {
  return [
    m('span.pf-sismo-meter__big', big),
    m('span.pf-sismo-meter__caption', caption),
  ];
}

function renderLabel(label: string, help: string | undefined): m.Children {
  return m(
    '.pf-sismo-meter__label',
    label,
    help !== undefined &&
      m(
        Tooltip,
        {
          trigger: m(Icon, {
            icon: 'help_outline',
            className: 'pf-sismo-meter__help-icon',
          }),
        },
        help,
      ),
  );
}

function renderBar(segments: ReadonlyArray<MeterSegment>): m.Children {
  return m(
    '.pf-sismo-meter__bar',
    segments.map((s) => renderFill(s.color, s.frac)),
  );
}

function renderTrack(t: MeterTrack): m.Children {
  return m(
    '.pf-sismo-meter__track',
    m('span.pf-sismo-meter__track-label', t.label),
    m('.pf-sismo-meter__bar', renderFill(t.color, t.frac)),
    m('span.pf-sismo-meter__track-val', t.value),
  );
}

function renderLegend(items: ReadonlyArray<MeterLegendItem>): m.Children {
  return m(
    '.pf-sismo-meter__legend',
    items.map((it) =>
      m(
        '.pf-sismo-meter__legend-item',
        m(`.pf-sismo-meter__swatch.pf-sismo-meter__fill--${it.color}`),
        `${it.label} ${it.value}`,
      ),
    ),
  );
}

function renderFill(color: MeterColor, frac: number | null): m.Children {
  return m(`.pf-sismo-meter__fill.pf-sismo-meter__fill--${color}`, {
    style: {width: `${clampFrac(frac) * 100}%`},
  });
}

function clampFrac(frac: number | null): number {
  if (frac === null || !isFinite(frac)) return 0;
  return Math.max(0, Math.min(1, frac));
}
