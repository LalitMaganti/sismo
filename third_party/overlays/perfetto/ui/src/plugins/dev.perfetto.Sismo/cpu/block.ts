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

// Shared shell for a landing-page question block: the user's QUESTION as the
// heading, a one-line plain answer, then the evidence (meter/table), then a "go
// deeper" link into the matching tab. Every block is ALWAYS rendered — the
// landing states what the trace says about each question rather than gating on
// whether something looks notable.

import m from 'mithril';
import {Card} from '../../../widgets/card';
import {Button, ButtonVariant} from '../../../widgets/button';
import {Callout} from '../../../widgets/callout';
import {Intent} from '../../../widgets/common';
import {loadingBody} from '../page_common';

// An in-card navigation/drill link. A plain action (no icon) reads as "go deeper
// →" with a trailing arrow; supplying an icon (e.g. 'help_outline' for a drill)
// uses it as a leading glyph instead.
export interface DeeperAction {
  readonly label: string;
  readonly onclick: () => void;
  readonly icon?: string;
}

export interface QuestionBlockAttrs {
  // The question, as the user would ask it. The block's heading.
  readonly question: string;
  // One static line on what this section examines — shown under the heading,
  // before the trace-derived answer. Orients the reader the way a tab section's
  // subtitle does.
  readonly description?: string;
  // One-line plain-language answer from the trace; shown under the heading.
  readonly answer?: m.Children;
  // Drill/navigation links rendered as a quiet row at the foot of the card —
  // part of the block, not a detached button strip below it.
  readonly deeper?: DeeperAction | ReadonlyArray<DeeperAction>;
}

function deeperButton(a: DeeperAction): m.Children {
  return m(Button, {
    label: a.label,
    ...(a.icon !== undefined ? {icon: a.icon} : {rightIcon: 'arrow_forward'}),
    variant: ButtonVariant.Minimal,
    onclick: a.onclick,
  });
}

export function questionBlock(
  attrs: QuestionBlockAttrs,
  body?: m.Children,
): m.Children {
  const deeper =
    attrs.deeper === undefined
      ? []
      : Array.isArray(attrs.deeper)
        ? attrs.deeper
        : [attrs.deeper as DeeperAction];
  return m(
    Card,
    {className: 'pf-sismo-qblock'},
    // Question on the left, its "go deeper" links on the right of the same row —
    // up top where they're seen, not buried under the evidence.
    m(
      '.pf-sismo-qblock__header',
      m('.pf-sismo-qblock__q', attrs.question),
      deeper.length > 0 &&
        m('.pf-sismo-qblock__actions', deeper.map(deeperButton)),
    ),
    attrs.description !== undefined &&
      m('.pf-sismo-qblock__desc', attrs.description),
    attrs.answer !== undefined &&
      m(Callout, {icon: 'lightbulb', intent: Intent.Primary}, attrs.answer),
    body !== undefined && m('.pf-sismo-qblock__body', body),
  );
}

// A labelled sub-section within a question block — a small heading over a piece
// of evidence (e.g. a breakdown grid), used when a block has more than one.
export function subSection(title: string, body: m.Children): m.Children {
  return m(
    '.pf-sismo-subsection',
    m('.pf-sismo-subsection__title', title),
    body,
  );
}

// A block whose data is still loading. Shows the question so the landing stays
// complete and ordered while the answer arrives.
export function loadingBlock(question: string): m.Children {
  return questionBlock({question}, loadingBody('Reading the trace…'));
}
