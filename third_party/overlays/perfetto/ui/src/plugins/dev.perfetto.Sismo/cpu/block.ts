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

export interface QuestionBlockAttrs {
  // The question, as the user would ask it. The block's heading.
  readonly question: string;
  // One-line plain-language answer from the trace; shown under the heading.
  readonly answer?: m.Children;
  // Optional drill into the matching deep-dive tab.
  readonly deeper?: {readonly label: string; readonly onclick: () => void};
}

export function questionBlock(
  attrs: QuestionBlockAttrs,
  body?: m.Children,
): m.Children {
  return m(
    Card,
    {className: 'pf-sismo-qblock'},
    m('.pf-sismo-qblock__q', attrs.question),
    attrs.answer !== undefined &&
      m(Callout, {icon: 'lightbulb', intent: Intent.Primary}, attrs.answer),
    body !== undefined && m('.pf-sismo-qblock__body', body),
    attrs.deeper !== undefined &&
      m(
        '.pf-sismo-qblock__deeper',
        m(Button, {
          label: attrs.deeper.label,
          rightIcon: 'arrow_forward',
          variant: ButtonVariant.Minimal,
          onclick: attrs.deeper.onclick,
        }),
      ),
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
