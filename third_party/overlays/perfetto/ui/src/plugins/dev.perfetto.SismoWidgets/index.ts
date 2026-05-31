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

// Holder plugin for shared Sismo UI widgets (Meter, …). Owns no pages or trace
// state — it exists so widgets used across the Sismo plugins live in one place
// with their own styles, rather than buried in a single page plugin. Importing
// this module pulls in the widget styles; the widgets themselves are plain ES
// exports (e.g. ./meter) that other plugins import directly.

import './styles.scss';
import type {PerfettoPlugin} from '../../public/plugin';

export default class implements PerfettoPlugin {
  static readonly id = 'dev.perfetto.SismoWidgets';
  static readonly description = 'Shared UI widgets for the Sismo plugins.';
}
