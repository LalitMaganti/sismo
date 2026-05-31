// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

import {Embedder} from './embedder';
import {SismoHomePage} from './sismo_home_page';

// Sidebar background is always dark (light-theme blue #262f3c, dark-theme
// gray #343434), so a fixed white fill works for both themes. Embedded as a
// data URL because the brand slot is rendered via <img>, which can't pick
// up `currentColor` from parent CSS.
const SISMO_BRAND =
  "data:image/svg+xml;utf8," +
  "<svg xmlns='http://www.w3.org/2000/svg' width='122' height='36'" +
  " viewBox='0 0 122 36'>" +
  "<text x='122' y='27' text-anchor='end' font-family='Roboto,sans-serif'" +
  " font-size='28' font-weight='300' fill='white'>Sismo</text>" +
  '</svg>';

export class SismoEmbedder implements Embedder {
  readonly analyticsId = undefined;
  readonly extensionServer = undefined;
  readonly brandingBadge = undefined;
  readonly defaultPlugins: ReadonlyArray<string> = [
    'dev.perfetto.Timeline',
    'dev.perfetto.SettingsPage',
    'dev.perfetto.CoreCommands',
    'dev.perfetto.SismoWidgets',
    'dev.perfetto.Sismo',
  ];
  readonly homePage = SismoHomePage;
  readonly brandLogo = {src: SISMO_BRAND, alt: 'Sismo'};
}
