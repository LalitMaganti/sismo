// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

import {Embedder} from './embedder';
import {SismoHomePage} from './sismo_home_page';

// Inline SVG wordmark used as the sidebar brand. The sidebar background is
// always dark (light-theme blue #262f3c, dark-theme gray #343434), so a
// fixed white fill renders correctly under both themes. Embedded as a data
// URL because the brand slot is rendered via <img>, which would not pick up
// `currentColor` from parent CSS.
//
// Small right-shift inside the brand canvas so the wordmark isn't flush
// against the sidebar edge but also doesn't drift far enough right to leave
// a gap on the left.
const SISMO_BRAND =
  "data:image/svg+xml;utf8," +
  "<svg xmlns='http://www.w3.org/2000/svg' width='122' height='36'" +
  " viewBox='0 0 122 36'>" +
  "<text x='122' y='27' text-anchor='end' font-family='Roboto,sans-serif'" +
  " font-size='28' font-weight='300' fill='white'>Sismo</text>" +
  '</svg>';

/**
 * Embedder used when the UI is served from a sismo deployment
 * (ui.sismo.dev, the Cloudflare pages.dev preview URLs, and localhost
 * dev-server instances of this fork).
 *
 * `homePage` references SismoHomePage; the App is delivered to it via
 * Mithril attrs (see PR #5712) so the import graph from this module to
 * SismoHomePage doesn't reach AppImpl, avoiding the cycle that would
 * otherwise form via createEmbedder.
 */
export class SismoEmbedder implements Embedder {
  readonly analyticsId = undefined;
  readonly extensionServer = undefined;
  readonly brandingBadge = undefined;
  // Minimal plugin set: only enough for a blank trace to load and the
  // timeline shell to render. Iteratively grown empirically — adding a
  // plugin here should be justified by something the user can't do
  // without it.
  readonly defaultPlugins: ReadonlyArray<string> = [
    'dev.perfetto.Timeline',
    'dev.perfetto.SettingsPage',
    'dev.perfetto.CoreCommands',
  ];
  readonly homePage = SismoHomePage;
  readonly brandLogo = {src: SISMO_BRAND, alt: 'Sismo'};
}
