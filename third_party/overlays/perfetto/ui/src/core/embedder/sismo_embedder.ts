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
// Right-aligned within a 130-wide canvas: the channel-name badge
// (`CANARY` / `AUTOPUSH`, position: absolute at right: 48px) sits to the
// right of the wordmark, so pushing "Sismo" toward that edge keeps the two
// visually grouped instead of separated by a wide gap.
const SISMO_BRAND =
  "data:image/svg+xml;utf8," +
  "<svg xmlns='http://www.w3.org/2000/svg' width='130' height='36'" +
  " viewBox='0 0 130 36'>" +
  "<text x='130' y='27' text-anchor='end' font-family='Roboto,sans-serif'" +
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
  ];
  readonly homePage = SismoHomePage;
  readonly brandLogo = {src: SISMO_BRAND, alt: 'Sismo'};
}
