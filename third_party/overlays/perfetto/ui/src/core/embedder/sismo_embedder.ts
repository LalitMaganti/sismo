// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

import {Embedder} from './embedder';
import {defaultPlugins} from './default_plugins';
import {SismoHomePage} from './sismo_home_page';

// Inline SVG wordmark used as the sidebar brand. The sidebar background is
// always dark (light-theme blue #262f3c, dark-theme gray #343434), so a
// fixed light fill renders correctly under both themes. Embedded as a data
// URL because the brand slot is rendered via <img>, which would not pick up
// `currentColor` from parent CSS.
const SISMO_BRAND =
  "data:image/svg+xml;utf8," +
  "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 130 60'>" +
  "<text x='4' y='46' font-family='Roboto,sans-serif' font-size='44'" +
  " font-weight='300' fill='%23e07020'>Sismo</text>" +
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
  readonly defaultPlugins = defaultPlugins;
  readonly homePage = SismoHomePage;
  readonly brandLogo = {src: SISMO_BRAND, alt: 'Sismo'};
}
