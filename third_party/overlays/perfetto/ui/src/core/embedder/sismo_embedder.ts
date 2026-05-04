// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

import {Embedder} from './embedder';
import {defaultPlugins} from './default_plugins';
import {SismoHomePage} from './sismo_home_page';

// Transparent inline SVG placeholder used as the sidebar wordmark until a
// proper sismo logo asset is designed. Keeps perfetto's brand aspect ratio
// so the absolutely-positioned `SISMO` badge and channel-name label still
// land in their existing slots; the wordmark itself just renders nothing.
const SISMO_BRAND_PLACEHOLDER =
  "data:image/svg+xml;utf8," +
  "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 252 60'/>";

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
  readonly brandingBadge = {
    text: 'SISMO',
    color: '#e07020',
  };
  readonly defaultPlugins = defaultPlugins;
  readonly homePage = SismoHomePage;
  readonly brandLogo = {src: SISMO_BRAND_PLACEHOLDER, alt: 'sismo'};
}
