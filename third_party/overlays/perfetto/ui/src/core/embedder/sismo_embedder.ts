// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

import {Embedder} from './embedder';
import {defaultPlugins} from './default_plugins';

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
 * `homePage` is undefined here on purpose: the sismo home page is an
 * overlay of perfetto's frontend/home_page.ts (same exported class name
 * `HomePage`). Wiring it through the embedder field would create a
 * circular import (embedder -> home page -> AppImpl -> createEmbedder
 * -> external_embedder -> embedder), which rollup 4 can't print
 * cleanly because perfetto's onwarn handler still uses the rollup-2
 * `warning.cycle` field.
 */
export class SismoEmbedder implements Embedder {
  readonly analyticsId = undefined;
  readonly extensionServer = undefined;
  readonly brandingBadge = {
    text: 'SISMO',
    color: '#e07020',
  };
  readonly defaultPlugins = defaultPlugins;
  readonly homePage = undefined;
  readonly brandLogo = {src: SISMO_BRAND_PLACEHOLDER, alt: 'sismo'};
}
