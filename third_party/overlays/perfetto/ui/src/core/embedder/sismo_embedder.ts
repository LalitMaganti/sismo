// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

import {Embedder} from './embedder';
import {defaultPlugins} from './default_plugins';
import {SismoHomePage} from './sismo_home_page';

/**
 * Embedder used when the UI is served from a sismo deployment
 * (ui.sismo.dev, the Cloudflare pages.dev preview URLs, and localhost
 * dev-server instances of this fork).
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
  readonly brandLogo = undefined;
}
