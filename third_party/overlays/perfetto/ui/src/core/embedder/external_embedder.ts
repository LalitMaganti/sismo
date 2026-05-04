// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

// Sismo override of upstream's ui/src/core/embedder/external_embedder.ts —
// the override-point file added by google/perfetto#5714. Once create_embedder.ts
// is patched to consult EXTERNAL_EMBEDDER (via #5714 or the local bridge
// patch), this file's value is used unconditionally for any origin, so the
// SismoEmbedder ships everywhere a sismo build runs.

import {Embedder} from './embedder';
import {SismoEmbedder} from './sismo_embedder';

export const EXTERNAL_EMBEDDER: Embedder = new SismoEmbedder();
