# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""Run the Perfetto UI dev server (esbuild + watch + local HTTP).

Thin wrapper around third_party/src/perfetto/ui/run-dev-server: ensures
sismo's overlay files (external_embedder.ts, sismo_embedder.ts, …) are
in place under the perfetto checkout, then execs the upstream script
with passthrough args.

Prereq: `tools/install-build-deps` (toolchain) and, from the perfetto
checkout, `tools/install-build-deps --ui` (node + ui deps). The dev
server's own startup will fail loudly if the latter hasn't run.
"""

from __future__ import annotations

import os
import sys

ROOT_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUN_DEV_SERVER: str = os.path.join(
    ROOT_DIR, "third_party", "src", "perfetto", "ui", "run-dev-server"
)


def main() -> int:
    # Refresh sismo overlays (sismo_embedder.ts etc.) before the dev server
    # starts watching. apply_perfetto_patches/install_perfetto_overlays are
    # both idempotent and cheap — safe to call on every invocation.
    from python.tools.install_build_deps import (
        apply_perfetto_patches,
        install_perfetto_overlays,
    )
    if not apply_perfetto_patches():
        return 1
    if not install_perfetto_overlays():
        return 1

    if not os.access(RUN_DEV_SERVER, os.X_OK):
        print(
            f"perfetto run-dev-server not found at {RUN_DEV_SERVER} — "
            f"did you `git submodule update --init --recursive`?",
            file=sys.stderr,
        )
        return 1

    os.execv(RUN_DEV_SERVER, [RUN_DEV_SERVER] + sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
